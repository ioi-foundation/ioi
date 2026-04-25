use super::*;
use crate::kernel::chat::content_session::attach_non_artifact_chat_session;
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
fn current_task_turn_surfaces_non_artifact_routes_as_shared_execution_sessions() {
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
        .routing_hints
        .iter()
        .any(|hint| hint == "no_persistent_artifact_requested"));
    assert_eq!(
        chat_session.outcome_request.outcome_kind,
        ChatOutcomeKind::Conversation
    );
    assert!(chat_session.materialization.swarm_execution.is_some());
    assert_eq!(
        chat_session
            .materialization
            .swarm_execution
            .as_ref()
            .expect("swarm execution")
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
        routing_hints: vec![
            "currentness_override".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
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

#[test]
fn weather_tool_widget_route_requires_chat_primary_execution() {
    let mut task = empty_task("What is the weather in Boston today?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-request".to_string(),
        raw_prompt: "What is the weather in Boston today?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.96,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What is the weather in Boston today?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn weather_scope_parser_extracts_multi_city_lists() {
    let scopes = super::prepare::extract_weather_scopes(
        "Compare the weather in three cities I'm considering moving to: Austin, Denver, and Portland",
    );

    assert_eq!(
        scopes,
        vec![
            "Austin".to_string(),
            "Denver".to_string(),
            "Portland".to_string()
        ]
    );
}

#[test]
fn weather_report_fallback_parser_condenses_wttr_report() {
    let summary = super::prepare::parse_weather_report_fallback(
        "Boston",
        "Weather report: boston\n\n                Mist\n   _ - _ - _ -  50 °F          \n    _ - _ - _   ↙ 2 mph        \n   _ - _ - _ -  1 mi           \n                0.0 in         \n",
    );

    assert_eq!(
        summary.as_deref(),
        Some("Boston: Mist 50 °F wind ↙ 2 mph visibility 1 mi precipitation 0.0 in."),
    );
}

#[test]
fn weather_tool_widget_follow_up_reuses_retained_location_scope() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-follow-up".to_string(),
        raw_prompt: "What's the weather in Boston this weekend?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.97,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: Some(ioi_types::app::chat::ChatNormalizedRequestFrame::Weather(
            ioi_types::app::chat::ChatWeatherRequestFrame {
                inferred_locations: vec!["Boston".to_string()],
                assumed_location: None,
                temporal_scope: Some("tomorrow".to_string()),
                missing_slots: Vec::new(),
                clarification_required_slots: Vec::new(),
            },
        )),
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let scopes = super::prepare::weather_scopes_for_tool_widget(
        "How about tomorrow instead?",
        &outcome_request,
    );

    assert_eq!(scopes, vec!["Boston".to_string()]);
}

#[test]
fn sports_tool_widget_route_requires_chat_primary_execution() {
    let mut task = empty_task("What's the story with the Lakers this season?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "sports-request".to_string(),
        raw_prompt: "What's the story with the Lakers this season?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:sports".to_string(),
            "narrow_surface_preferred".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What's the story with the Lakers this season?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn places_tool_widget_route_requires_chat_primary_execution() {
    let mut task = empty_task("What are some good coffee shops near downtown Portland?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-request".to_string(),
        raw_prompt: "What are some good coffee shops near downtown Portland?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:places".to_string(),
            "narrow_surface_preferred".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What are some good coffee shops near downtown Portland?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn conversation_single_pass_route_requires_chat_primary_execution() {
    let mut task = empty_task("What is the capital of Spain?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "conversation-request".to_string(),
        raw_prompt: "What is the capital of Spain?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["no_persistent_artifact_requested".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What is the capital of Spain?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn workspace_grounded_single_pass_route_stays_off_chat_primary_execution() {
    let mut task = empty_task("What npm script launches the desktop app in this repo?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-grounding-single-pass".to_string(),
        raw_prompt: "What npm script launches the desktop app in this repo?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.93,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "workspace_grounding_required".to_string(),
            "coding_workspace_context".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What npm script launches the desktop app in this repo?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(!task_requires_chat_primary_execution(&task));
}

#[test]
fn visualizer_route_requires_chat_primary_execution() {
    let mut task = empty_task("Show a simple mermaid diagram of the HTTP request lifecycle.");
    let outcome_request = ChatOutcomeRequest {
        request_id: "visualizer-request".to_string(),
        raw_prompt: "Show a simple mermaid diagram of the HTTP request lifecycle.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Visualizer,
        execution_strategy: ChatExecutionStrategy::DirectAuthor,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["no_persistent_artifact_requested".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "Show a simple mermaid diagram of the HTTP request lifecycle.",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
}

#[test]
fn non_artifact_route_receipt_event_preserves_explicit_route_decision() {
    let mut task = empty_task("What is the capital of Spain?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "conversation-route".to_string(),
        raw_prompt: "What is the capital of Spain?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.99,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["no_persistent_artifact_requested".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What is the capital of Spain?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    let route_event = task
        .events
        .iter()
        .find(|event| event.title == "Chat route decision")
        .expect("route decision event");
    let digest = route_event.digest.as_object().expect("route digest");
    assert_eq!(
        digest.get("route_family").and_then(|value| value.as_str()),
        Some("general")
    );
    let route_decision = digest
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision payload");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("direct_inline")
    );
    assert_eq!(
        route_decision
            .get("direct_answer_allowed")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
}

#[test]
fn route_contract_payload_maps_weather_widget_to_research_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-route".to_string(),
        raw_prompt: "What is the weather in Boston today?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.96,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let lane_frame = payload_object
        .get("lane_frame")
        .and_then(|value| value.as_object())
        .expect("lane frame");
    assert_eq!(
        lane_frame
            .get("primaryLane")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let request_frame = payload_object
        .get("request_frame")
        .and_then(|value| value.as_object())
        .expect("request frame");
    assert_eq!(
        request_frame.get("kind").and_then(|value| value.as_str()),
        Some("weather")
    );
    assert!(request_frame
        .get("inferredLocations")
        .and_then(|value| value.as_array())
        .is_some_and(|locations| locations
            .iter()
            .any(|value| value.as_str() == Some("boston"))));
    let source_selection = payload_object
        .get("source_selection")
        .and_then(|value| value.as_object())
        .expect("source selection");
    assert_eq!(
        source_selection
            .get("selectedSource")
            .and_then(|value| value.as_str()),
        Some("specialized_tool")
    );
    assert!(payload_object
        .get("orchestration_state")
        .and_then(|value| value.as_object())
        .is_some());
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("tool_execution")
    );
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert_eq!(
        route_decision
            .get("narrow_tool_preference")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(effective_tool_surface
        .get("projected_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools
            .iter()
            .any(|tool| tool.as_str() == Some("weather_fetch"))));
    assert!(effective_tool_surface
        .get("broad_fallback_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("web_search"))));
}

#[test]
fn route_contract_payload_maps_recipe_widget_to_research_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "recipe-route".to_string(),
        raw_prompt: "How do I make carbonara for 3 people?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:recipe".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let lane_frame = payload_object
        .get("lane_frame")
        .and_then(|value| value.as_object())
        .expect("lane frame");
    assert_eq!(
        lane_frame
            .get("primaryLane")
            .and_then(|value| value.as_str()),
        Some("research")
    );
}

#[test]
fn route_contract_payload_preserves_connector_source_selection_and_lane_transition() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "mail.primary".to_string(),
        plugin_id: "wallet_mail".to_string(),
        name: "Mail".to_string(),
        provider: "wallet.network".to_string(),
        category: "communication".to_string(),
        description: "Wallet-backed mail connector.".to_string(),
        status: "connected".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec![
            "mail.read.latest".to_string(),
            "mail.list.recent".to_string(),
        ],
        last_sync_at_utc: None,
        notes: None,
    }];
    let context =
        infer_connector_route_context_from_catalog("Summarize my unread emails", &connectors)
            .expect("mail request should synthesize connector context");
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "mail-route-payload".to_string(),
        raw_prompt: "Summarize my unread emails".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.91,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["shared_answer_surface".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::merge_connector_route_context(&mut outcome_request, context);

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("communication")
    );
    let source_selection = payload_object
        .get("source_selection")
        .and_then(|value| value.as_object())
        .expect("source selection");
    assert_eq!(
        source_selection
            .get("selectedSource")
            .and_then(|value| value.as_str()),
        Some("connector")
    );
    let retained_lane_state = payload_object
        .get("retained_lane_state")
        .and_then(|value| value.as_object())
        .expect("retained lane state");
    assert_eq!(
        retained_lane_state
            .get("selectedProviderFamily")
            .and_then(|value| value.as_str()),
        Some("mail.wallet_network")
    );
    assert!(payload_object
        .get("lane_transitions")
        .and_then(|value| value.as_array())
        .is_some_and(|transitions| transitions.iter().any(|transition| {
            transition.get("toLane").and_then(|value| value.as_str()) == Some("integrations")
        })));
}

#[test]
fn route_contract_payload_maps_sports_widget_to_specialized_tool_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "sports-route".to_string(),
        raw_prompt: "What's the story with the Lakers this season?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:sports".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert!(effective_tool_surface
        .get("projected_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|tool| tool.as_str() == Some("fetch_sports_data"))
        }));
}

#[test]
fn route_contract_payload_maps_places_widget_to_search_and_map_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-route".to_string(),
        raw_prompt: "What are some good coffee shops near downtown Portland?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:places".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    let projected_tools = effective_tool_surface
        .get("projected_tools")
        .and_then(|value| value.as_array())
        .expect("projected tools");
    assert!(projected_tools
        .iter()
        .any(|tool| tool.as_str() == Some("places_search")));
    assert!(projected_tools
        .iter()
        .any(|tool| tool.as_str() == Some("places_map_display_v0")));
}

#[test]
fn route_contract_payload_maps_currentness_conversation_to_research_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "currentness-route".to_string(),
        raw_prompt: "Who is the current Secretary-General of the UN?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::AdaptiveWorkGraph,
        execution_mode_decision: None,
        confidence: 0.91,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "currentness_override".to_string(),
            "no_persistent_artifact_requested".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("conversation_currentness_adaptive_work_graph")
    );
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("research")
    );
    assert_eq!(
        payload_object
            .get("verifier_state")
            .and_then(|value| value.as_str()),
        Some("active")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("tool_execution")
    );
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("web_search"))));
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("web_fetch"))));
}

#[test]
fn route_contract_payload_maps_workspace_grounded_conversation_to_coding_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-grounding-route".to_string(),
        raw_prompt: "What npm script launches the desktop app in this repo?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.93,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "workspace_grounding_required".to_string(),
            "coding_workspace_context".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("conversation_workspace_grounded_single_pass")
    );
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("coding")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("tool_execution")
    );
    assert_eq!(
        route_decision
            .get("direct_answer_allowed")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(route_decision
        .get("direct_answer_blockers")
        .and_then(|value| value.as_array())
        .is_some_and(|blockers| blockers
            .iter()
            .any(|blocker| blocker.as_str() == Some("workspace_grounding_required"))));
    assert_eq!(
        route_decision
            .get("narrow_tool_preference")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    let effective_tool_surface = route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.as_object())
        .expect("effective tool surface");
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("view"))));
    assert!(effective_tool_surface
        .get("primary_tools")
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("bash_tool"))));
}

#[test]
fn runtime_handoff_prefix_carries_workspace_grounded_route_contract() {
    let mut task = empty_task("What npm script launches the desktop app in this repo?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-grounding-handoff".to_string(),
        raw_prompt: "What npm script launches the desktop app in this repo?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.93,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "workspace_grounding_required".to_string(),
            "coding_workspace_context".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What npm script launches the desktop app in this repo?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "test".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    let prefix = runtime_handoff_prompt_prefix_for_task(&task).expect("route handoff prefix");
    assert!(prefix.contains("CHAT ARTIFACT ROUTE CONTRACT:"));
    assert!(prefix.contains("selected_route: conversation_workspace_grounded_single_pass"));
    assert!(prefix.contains("route_family: coding"));
    assert!(prefix.contains("primary_tools: view, bash_tool"));
    assert!(prefix.contains("workspace_grounding_required"));
    assert!(prefix.contains("Treat local workspace inspection as mandatory"));
}

#[test]
fn clarification_non_artifact_route_stays_chat_primary() {
    let mut task = empty_task("Make me a report.");
    let outcome_request = ChatOutcomeRequest {
        request_id: "clarification-route".to_string(),
        raw_prompt: "Make me a report.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.75,
        needs_clarification: true,
        clarification_questions: vec!["What should the report cover?".to_string()],
        routing_hints: vec![
            "artifact_clarification_required".to_string(),
            "under_specified_document_request".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "Make me a report.",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );
    super::apply_chat_authoritative_status(&mut task, None);

    assert!(task_is_chat_authoritative(&task));
    assert!(task_requires_chat_primary_execution(&task));
    assert_eq!(task.phase, AgentPhase::Gate);
    assert_eq!(
        task.clarification_request
            .as_ref()
            .map(|request| request.question.as_str()),
        Some("What should the report cover?")
    );
    assert!(task.current_step.contains("waiting for clarification"));
}

#[test]
fn missing_connector_reframes_impossible_workspace_clarification() {
    let connectors = vec![
        ConnectorCatalogEntry {
            id: "mail.primary".to_string(),
            plugin_id: "wallet_mail".to_string(),
            name: "Mail".to_string(),
            provider: "wallet.network".to_string(),
            category: "communication".to_string(),
            description: "Wallet-backed mail connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec!["mail.read.latest".to_string()],
            last_sync_at_utc: None,
            notes: None,
        },
        ConnectorCatalogEntry {
            id: "google.workspace".to_string(),
            plugin_id: "google_workspace".to_string(),
            name: "Google".to_string(),
            provider: "google".to_string(),
            category: "productivity".to_string(),
            description: "Google Workspace connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec!["gmail".to_string(), "calendar".to_string()],
            last_sync_at_utc: None,
            notes: None,
        },
    ];
    let context = infer_connector_route_context_from_catalog(
        "Summarize my Slack unread messages",
        &connectors,
    )
    .expect("slack request should synthesize connector context");

    let mut outcome_request = ChatOutcomeRequest {
        request_id: "slack-missing".to_string(),
        raw_prompt: "Summarize my Slack unread messages".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: true,
        clarification_questions: vec!["Which Slack workspace should I monitor?".to_string()],
        routing_hints: vec!["shared_answer_surface".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::merge_connector_route_context(&mut outcome_request, context);

    assert_eq!(
        outcome_request.clarification_questions,
        vec![
            "Slack is not available in this runtime yet. Should Chat wait for you to connect it, or should I work from pasted data instead?"
                .to_string()
        ]
    );
    assert!(outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "connector_missing"));

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("missing connector route should surface clarification UX");
    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].id, "open_capabilities_to_connect");
    assert!(request.options[0].recommended);

    let route_decision = route_decision_for_outcome_request(&outcome_request);
    assert_eq!(route_decision.connector_candidate_count, 0);
    assert!(route_decision.connector_first_preference);
    assert!(route_decision.narrow_tool_preference);
    assert_eq!(route_decision.route_family, "integrations");
    assert!(route_decision
        .direct_answer_blockers
        .iter()
        .any(|blocker| blocker == "connector_unavailable"));
}

#[test]
fn connected_mail_route_clears_redundant_identity_clarification() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "mail.primary".to_string(),
        plugin_id: "wallet_mail".to_string(),
        name: "Mail".to_string(),
        provider: "wallet.network".to_string(),
        category: "communication".to_string(),
        description: "Wallet-backed mail connector.".to_string(),
        status: "connected".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec![
            "mail.read.latest".to_string(),
            "mail.list.recent".to_string(),
        ],
        last_sync_at_utc: None,
        notes: None,
    }];
    let context =
        infer_connector_route_context_from_catalog("Summarize my unread emails", &connectors)
            .expect("mail request should synthesize connector context");

    let mut outcome_request = ChatOutcomeRequest {
        request_id: "mail-connected".to_string(),
        raw_prompt: "Summarize my unread emails".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.91,
        needs_clarification: true,
        clarification_questions: vec!["Which inbox should Chat check?".to_string()],
        routing_hints: vec!["shared_answer_surface".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::merge_connector_route_context(&mut outcome_request, context);

    assert!(!outcome_request.needs_clarification);
    assert!(outcome_request.clarification_questions.is_empty());
    assert!(outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "connector_identity_auto_selected"));

    let route_decision = route_decision_for_outcome_request(&outcome_request);
    assert_eq!(route_decision.connector_candidate_count, 1);
    assert_eq!(route_decision.route_family, "integrations");
    assert_eq!(
        route_decision.selected_provider_family.as_deref(),
        Some("mail.wallet_network")
    );
    assert_eq!(
        route_decision.selected_provider_route_label.as_deref(),
        Some("mail_connector")
    );
    assert!(route_decision.connector_first_preference);
    assert!(route_decision.narrow_tool_preference);
    assert!(route_decision
        .effective_tool_surface
        .primary_tools
        .iter()
        .any(|tool| tool == "connector:mail.primary"));
}

#[test]
fn generic_mail_prefers_dedicated_connector_over_broader_platform_route() {
    let connectors = vec![
        ConnectorCatalogEntry {
            id: "google.workspace".to_string(),
            plugin_id: "google_workspace".to_string(),
            name: "Google".to_string(),
            provider: "google".to_string(),
            category: "productivity".to_string(),
            description: "Google Workspace connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec!["gmail".to_string()],
            last_sync_at_utc: None,
            notes: None,
        },
        ConnectorCatalogEntry {
            id: "mail.primary".to_string(),
            plugin_id: "wallet_mail".to_string(),
            name: "Mail".to_string(),
            provider: "wallet.network".to_string(),
            category: "communication".to_string(),
            description: "Wallet-backed mail connector.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec![
                "mail.read.latest".to_string(),
                "mail.list.recent".to_string(),
            ],
            last_sync_at_utc: None,
            notes: None,
        },
    ];
    let context =
        infer_connector_route_context_from_catalog("Summarize my unread emails", &connectors)
            .expect("mail request should synthesize connector context");

    assert!(context
        .routing_hints
        .iter()
        .any(|hint| hint == "selected_connector_id:mail.primary"));
    assert!(context
        .routing_hints
        .iter()
        .any(|hint| hint == "selected_provider_family:mail.wallet_network"));
    assert!(context
        .routing_hints
        .iter()
        .any(|hint| hint == "connector_tiebreaker:narrow_connector"));
}

#[test]
fn downloadable_spreadsheet_prompt_does_not_trigger_connector_context() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "google.workspace".to_string(),
        plugin_id: "google_workspace".to_string(),
        name: "Google".to_string(),
        provider: "google".to_string(),
        category: "productivity".to_string(),
        description: "Google Workspace connector.".to_string(),
        status: "needs_auth".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec!["sheets".to_string()],
        last_sync_at_utc: None,
        notes: None,
    }];

    let context = infer_connector_route_context_from_catalog(
        "Create a budget spreadsheet with income and expense categories, monthly columns, SUM formulas for totals, conditional formatting for overages, and a summary chart",
        &connectors,
    );

    assert!(
        context.is_none(),
        "explicit downloadable spreadsheet prompts should stay on the artifact lane"
    );
}

#[test]
fn pure_draft_email_prompt_prefers_local_message_compose_over_connector_gate() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "mail.primary".to_string(),
        plugin_id: "mail_primary".to_string(),
        name: "Mail".to_string(),
        provider: "wallet".to_string(),
        category: "communication".to_string(),
        description: "Primary mail connector.".to_string(),
        status: "needs_auth".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec!["mail.read.latest".to_string()],
        last_sync_at_utc: None,
        notes: None,
    }];

    let context = infer_connector_route_context_from_catalog(
        "Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise.",
        &connectors,
    );

    assert!(
        context.is_none(),
        "pure composition requests should stay on the communication lane instead of forcing connector auth"
    );
}

#[test]
fn document_artifact_route_contract_preserves_artifact_vs_file_split() {
    let outcome_request = test_outcome_request();
    let route_decision = route_decision_for_outcome_request(&outcome_request);

    assert_eq!(route_decision.route_family, "artifacts");
    assert!(route_decision.artifact_output_intent);
    assert!(route_decision.file_output_intent);
    assert!(!route_decision.inline_visual_intent);
    assert!(!route_decision.narrow_tool_preference);
    assert!(!route_decision.skill_prep_required);
    assert_eq!(route_decision.output_intent, "artifact");
}

#[test]
fn communication_route_contract_uses_tool_execution_surface() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "message-route".to_string(),
        raw_prompt: "Draft a professional email to my landlord asking whether the lease renewal paperwork is ready and keep it concise.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "email_draft".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("communication")
    );
    let route_decision = payload_object
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("tool_execution")
    );
    assert_eq!(
        route_decision
            .get("direct_answer_allowed")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        route_decision
            .get("narrow_tool_preference")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(route_decision
        .get("effective_tool_surface")
        .and_then(|value| value.get("primary_tools"))
        .and_then(|value| value.as_array())
        .is_some_and(|tools| tools
            .iter()
            .any(|value| value.as_str() == Some("message_compose_v1"))));
    assert!(payload_object
        .get("orchestration_state")
        .and_then(|value| value.get("tasks"))
        .and_then(|value| value.as_array())
        .is_some_and(|tasks| tasks.len() >= 3));
}

#[test]
fn artifact_route_contract_prefers_artifact_surface_over_specialized_prompt_terms() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "itinerary-artifact".to_string(),
        raw_prompt: "Plan a Saturday in Portland by comparing the weather, choosing a coffee shop downtown, and suggesting one nearby dinner spot, then turn it into a short itinerary artifact.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.97,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "persistent_artifact_requested".to_string(),
            "generic_document_artifact_defaults_to_markdown".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(test_outcome_request().artifact.expect("artifact request")),
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    let bundle = payload_object
        .get("domain_policy_bundle")
        .and_then(|value| value.as_object())
        .expect("domain policy bundle");
    assert_eq!(
        bundle
            .get("presentationPolicy")
            .or_else(|| bundle.get("presentation_policy"))
            .and_then(|value| value
                .get("primarySurface")
                .or_else(|| value.get("primary_surface")))
            .and_then(|value| value.as_str()),
        Some("artifact_surface")
    );
    assert!(bundle
        .get("verificationContract")
        .or_else(|| bundle.get("verification_contract"))
        .and_then(|value| value
            .get("requiredChecks")
            .or_else(|| value.get("required_checks")))
        .and_then(|value| value.as_array())
        .is_some_and(|checks| checks
            .iter()
            .any(|value| value.as_str() == Some("artifact_surface_rendered"))));
    assert!(payload_object
        .get("lane_frame")
        .and_then(|value| value
            .get("secondaryLanes")
            .or_else(|| value.get("secondary_lanes")))
        .and_then(|value| value.as_array())
        .is_some_and(|lanes| lanes.iter().any(|value| value.as_str() == Some("research"))));
}

#[test]
fn conversation_with_tool_widget_hint_is_not_marked_direct_inline() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-inline-mismatch".to_string(),
        raw_prompt: "What are some good coffee shops near downtown Portland?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.74,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:places".to_string(),
            "narrow_surface_preferred".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let route_decision = route_decision_for_outcome_request(&outcome_request);

    assert!(!route_decision.direct_answer_allowed);
    assert_eq!(route_decision.output_intent, "tool_execution");
    assert!(route_decision
        .direct_answer_blockers
        .iter()
        .any(|blocker| blocker == "tool_widget_surface_selected"));
}

#[test]
fn workspace_artifact_route_contract_uses_coding_family_and_workspace_prep() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "workspace-route".to_string(),
        raw_prompt:
            "Build a React + Vite workspace project for a task tracker with separate components"
                .to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.97,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "explicit_workspace_project_deliverable".to_string(),
            "workspace_runtime_required".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(test_workspace_request()),
    };

    let route_decision = route_decision_for_outcome_request(&outcome_request);

    assert_eq!(route_decision.route_family, "coding");
    assert!(route_decision.artifact_output_intent);
    assert!(!route_decision.file_output_intent);
    assert!(route_decision.skill_prep_required);
    assert_eq!(route_decision.output_intent, "artifact");
}

#[test]
fn non_artifact_weather_route_builds_renderable_parity_surface_and_widget_state() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    let outcome_request = ChatOutcomeRequest {
        request_id: "weather-widget".to_string(),
        raw_prompt: "What is the weather in Boston today?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.88,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    attach_non_artifact_chat_session(
        &mut task,
        "What is the weather in Boston today?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "local".to_string(),
            model: Some("fixture".to_string()),
            endpoint: None,
        },
        &outcome_request,
    );

    let session = task.chat_session.expect("chat session");
    assert_eq!(
        session.artifact_manifest.renderer,
        ChatRendererKind::HtmlIframe
    );
    assert_eq!(session.artifact_manifest.primary_tab, "render");
    assert!(session
        .artifact_manifest
        .files
        .iter()
        .any(|file| file.renderable && file.external_url.is_some()));
    assert_eq!(
        session
            .widget_state
            .as_ref()
            .and_then(|state| state.widget_family.as_deref()),
        Some("weather")
    );
}

#[test]
fn attach_non_artifact_session_preserves_retained_widget_state_during_topology_refresh() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    let provenance = crate::models::ChatRuntimeProvenance {
        kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
        label: "local".to_string(),
        model: Some("fixture".to_string()),
        endpoint: None,
    };
    let initial_request = ChatOutcomeRequest {
        request_id: "weather-initial".to_string(),
        raw_prompt: "What is the weather in Boston today?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.9,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:weather".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: Some(ioi_types::app::chat::ChatNormalizedRequestFrame::Weather(
            ioi_types::app::chat::ChatWeatherRequestFrame {
                inferred_locations: vec!["Boston".to_string()],
                assumed_location: Some("Boston".to_string()),
                temporal_scope: Some("today".to_string()),
                missing_slots: Vec::new(),
                clarification_required_slots: Vec::new(),
            },
        )),
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    attach_non_artifact_chat_session(
        &mut task,
        "What is the weather in Boston today?",
        provenance.clone(),
        &initial_request,
    );

    let follow_up_request = ChatOutcomeRequest {
        request_id: "weather-follow-up".to_string(),
        raw_prompt: "How about tomorrow instead?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:weather".to_string(),
            "retained_widget_follow_up".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    attach_non_artifact_chat_session(
        &mut task,
        "How about tomorrow instead?",
        provenance,
        &follow_up_request,
    );

    match task
        .chat_outcome
        .as_ref()
        .and_then(|request| request.request_frame.as_ref())
        .expect("request frame after retained follow-up")
    {
        ioi_types::app::chat::ChatNormalizedRequestFrame::Weather(frame) => {
            assert!(frame
                .assumed_location
                .as_deref()
                .is_some_and(|location| location.eq_ignore_ascii_case("Boston")));
            assert_eq!(frame.temporal_scope.as_deref(), Some("tomorrow"));
            assert!(frame.missing_slots.is_empty());
        }
        other => panic!("expected weather frame, got {other:?}"),
    }
    assert!(task
        .chat_outcome
        .as_ref()
        .expect("chat outcome")
        .routing_hints
        .iter()
        .any(|hint| hint == "retained_widget_state_applied"));
}

#[test]
fn route_contract_payload_includes_domain_policy_bundle() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "places-policy".to_string(),
        raw_prompt: "Find coffee shops near downtown Portland".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.84,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:places".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let object = payload.as_object().expect("payload object");
    let bundle = object
        .get("domain_policy_bundle")
        .and_then(|value| value.as_object())
        .expect("domain policy bundle");
    assert_eq!(
        bundle
            .get("presentationPolicy")
            .or_else(|| bundle.get("presentation_policy"))
            .and_then(|value| value
                .get("primarySurface")
                .or_else(|| value.get("primary_surface")))
            .and_then(|value| value.as_str()),
        Some("places_widget")
    );
    assert!(bundle
        .get("sourceRanking")
        .or_else(|| bundle.get("source_ranking"))
        .and_then(|value| value.as_array())
        .map(|entries| !entries.is_empty())
        .unwrap_or(false));
}

#[test]
fn weather_advice_clarification_surfaces_structured_scope_options() {
    with_runtime_locality_scope_hint_override(None, || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "weather-clarification".to_string(),
            raw_prompt: "Should I wear a jacket today?".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.9,
            needs_clarification: true,
            clarification_questions: vec![
                "What city should Chat check the weather for?".to_string()
            ],
            routing_hints: vec![
                "tool_widget:weather".to_string(),
                "weather_advice_request".to_string(),
                "location_required_for_weather_advice".to_string(),
                "narrow_surface_preferred".to_string(),
            ],
            lane_frame: None,
            request_frame: None,
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        };

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("weather advice route should surface clarification UX");

        assert_eq!(
            request.question,
            "What city should Chat check the weather for?"
        );
        assert_eq!(request.options.len(), 2);
        assert_eq!(request.options[0].id, "share_city");
        assert!(request.options[0].recommended);
        assert_eq!(request.options[1].label, "General advice");
    });
}

#[test]
fn weather_advice_clarification_promotes_current_area_when_runtime_locality_exists() {
    with_runtime_locality_scope_hint_override(Some("Brooklyn, NY"), || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "weather-clarification-locality".to_string(),
            raw_prompt: "Should I wear a jacket today?".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.9,
            needs_clarification: true,
            clarification_questions: vec![
                "What city should Chat check the weather for?".to_string()
            ],
            routing_hints: vec![
                "tool_widget:weather".to_string(),
                "weather_advice_request".to_string(),
                "location_required_for_weather_advice".to_string(),
                "narrow_surface_preferred".to_string(),
            ],
            lane_frame: None,
            request_frame: None,
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        };

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("weather advice route should surface clarification UX");

        assert_eq!(request.options.len(), 3);
        assert_eq!(request.options[0].id, "share_city");
        assert!(!request.options[0].recommended);
        assert_eq!(request.options[1].id, "use_current_area");
        assert!(request.options[1].recommended);
    });
}

#[test]
fn message_compose_clarification_uses_domain_specific_prompt_and_options() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "message-clarification".to_string(),
        raw_prompt: "Draft something to my landlord about the lease renewal.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.9,
        needs_clarification: true,
        clarification_questions: vec!["What channel should Chat use?".to_string()],
        routing_hints: vec!["shared_answer_surface".to_string()],
        lane_frame: None,
        request_frame: Some(
            ioi_types::app::chat::ChatNormalizedRequestFrame::MessageCompose(
                ioi_types::app::chat::ChatMessageComposeRequestFrame {
                    channel: None,
                    recipient_context: Some("landlord".to_string()),
                    purpose: Some("draft".to_string()),
                    missing_slots: vec!["channel".to_string()],
                    clarification_required_slots: vec!["channel".to_string()],
                },
            ),
        ),
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("message route should surface clarification UX");

    assert_eq!(
        request.question,
        "Which channel should Chat draft this for: email, Slack, text, or chat?"
    );
    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].id, "draft_email");
    assert!(request.options[0].recommended);
    assert_eq!(request.options[1].id, "draft_slack");
    assert_eq!(request.options[2].id, "draft_text");
}

#[test]
fn places_clarification_uses_domain_specific_anchor_options() {
    with_runtime_locality_scope_hint_override(None, || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "places-clarification".to_string(),
            raw_prompt: "Find good coffee shops.".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.87,
            needs_clarification: true,
            clarification_questions: vec!["Where should Chat search?".to_string()],
            routing_hints: vec![
                "tool_widget:places".to_string(),
                "narrow_surface_preferred".to_string(),
            ],
            lane_frame: None,
            request_frame: Some(ioi_types::app::chat::ChatNormalizedRequestFrame::Places(
                ioi_types::app::chat::ChatPlacesRequestFrame {
                    search_anchor: None,
                    category: Some("coffee shops".to_string()),
                    location_scope: None,
                    missing_slots: vec!["search_anchor".to_string()],
                    clarification_required_slots: vec!["search_anchor".to_string()],
                },
            )),
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        };

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("places route should surface clarification UX");

        assert_eq!(
            request.question,
            "Which neighborhood, city, or anchor location should Chat search around?"
        );
        assert_eq!(request.options.len(), 2);
        assert_eq!(request.options[0].id, "share_location_anchor");
        assert!(request.options[0].recommended);
        assert_eq!(request.options[1].id, "broad_city_recs");
    });
}

#[test]
fn places_clarification_surfaces_current_area_when_runtime_locality_exists() {
    with_runtime_locality_scope_hint_override(Some("Williamsburg, Brooklyn"), || {
        let outcome_request = ChatOutcomeRequest {
            request_id: "places-clarification-locality".to_string(),
            raw_prompt: "Find good coffee shops.".to_string(),
            active_artifact_id: None,
            outcome_kind: ChatOutcomeKind::ToolWidget,
            execution_strategy: ChatExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.87,
            needs_clarification: true,
            clarification_questions: vec!["Where should Chat search?".to_string()],
            routing_hints: vec![
                "tool_widget:places".to_string(),
                "narrow_surface_preferred".to_string(),
            ],
            lane_frame: None,
            request_frame: Some(ioi_types::app::chat::ChatNormalizedRequestFrame::Places(
                ioi_types::app::chat::ChatPlacesRequestFrame {
                    search_anchor: None,
                    category: Some("coffee shops".to_string()),
                    location_scope: None,
                    missing_slots: vec!["search_anchor".to_string()],
                    clarification_required_slots: vec!["search_anchor".to_string()],
                },
            )),
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        };

        let request = clarification_request_for_outcome_request(&outcome_request)
            .expect("places route should surface clarification UX");

        assert_eq!(request.options.len(), 3);
        assert_eq!(request.options[1].id, "use_current_area");
        assert!(request.options[1].recommended);
    });
}

#[test]
fn places_request_frame_promotes_missing_anchor_into_clarification_gate() {
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "places-topology".to_string(),
        raw_prompt: "Find coffee shops open now.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.88,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "tool_widget:places".to_string(),
            "narrow_surface_preferred".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    super::content_session::refresh_outcome_request_topology(&mut outcome_request, None);

    assert!(outcome_request.needs_clarification);
    assert_eq!(
        outcome_request.clarification_questions,
        vec!["Which neighborhood, city, or anchor location should Chat search around?".to_string()]
    );
    assert!(outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "request_frame_clarification_required"));
    match outcome_request.request_frame.as_ref() {
        Some(ioi_types::app::chat::ChatNormalizedRequestFrame::Places(frame)) => {
            assert!(frame.clarification_required_slots.iter().any(|slot| {
                slot == "search_anchor" || slot == "location_scope" || slot == "location"
            }));
        }
        other => panic!("expected places request frame, got {other:?}"),
    }
}

#[test]
fn currentness_scope_clarification_surfaces_structured_topic_options() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "currentness-clarification".to_string(),
        raw_prompt: "What's happening this week?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.86,
        needs_clarification: true,
        clarification_questions: vec![
            "Do you mean local events, a specific topic, or general news this week?".to_string(),
        ],
        routing_hints: vec![
            "currentness_override".to_string(),
            "currentness_scope_ambiguous".to_string(),
            "clarification_required_for_currentness".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("currentness clarification should surface structured options");

    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].label, "Local events");
    assert!(request.options[0].recommended);
    assert_eq!(request.options[1].id, "specific_topic");
    assert_eq!(request.options[2].id, "general_news");
}

#[test]
fn connector_catalog_application_routes_mail_intent_into_integrations_lane() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "mail.primary".to_string(),
        plugin_id: "wallet_mail".to_string(),
        name: "Mail".to_string(),
        provider: "wallet.network".to_string(),
        category: "communication".to_string(),
        description: "Wallet-backed mail connector.".to_string(),
        status: "connected".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec![
            "mail.read.latest".to_string(),
            "mail.list.recent".to_string(),
            "mail.delete".to_string(),
        ],
        last_sync_at_utc: None,
        notes: None,
    }];
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "mail-delete-route".to_string(),
        raw_prompt: "Delete these emails".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.9,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["shared_answer_surface".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    super::content_session::apply_connector_catalog_to_outcome_request(
        &mut outcome_request,
        &connectors,
    );
    super::content_session::refresh_outcome_request_topology(&mut outcome_request, None);

    assert!(outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "connector_intent_detected"));
    assert!(outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "connector_preferred"));
    assert!(outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "selected_connector_id:mail.primary"));

    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("communication")
    );
    let source_selection = payload_object
        .get("source_selection")
        .and_then(|value| value.as_object())
        .expect("source selection");
    assert_eq!(
        source_selection
            .get("selectedSource")
            .and_then(|value| value.as_str()),
        Some("connector")
    );
}

#[test]
fn connector_catalog_application_preserves_connector_source_for_artifact_report_requests() {
    let connectors = vec![ConnectorCatalogEntry {
        id: "mail.primary".to_string(),
        plugin_id: "wallet_mail".to_string(),
        name: "Mail".to_string(),
        provider: "wallet.network".to_string(),
        category: "communication".to_string(),
        description: "Wallet-backed mail connector.".to_string(),
        status: "connected".to_string(),
        auth_mode: "wallet_capability".to_string(),
        scopes: vec![
            "mail.read.latest".to_string(),
            "mail.list.recent".to_string(),
            "mail.delete".to_string(),
        ],
        last_sync_at_utc: None,
        notes: None,
    }];
    let artifact = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Document,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };
    let mut outcome_request = ChatOutcomeRequest {
        request_id: "mail-artifact-route".to_string(),
        raw_prompt: "Summarize my unread emails into an HTML report".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["persistent_artifact_requested".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(artifact),
    };

    super::content_session::apply_connector_catalog_to_outcome_request(
        &mut outcome_request,
        &connectors,
    );
    super::content_session::refresh_outcome_request_topology(&mut outcome_request, None);

    assert!(outcome_request
        .routing_hints
        .iter()
        .any(|hint| hint == "connector_intent_detected"));
    let payload = super::content_session::build_route_contract_payload(&outcome_request, false);
    let payload_object = payload.as_object().expect("payload object");
    assert_eq!(
        payload_object
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("artifact_html_iframe")
    );
    assert_eq!(
        payload_object
            .get("route_family")
            .and_then(|value| value.as_str()),
        Some("communication")
    );
    let source_selection = payload_object
        .get("source_selection")
        .and_then(|value| value.as_object())
        .expect("source selection");
    assert_eq!(
        source_selection
            .get("selectedSource")
            .and_then(|value| value.as_str()),
        Some("connector")
    );
    let retained_lane_state = payload_object
        .get("retained_lane_state")
        .and_then(|value| value.as_object())
        .expect("retained lane state");
    assert_eq!(
        retained_lane_state
            .get("selectedProviderFamily")
            .and_then(|value| value.as_str()),
        Some("mail.wallet_network")
    );
}

#[test]
fn prioritization_clarification_surfaces_structured_ranking_options() {
    let outcome_request = ChatOutcomeRequest {
        request_id: "prioritization-clarification".to_string(),
        raw_prompt: "Help me prioritize my renovation projects".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: true,
        clarification_questions: vec![
            "What options or decision shape should Chat present?".to_string()
        ],
        routing_hints: vec![
            "tool_widget:user_input".to_string(),
            "user_input_preferred".to_string(),
            "prioritization_request".to_string(),
            "structured_input_options_missing".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };

    let request = clarification_request_for_outcome_request(&outcome_request)
        .expect("prioritization clarification should surface structured ranking options");

    assert_eq!(
        request.question,
        "What should drive the ranking: impact, urgency, or return on investment?"
    );
    assert_eq!(
        request.evidence_snippet.as_deref(),
        Some(
            "Chat paused before selecting the outcome surface because it needs clarification: What should drive the ranking: impact, urgency, or return on investment?"
        )
    );
    assert_eq!(request.options.len(), 3);
    assert_eq!(request.options[0].id, "impact_first");
    assert!(request.options[0].recommended);
    assert_eq!(request.options[1].id, "urgency_first");
    assert_eq!(request.options[2].id, "roi_first");
}

#[test]
fn currentness_override_conversation_does_not_stay_chat_primary() {
    let mut task = empty_task("What is the latest OpenAI API pricing?");
    let outcome_request = ChatOutcomeRequest {
        request_id: "currentness-override".to_string(),
        raw_prompt: "What is the latest OpenAI API pricing?".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "currentness_override".to_string(),
            "no_persistent_artifact_requested".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_non_artifact_chat_session(
        &mut task,
        "What is the latest OpenAI API pricing?",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    assert!(!task_requires_chat_primary_execution(&task));
}

#[test]
fn provisional_artifact_route_state_emits_route_receipt_before_materialization() {
    let prompt = "A mortgage calculator where I can adjust rate, term, and down payment";
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };
    let outcome_request = ChatOutcomeRequest {
        request_id: "interactive-artifact-route".to_string(),
        raw_prompt: prompt.to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::DirectAuthor,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["interactive_surface_requested".to_string()],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request.clone()),
    };
    let title = "Mortgage calculator";
    let summary = "Chat is preparing the interactive artifact.";
    let chat_session = super::prepare::provisional_non_workspace_chat_session(
        "thread-1",
        "chat-session-1",
        title,
        summary,
        "2026-04-15T00:00:00Z",
        &outcome_request,
        Some("prompt-evt-1"),
        materialization_contract_for_request(
            prompt,
            &request,
            summary,
            None,
            outcome_request.execution_strategy,
        ),
    )
    .expect("provisional session");
    let mut task = empty_task(prompt);

    super::prepare::seed_provisional_artifact_route_state(
        &mut task,
        &outcome_request,
        summary,
        chat_session,
        None,
        None,
    );

    let route_event = task
        .events
        .iter()
        .find(|event| event.title == "Chat route decision")
        .expect("route decision event");
    let digest = route_event.digest.as_object().expect("route digest");
    assert_eq!(
        digest
            .get("selected_route")
            .and_then(|value| value.as_str()),
        Some("artifact_html_iframe")
    );
    let route_decision = digest
        .get("route_decision")
        .and_then(|value| value.as_object())
        .expect("route decision payload");
    assert_eq!(
        route_decision
            .get("output_intent")
            .and_then(|value| value.as_str()),
        Some("artifact")
    );
    assert_eq!(
        route_decision
            .get("artifact_output_intent")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(task.chat_session.is_some());
}
