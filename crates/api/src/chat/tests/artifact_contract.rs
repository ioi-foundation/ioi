use super::*;

#[test]
fn direct_author_fast_surface_skips_acceptance_runtime() {
    #[derive(Debug, Clone)]
    struct FastProductionRuntime;

    #[async_trait]
    impl InferenceRuntime for FastProductionRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            let response = if prompt.contains("typed artifact brief planner") {
                serde_json::to_string(&sample_quantum_markdown_brief())
                    .expect("sample markdown brief should serialize")
            } else if prompt.contains("direct document author") {
                "# Quantum computers\n\nQuantum computing uses qubits, interference, and measurement to solve certain classes of problems differently from classical machines.\n\n## Core concepts\n- Superposition keeps multiple amplitudes in play.\n- Entanglement links qubit states.\n- Measurement samples a concrete result."
                    .to_string()
            } else if prompt.contains("typed artifact validation") {
                serde_json::json!({
                    "classification": "pass",
                    "requestFaithfulness": 4,
                    "conceptCoverage": 4,
                    "interactionRelevance": 3,
                    "layoutCoherence": 4,
                    "visualHierarchy": 4,
                    "completeness": 4,
                    "genericShellDetected": false,
                    "trivialShellDetected": false,
                    "deservesPrimaryArtifactView": false,
                    "patchedExistingArtifact": null,
                    "continuityRevisionUx": null,
                    "issueClasses": [],
                    "repairHints": [],
                    "strengths": ["Request-specific direct draft"],
                    "blockedReasons": [],
                    "fileFindings": [],
                    "aestheticVerdict": "Specific enough for a viable draft.",
                    "interactionVerdict": "A single-document artifact does not require extra interaction.",
                    "truthfulnessWarnings": [],
                    "recommendedNextPass": "accept",
                    "strongestContradiction": null,
                    "rationale": "The direct-authored draft is viable even before stronger acceptance finishes."
                })
                .to_string()
            } else {
                return Err(VmError::HostError(format!(
                    "unexpected production prompt in direct-author timeout test: {prompt}"
                )));
            };
            Ok(response.into_bytes())
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            Ok(Vec::new())
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::FixtureRuntime,
                label: "fast production fixture".to_string(),
                model: Some("fixture-production".to_string()),
                endpoint: Some("fixture://production".to_string()),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct SlowAcceptanceRuntime;

    #[async_trait]
    impl InferenceRuntime for SlowAcceptanceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "direct-author fast surface should not call the acceptance runtime: {prompt}"
            )))
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            Ok(Vec::new())
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::FixtureRuntime,
                label: "slow acceptance fixture".to_string(),
                model: Some("fixture-acceptance".to_string()),
                endpoint: Some("fixture://acceptance".to_string()),
            }
        }
    }

    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(FastProductionRuntime);
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowAcceptanceRuntime);
    let title = "Quantum computers brief";
    let intent = "Create a markdown artifact that explains quantum computers";
    let evaluator = ChatPassingRenderEvaluator;

    let bundle = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let runtime_plan = resolve_chat_artifact_runtime_plan(
                &request,
                production_runtime.clone(),
                Some(acceptance_runtime.clone()),
                ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
            );
            let planning_context = planned_prepared_context_with_runtime_plan(
                &runtime_plan,
                title,
                intent,
                &request,
                None,
            )
            .await;
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::DirectAuthor,
                Some(&evaluator),
                None,
                None,
            )
            .await
        })
        .expect("direct author fast surface should return a validated bundle");

    assert_eq!(bundle.ux_lifecycle, ChatArtifactUxLifecycle::Validated);
    assert_eq!(
        bundle.validation.classification,
        ChatArtifactValidationStatus::Pass
    );
    assert!(bundle
        .validation
        .rationale
        .contains("without waiting on the slow acceptance gate"));
    assert_eq!(bundle.winner.files[0].path, "artifact.md");
    assert!(bundle.winning_candidate_id.is_some());
}

pub(crate) fn chat_test_validation(
    classification: ChatArtifactValidationStatus,
    deserves_primary_artifact_view: bool,
    request_faithfulness: u8,
    concept_coverage: u8,
    interaction_relevance: u8,
    layout_coherence: u8,
    visual_hierarchy: u8,
    completeness: u8,
) -> ChatArtifactValidationResult {
    ChatArtifactValidationResult {
        classification,
        request_faithfulness,
        concept_coverage,
        interaction_relevance,
        layout_coherence,
        visual_hierarchy,
        completeness,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        score_total: i32::from(request_faithfulness)
            + i32::from(concept_coverage)
            + i32::from(interaction_relevance)
            + i32::from(layout_coherence)
            + i32::from(visual_hierarchy)
            + i32::from(completeness),
        proof_kind: "test_fixture".to_string(),
        primary_view_cleared: deserves_primary_artifact_view,
        validated_paths: Vec::new(),
        issue_codes: Vec::new(),
        issue_classes: Vec::new(),
        repair_hints: Vec::new(),
        strengths: Vec::new(),
        blocked_reasons: Vec::new(),
        file_findings: Vec::new(),
        aesthetic_verdict: "Test verdict".to_string(),
        interaction_verdict: "Test verdict".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: None,
        strongest_contradiction: None,
        summary: "Test summary".to_string(),
        rationale: "Test rationale".to_string(),
    }
}

#[test]
fn requested_follow_up_pass_prefers_structural_repair_for_repairable_accept_mismatch() {
    let mut validation = chat_test_validation(
        ChatArtifactValidationStatus::Repairable,
        false,
        5,
        5,
        4,
        4,
        5,
        4,
    );
    validation.recommended_next_pass = Some("accept".to_string());

    assert_eq!(
        requested_follow_up_pass(&validation),
        Some("structural_repair")
    );
}

#[test]
fn requested_follow_up_pass_prefers_polish_for_warning_only_render_eval_repairs() {
    let mut validation = chat_test_validation(
        ChatArtifactValidationStatus::Repairable,
        false,
        5,
        5,
        5,
        4,
        5,
        4,
    );
    validation.issue_classes = vec!["render_eval".to_string()];
    validation.recommended_next_pass = Some("accept".to_string());

    assert_eq!(requested_follow_up_pass(&validation), Some("polish_pass"));
}

#[test]
fn requested_follow_up_pass_stops_for_clean_acceptance_clear() {
    let mut validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 5, 5, 5);
    validation.recommended_next_pass = Some("accept".to_string());

    assert_eq!(requested_follow_up_pass(&validation), None);
}

#[test]
fn requested_follow_up_pass_keeps_repairing_nontrivial_blocks() {
    let mut validation = chat_test_validation(
        ChatArtifactValidationStatus::Blocked,
        false,
        4,
        5,
        2,
        2,
        2,
        3,
    );
    validation.repair_hints = vec![
        "Increase text contrast.".to_string(),
        "Strengthen visible interaction change.".to_string(),
    ];

    assert_eq!(
        requested_follow_up_pass(&validation),
        Some("structural_repair")
    );
}

#[test]
fn modal_first_refinement_directives_do_not_force_shared_detail_panels() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let validation = chat_test_validation(
            ChatArtifactValidationStatus::Repairable,
            false,
            4,
            5,
            2,
            3,
            3,
            3,
        );

        let directives =
            super::chat_artifact_candidate_refinement_directives(&request, &brief, &validation);

        assert!(!directives
            .contains("Use a named control bar plus a shared detail or comparison panel"));
        assert!(directives.contains("detached shared-detail panel is optional"));
        assert!(directives.contains("chosen interaction grammar"));
    });
}

pub(crate) fn chat_test_candidate_summary(
    candidate_id: &str,
    validation: ChatArtifactValidationResult,
) -> ChatArtifactCandidateSummary {
    ChatArtifactCandidateSummary {
        candidate_id: candidate_id.to_string(),
        seed: 1,
        model: "test-model".to_string(),
        temperature: 0.2,
        strategy: "test".to_string(),
        origin: ChatArtifactOutputOrigin::MockInference,
        provenance: Some(ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::MockRuntime,
            label: "mock".to_string(),
            model: Some("test-model".to_string()),
            endpoint: None,
        }),
        summary: format!("Summary for {candidate_id}"),
        renderable_paths: vec!["index.html".to_string()],
        selected: false,
        fallback: false,
        failure: None,
        raw_output_preview: None,
        convergence: None,
        render_evaluation: None,
        validation,
    }
}

pub(crate) fn chat_test_render_capture(
    viewport: ChatArtifactRenderCaptureViewport,
    visible_element_count: usize,
    visible_text_chars: usize,
    interactive_element_count: usize,
) -> ChatArtifactRenderCapture {
    ChatArtifactRenderCapture {
        viewport,
        width: 1440,
        height: 960,
        screenshot_sha256: format!("sha-{visible_element_count}-{visible_text_chars}"),
        screenshot_byte_count: 2048,
        visible_element_count,
        visible_text_chars,
        interactive_element_count,
        screenshot_changed_from_previous: true,
    }
}

pub(crate) fn chat_test_render_evaluation(
    overall_score: u8,
    first_paint_captured: bool,
    findings: Vec<ChatArtifactRenderFinding>,
    captures: Vec<ChatArtifactRenderCapture>,
) -> ChatArtifactRenderEvaluation {
    ChatArtifactRenderEvaluation {
        supported: true,
        first_paint_captured,
        interaction_capture_attempted: captures
            .iter()
            .any(|capture| capture.viewport == ChatArtifactRenderCaptureViewport::Interaction),
        captures,
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 4,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 4,
        overall_score,
        findings,
        acceptance_obligations: Vec::new(),
        execution_witnesses: Vec::new(),
        summary: "Render evaluation completed.".to_string(),
        observation: None,
        acceptance_policy: None,
    }
}

#[derive(Default)]
pub(crate) struct ChatPassingRenderEvaluator;

#[async_trait]
impl ChatArtifactRenderEvaluator for ChatPassingRenderEvaluator {
    async fn evaluate_candidate_render(
        &self,
        _request: &ChatOutcomeArtifactRequest,
        _brief: &ChatArtifactBrief,
        _blueprint: Option<&ChatArtifactBlueprint>,
        _artifact_ir: Option<&ChatArtifactIR>,
        _edit_intent: Option<&ChatArtifactEditIntent>,
        _candidate: &ChatGeneratedArtifactPayload,
    ) -> Result<Option<ChatArtifactRenderEvaluation>, String> {
        Ok(Some(chat_test_render_evaluation(
            18,
            true,
            Vec::new(),
            vec![
                chat_test_render_capture(
                    ChatArtifactRenderCaptureViewport::Desktop,
                    88,
                    720,
                    4,
                ),
                chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 72, 610, 4),
            ],
        )))
    }
}

#[test]
fn derived_blueprint_for_html_brief_emits_structure_and_skill_needs() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let blueprint = derive_chat_artifact_blueprint(&request, &sample_html_brief());

    assert_eq!(blueprint.renderer, ChatRendererKind::HtmlIframe);
    assert_eq!(blueprint.scaffold_family, "comparison_story");
    assert!(blueprint.section_plan.len() >= 4);
    assert!(blueprint
        .interaction_plan
        .iter()
        .any(|interaction| interaction.family == "view_switching"));
    assert!(blueprint
        .skill_needs
        .iter()
        .any(|need| need.kind == ChatArtifactSkillNeedKind::VisualArtDirection));
    assert!(blueprint
        .skill_needs
        .iter()
        .any(|need| need.kind == ChatArtifactSkillNeedKind::AccessibilityReview));
    assert!(blueprint
        .component_plan
        .iter()
        .any(|component| component.component_family == "tabbed_evidence_rail"));
    assert!(blueprint
        .component_plan
        .iter()
        .any(|component| component.component_family == "comparison_table"));
}

#[test]
fn compiled_artifact_ir_captures_scaffold_tokens_and_render_checks() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);

    assert_eq!(artifact_ir.scaffold_family, blueprint.scaffold_family);
    assert!(!artifact_ir.semantic_structure.is_empty());
    assert!(!artifact_ir.design_tokens.is_empty());
    assert!(!artifact_ir.render_eval_checklist.is_empty());
    assert!(artifact_ir
        .static_audit_expectations
        .iter()
        .any(|expectation| expectation.contains("first-paint")));
    assert!(artifact_ir
        .component_bindings
        .iter()
        .any(|binding| binding.contains("tabbed_evidence_rail")));
}

#[test]
fn render_eval_merge_blocks_primary_view_when_first_paint_fails() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 5, 5, 5);
    let render_evaluation = chat_test_render_evaluation(
        8,
        false,
        vec![ChatArtifactRenderFinding {
            code: "first_paint_missing".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Blocked,
            summary: "First paint never stabilized.".to_string(),
        }],
        vec![chat_test_render_capture(
            ChatArtifactRenderCaptureViewport::Desktop,
            0,
            0,
            0,
        )],
    );

    let merged = merge_chat_artifact_render_evaluation_into_validation(
        &request,
        validation,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        ChatArtifactValidationStatus::Blocked
    );
    assert!(!merged.deserves_primary_artifact_view);
    assert!(merged.trivial_shell_detected);
    assert_eq!(
        merged.strongest_contradiction.as_deref(),
        Some("First paint never stabilized.")
    );
    assert!(merged
        .issue_classes
        .iter()
        .any(|value| value == "render_eval"));
    assert!(merged
        .blocked_reasons
        .iter()
        .any(|value| value == "First paint never stabilized."));
}

#[test]
fn render_eval_merge_adds_strength_for_clean_desktop_and_mobile_captures() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 4, 4, 4, 4, 4, 4);
    let render_evaluation = chat_test_render_evaluation(
        22,
        true,
        Vec::new(),
        vec![
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Desktop, 48, 420, 6),
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 46, 405, 6),
        ],
    );

    let merged = merge_chat_artifact_render_evaluation_into_validation(
        &request,
        validation,
        Some(&render_evaluation),
    );

    assert_eq!(merged.classification, ChatArtifactValidationStatus::Pass);
    assert!(merged.deserves_primary_artifact_view);
    assert!(merged
        .strengths
        .iter()
        .any(|value| value.contains("Desktop and mobile render captures")));
    assert!(merged.rationale.contains("Render evaluation"));
}

#[test]
fn render_eval_merge_overrides_accept_to_polish_for_warning_only_regressions() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let mut validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 4, 5, 4);
    validation.recommended_next_pass = Some("accept".to_string());
    let render_evaluation = chat_test_render_evaluation(
        17,
        true,
        vec![ChatArtifactRenderFinding {
            code: "alignment_unstable".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Warning,
            summary: "Captured viewports show weak alignment or inconsistent spacing cadence."
                .to_string(),
        }],
        vec![
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Desktop, 12, 1629, 5),
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 7, 1076, 3),
        ],
    );

    let merged = merge_chat_artifact_render_evaluation_into_validation(
        &request,
        validation,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        ChatArtifactValidationStatus::Repairable
    );
    assert!(!merged.deserves_primary_artifact_view);
    assert_eq!(merged.recommended_next_pass.as_deref(), Some("polish_pass"));
    assert_eq!(
        merged.strongest_contradiction.as_deref(),
        Some("Captured viewports show weak alignment or inconsistent spacing cadence.")
    );
}

#[test]
fn render_eval_merge_keeps_primary_view_for_warning_only_regressions_above_threshold() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let mut validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 4, 5, 4);
    validation.recommended_next_pass = Some("accept".to_string());
    let render_evaluation = chat_test_render_evaluation(
        19,
        true,
        vec![ChatArtifactRenderFinding {
            code: "alignment_unstable".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Warning,
            summary: "Captured viewports show weak alignment or inconsistent spacing cadence."
                .to_string(),
        }],
        vec![
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Desktop, 12, 1629, 5),
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 7, 1076, 3),
        ],
    );

    let merged = merge_chat_artifact_render_evaluation_into_validation(
        &request,
        validation,
        Some(&render_evaluation),
    );

    assert_eq!(merged.classification, ChatArtifactValidationStatus::Pass);
    assert!(merged.deserves_primary_artifact_view);
    assert_eq!(merged.recommended_next_pass.as_deref(), Some("polish_pass"));
    assert_eq!(
        merged.strongest_contradiction.as_deref(),
        Some("Captured viewports show weak alignment or inconsistent spacing cadence.")
    );
}

#[test]
fn render_eval_merge_ignores_unsupported_markdown_failures() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 4, 4, 4, 4, 4, 4);
    let render_evaluation = ChatArtifactRenderEvaluation {
        supported: false,
        first_paint_captured: false,
        interaction_capture_attempted: false,
        captures: Vec::new(),
        layout_density_score: 1,
        spacing_alignment_score: 1,
        typography_contrast_score: 1,
        visual_hierarchy_score: 1,
        blueprint_consistency_score: 1,
        overall_score: 1,
        findings: vec![ChatArtifactRenderFinding {
            code: "render_eval_failure".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Blocked,
                summary: "Render evaluation failed before Chat could verify the surfaced first paint: Driver internal error: JS decode failed: No value found".to_string(),
        }],
        acceptance_obligations: Vec::new(),
        execution_witnesses: Vec::new(),
        summary: "Render evaluation failed before Chat could verify the surfaced first paint: Driver internal error: JS decode failed: No value found".to_string(),
        observation: None,
        acceptance_policy: None,
    };

    let merged = merge_chat_artifact_render_evaluation_into_validation(
        &request,
        validation.clone(),
        Some(&render_evaluation),
    );

    assert_eq!(merged.classification, validation.classification);
    assert_eq!(
        merged.deserves_primary_artifact_view,
        validation.deserves_primary_artifact_view
    );
    assert!(!merged
        .issue_classes
        .iter()
        .any(|value| value == "render_eval"));
}

#[test]
fn render_eval_merge_downgrades_markdown_typography_block_to_warning() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 4, 4, 4, 4, 4, 4);
    let render_evaluation = ChatArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: false,
        captures: vec![
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Desktop, 18, 220, 0),
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 16, 180, 0),
        ],
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 2,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 4,
        overall_score: 18,
        findings: vec![ChatArtifactRenderFinding {
            code: "typography_contrast_low".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Blocked,
            summary: "Readable text contrast or typographic separation is still too weak in the captured render.".to_string(),
        }],
        acceptance_obligations: vec![
            ChatArtifactAcceptanceObligation {
                obligation_id: "document_complete".to_string(),
                family: "document_truth".to_string(),
                required: true,
                status: ChatArtifactAcceptanceObligationStatus::Passed,
                summary: "Chat captured desktop and mobile first paint.".to_string(),
                detail: None,
                witness_ids: Vec::new(),
            },
            ChatArtifactAcceptanceObligation {
                obligation_id: "primary_surface_present".to_string(),
                family: "presentation_truth".to_string(),
                required: true,
                status: ChatArtifactAcceptanceObligationStatus::Passed,
                summary: "The primary artifact surface is visibly present on first paint.".to_string(),
                detail: None,
                witness_ids: Vec::new(),
            },
        ],
        execution_witnesses: Vec::new(),
        summary: "Render evaluation observed minor typography weakness but preserved the document surface.".to_string(),
        observation: None,
        acceptance_policy: None,
    };

    let merged = merge_chat_artifact_render_evaluation_into_validation(
        &request,
        validation,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        ChatArtifactValidationStatus::Repairable
    );
    assert_eq!(merged.recommended_next_pass.as_deref(), Some("polish_pass"));
    assert_eq!(merged.strongest_contradiction.as_deref(), Some("Render evaluation observed minor typography weakness but preserved the document surface."));
    assert!(!merged
        .blocked_reasons
        .iter()
        .any(|reason| reason.contains("Readable text contrast")));
}

#[test]
fn render_evaluation_required_skips_default_markdown_requests() {
    let mut request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    request.verification.require_render = false;

    assert!(!render_evaluation_required(&request));
}

#[test]
fn render_evaluation_required_preserves_html_first_paint_checks() {
    let mut request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    request.verification.require_render = false;

    assert!(render_evaluation_required(&request));
}

#[test]
fn render_eval_merge_blocks_pass_when_required_execution_obligations_fail() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let validation =
        chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 5, 5, 5);
    let render_evaluation = ChatArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: true,
        captures: vec![
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Desktop, 24, 220, 4),
            chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 22, 196, 4),
        ],
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 4,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 4,
        overall_score: 20,
        findings: Vec::new(),
        acceptance_obligations: vec![ChatArtifactAcceptanceObligation {
            obligation_id: "controls_execute_cleanly".to_string(),
            family: "interaction_truth".to_string(),
            required: true,
            status: ChatArtifactAcceptanceObligationStatus::Failed,
            summary: "Surfaced controls executed without runtime errors or no-op behavior."
                .to_string(),
            detail: Some("successfulWitnesses=1 failedWitnesses=3".to_string()),
            witness_ids: vec!["witness-1".to_string()],
        }],
        execution_witnesses: vec![ChatArtifactExecutionWitness {
            witness_id: "witness-1".to_string(),
            obligation_id: Some("controls_execute_cleanly".to_string()),
            action_kind: "click".to_string(),
            status: ChatArtifactExecutionWitnessStatus::Failed,
            summary: "'Quantum Qubit' triggered a runtime error.".to_string(),
            detail: Some("ReferenceError: toggleQubit is not defined".to_string()),
            selector: Some("#btn-qubit".to_string()),
            console_errors: vec!["ReferenceError: toggleQubit is not defined".to_string()],
            state_changed: false,
        }],
        summary: "Render evaluation blocked the primary view.".to_string(),
        observation: None,
        acceptance_policy: None,
    };

    let merged = merge_chat_artifact_render_evaluation_into_validation(
        &request,
        validation,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        ChatArtifactValidationStatus::Repairable
    );
    assert!(!merged.deserves_primary_artifact_view);
    assert_eq!(
        merged.strongest_contradiction.as_deref(),
        Some(
            "Surfaced controls executed without runtime errors or no-op behavior. successfulWitnesses=1 failedWitnesses=3"
        )
    );
    assert!(merged
        .issue_classes
        .iter()
        .any(|value| value == "execution_witness"));
    assert!(merged
        .repair_hints
        .iter()
        .any(|value| value.contains("runtime error")));
}

#[derive(Default)]
struct ChatSlowRenderEvaluator;

#[async_trait]
impl ChatArtifactRenderEvaluator for ChatSlowRenderEvaluator {
    async fn evaluate_candidate_render(
        &self,
        _request: &ChatOutcomeArtifactRequest,
        _brief: &ChatArtifactBrief,
        _blueprint: Option<&ChatArtifactBlueprint>,
        _artifact_ir: Option<&ChatArtifactIR>,
        _edit_intent: Option<&ChatArtifactEditIntent>,
        _candidate: &ChatGeneratedArtifactPayload,
    ) -> Result<Option<ChatArtifactRenderEvaluation>, String> {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok(Some(chat_test_render_evaluation(
            20,
            true,
            Vec::new(),
            vec![chat_test_render_capture(
                ChatArtifactRenderCaptureViewport::Desktop,
                120,
                240,
                6,
            )],
        )))
    }
}

#[test]
fn browser_backed_render_eval_timeout_is_bounded() {
    assert_eq!(
        render_eval_timeout_for_runtime(
            ChatRendererKind::HtmlIframe,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        ),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        render_eval_timeout_for_runtime(
            ChatRendererKind::Markdown,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        ),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        render_eval_timeout_for_runtime(
            ChatRendererKind::BundleManifest,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        ),
        None
    );
}

#[tokio::test]
async fn render_eval_wrapper_passes_through_non_local_results() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();
    let candidate = ChatGeneratedArtifactPayload {
        summary: "Interactive rollout artifact".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>AI tools</h1></section><section><button type=\"button\">Compare</button></section><section><p>Evidence</p></section></main></body></html>".to_string(),
        }],
    };
    let evaluator = ChatSlowRenderEvaluator;

    let evaluation = evaluate_candidate_render_with_fallback(
        Some(&evaluator),
        &request,
        &brief,
        None,
        None,
        None,
        &candidate,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
    .await
    .expect("render evaluation result");

    assert!(evaluation.supported);
    assert!(evaluation.first_paint_captured);
}

#[test]
fn exemplar_query_prefers_structural_grounding_over_text_copy() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);
    let taste_memory = ChatArtifactTasteMemory {
        directives: vec!["editorial".to_string()],
        summary: "Prefer scientific editorial framing.".to_string(),
        typography_preferences: vec!["display serif + mono".to_string()],
        density_preference: Some("airy".to_string()),
        tone_family: vec!["editorial".to_string(), "scientific".to_string()],
        motion_tolerance: Some("measured".to_string()),
        preferred_scaffold_families: vec!["immersive_explainer".to_string()],
        preferred_component_patterns: vec!["bloch_sphere_demo".to_string()],
        anti_patterns: vec!["generic_cards".to_string()],
    };

    let query =
        build_chat_artifact_exemplar_query(&brief, &blueprint, &artifact_ir, Some(&taste_memory));

    assert!(query.contains(&format!("Scaffold family: {}", blueprint.scaffold_family)));
    assert!(query.contains("Interaction families:"));
    assert!(query.contains("bloch_sphere_demo"));
    assert!(query.contains("display serif + mono"));
    assert!(query.contains("Preferred scaffold families: immersive_explainer"));
    assert!(query.contains("Anti patterns: generic_cards"));
    assert!(query.contains("Use them as structural grounding only"));
}

#[test]
fn html_scaffold_registry_supplies_design_spine_and_component_contracts() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);
    let selected_skills = vec![ChatArtifactSelectedSkill {
        skill_hash: "skill-hash".to_string(),
        name: "frontend_editorial_direction".to_string(),
        description: "Editorial direction".to_string(),
        lifecycle_state: "promoted".to_string(),
        source_type: "imported".to_string(),
        reliability_bps: 9800,
        semantic_score_bps: 9000,
        adjusted_score_bps: 9300,
        relative_path: None,
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![ChatArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched the scaffold's visual art direction need.".to_string(),
        guidance_markdown: Some("Prefer editorial hierarchy.".to_string()),
    }];

    let design_spine =
        chat_html_promoted_design_skill_spine(&brief, &blueprint, &artifact_ir, &selected_skills)
            .expect("html design spine");
    let scaffold =
        chat_html_scaffold_contract(&blueprint, &artifact_ir, 7).expect("html scaffold");
    let component_packs = chat_html_component_pack_contracts(&blueprint);
    let digest = chat_html_scaffold_execution_digest(
        &brief,
        &blueprint,
        &artifact_ir,
        &selected_skills,
        7,
    )
    .expect("execution digest");

    assert!(design_spine.visual_thesis.contains("comparison"));
    assert!(design_spine
        .reinforced_need_kinds
        .iter()
        .any(|kind| kind == "visual_art_direction"));
    assert!(scaffold.font_embed_href.contains("fonts.googleapis.com"));
    assert!(scaffold.control_bar_pattern.contains("data-view"));
    assert!(scaffold.detail_panel_pattern.contains("#detail-copy"));
    assert!(component_packs
        .iter()
        .any(|pack| pack.family == "tabbed_evidence_rail"));
    assert!(digest.contains("Component packs to compose"));
}

#[test]
fn jsx_scaffold_registry_supplies_renderer_specific_design_spine_and_contracts() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::JsxSandbox,
    );
    let brief = sample_html_brief();
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);
    let selected_skills = vec![ChatArtifactSelectedSkill {
        skill_hash: "skill-hash".to_string(),
        name: "frontend_editorial_direction".to_string(),
        description: "Editorial direction".to_string(),
        lifecycle_state: "promoted".to_string(),
        source_type: "imported".to_string(),
        reliability_bps: 9800,
        semantic_score_bps: 9000,
        adjusted_score_bps: 9300,
        relative_path: None,
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![ChatArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched the scaffold's visual art direction need.".to_string(),
        guidance_markdown: Some("Prefer editorial hierarchy.".to_string()),
    }];

    let design_spine =
        chat_jsx_promoted_design_skill_spine(&brief, &blueprint, &artifact_ir, &selected_skills)
            .expect("jsx design spine");
    let scaffold = chat_jsx_scaffold_contract(&blueprint, &artifact_ir, 7).expect("jsx scaffold");
    let component_packs = chat_jsx_component_pack_contracts(&blueprint);
    let digest =
        chat_jsx_scaffold_execution_digest(&brief, &blueprint, &artifact_ir, &selected_skills, 7)
            .expect("jsx execution digest");

    assert!(design_spine.visual_thesis.contains("React/JSX surface"));
    assert!(design_spine
        .avoidances
        .iter()
        .any(|line| line.contains("document.querySelector")));
    assert!(scaffold.example_shell.contains("useState"));
    assert!(scaffold.control_bar_pattern.contains("component state"));
    assert!(component_packs
        .iter()
        .all(|pack| pack.behavior_signature.contains("JSX state")));
    assert!(digest.contains("JSX shell"));
}

#[test]
fn quantum_explainer_maps_to_structural_component_packs_without_domain_branching() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);
    let component_families = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.as_str())
        .collect::<Vec<_>>();

    assert_eq!(blueprint.scaffold_family, "guided_tutorial");
    assert!(component_families.contains(&"guided_stepper"));
    assert!(component_families.contains(&"state_space_visualizer"));
    assert!(component_families.contains(&"distribution_comparator"));
    assert!(component_families.contains(&"transform_diagram_surface"));
    assert!(component_families.contains(&"paired_state_correlation_demo"));
    assert!(artifact_ir
        .component_bindings
        .iter()
        .any(|binding| binding.contains("state_space_visualizer")));
}

#[test]
fn parse_chat_artifact_brief_coerces_scalar_and_array_shapes() {
    let brief = parse_chat_artifact_brief(
        r#"{
              "audience": ["operators"],
              "jobToBeDone": "inspect the rollout",
              "subjectDomain": "dog shampoo launch",
              "artifactThesis": "Explain the launch with labeled charts.",
              "requiredConcepts": "dog shampoo",
              "requiredInteractions": "chart toggle",
              "visualTone": "informative",
              "factualAnchors": ["customer feedback"],
              "styleDirectives": "clear hierarchy",
              "referenceHints": null
            }"#,
    )
    .expect("brief coercion should parse");

    assert_eq!(brief.audience, "operators");
    assert_eq!(brief.required_concepts, vec!["dog shampoo".to_string()]);
    assert_eq!(brief.visual_tone, vec!["informative".to_string()]);
    assert_eq!(brief.reference_hints, Vec::<String>::new());
}

#[test]
fn request_grounded_markdown_brief_prefers_subject_from_full_prompt_over_truncated_title() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let brief = derive_request_grounded_chat_artifact_brief(
        "Create a markdown brief explaining the HTTP request lifecycle in ...",
        "Create a markdown brief explaining the HTTP request lifecycle in five bullets.",
        &request,
        None,
    );

    assert_eq!(brief.subject_domain, "HTTP request lifecycle");
    assert_eq!(
        brief.job_to_be_done,
        "explain HTTP request lifecycle in five bullets"
    );
    assert_eq!(brief.artifact_thesis, "A HTTP request lifecycle document");
    assert_eq!(
        brief.required_concepts,
        vec![
            "HTTP request lifecycle".to_string(),
            "HTTP request lifecycle summary".to_string(),
            "HTTP request lifecycle evidence".to_string(),
        ]
    );
    assert_eq!(
        brief.factual_anchors,
        vec![
            "HTTP request lifecycle".to_string(),
            "HTTP request lifecycle examples".to_string(),
        ]
    );
}

#[test]
fn request_grounded_html_brief_prefers_subject_from_full_prompt_over_imperative_title() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = derive_request_grounded_chat_artifact_brief(
        "Create an interactive HTML artifact that explains the HTTP req...",
        "Create an interactive HTML artifact that explains the HTTP request lifecycle.",
        &request,
        None,
    );

    assert_eq!(brief.subject_domain, "HTTP request lifecycle");
    assert_eq!(brief.job_to_be_done, "explain HTTP request lifecycle");
    assert!(brief
        .artifact_thesis
        .contains("HTTP request lifecycle through visible evidence"));
    assert_eq!(
        brief.required_concepts,
        vec![
            "HTTP request lifecycle".to_string(),
            "HTTP request lifecycle fundamentals".to_string(),
            "HTTP request lifecycle examples".to_string(),
            "HTTP request lifecycle comparisons".to_string(),
        ]
    );
}

#[test]
fn artifact_connector_grounding_enriches_brief_without_duplicate_noise() {
    let request = request_for(
        ChatArtifactClass::Document,
        ChatRendererKind::HtmlIframe,
    );
    let mut brief = derive_request_grounded_chat_artifact_brief(
        "Summarize unread emails into an HTML report",
        "Summarize unread emails into an HTML report",
        &request,
        None,
    );

    apply_artifact_connector_grounding_to_brief(
        &mut brief,
        Some(&ArtifactConnectorGrounding {
            connector_id: Some("mail.primary".to_string()),
            provider_family: Some("mail.wallet_network".to_string()),
            target_label: Some("email".to_string()),
        }),
    );
    apply_artifact_connector_grounding_to_brief(
        &mut brief,
        Some(&ArtifactConnectorGrounding {
            connector_id: Some("mail.primary".to_string()),
            provider_family: Some("mail.wallet_network".to_string()),
            target_label: Some("email".to_string()),
        }),
    );

    assert!(brief
        .factual_anchors
        .iter()
        .any(|value| value == "selected connector data is the grounding source"));
    assert_eq!(
        brief
            .reference_hints
            .iter()
            .filter(|value| value.as_str() == "selected connector id: mail.primary")
            .count(),
        1
    );
    assert!(brief
        .reference_hints
        .iter()
        .any(|value| value == "selected provider family: mail.wallet_network"));
}

#[test]
fn markdown_blueprint_uses_document_native_contracts() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let brief = derive_request_grounded_chat_artifact_brief(
        "Create a markdown brief explaining the HTTP request lifecycle in ...",
        "Create a markdown brief explaining the HTTP request lifecycle in five bullets.",
        &request,
        None,
    );
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let component_families = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.as_str())
        .collect::<Vec<_>>();

    assert!(blueprint.interaction_plan.is_empty());
    assert_eq!(blueprint.acceptance_targets.minimum_interactive_regions, 0);
    assert_eq!(blueprint.acceptance_targets.minimum_section_count, 1);
    assert!(blueprint
        .evidence_plan
        .iter()
        .any(|entry| entry.kind == "supporting_surface"));
    assert!(component_families.contains(&"document_section_stack"));
    assert!(component_families.contains(&"bullet_list"));
    assert!(!component_families.contains(&"shared_detail_panel"));
    assert!(!component_families.contains(&"labeled_svg_chart_shell"));
}

#[test]
fn markdown_render_acceptance_policy_uses_document_thresholds() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let brief = derive_request_grounded_chat_artifact_brief(
        "Create a markdown brief explaining the HTTP request lifecycle in ...",
        "Create a markdown brief explaining the HTTP request lifecycle in five bullets.",
        &request,
        None,
    );
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);
    let policy = build_chat_artifact_render_acceptance_policy(
        &request,
        &brief,
        Some(&blueprint),
        Some(&artifact_ir),
    );

    assert_eq!(policy.minimum_semantic_regions, 1);
    assert_eq!(policy.primary_view_score_threshold, 15);
}

#[test]
fn interactive_html_render_acceptance_policy_scales_actionable_threshold_with_goal_count() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let single_goal_brief = ChatArtifactBrief {
        audience: "curious learners".to_string(),
        job_to_be_done: "adjust one state".to_string(),
        subject_domain: "quantum basics".to_string(),
        artifact_thesis: "Show one adjustable qubit state.".to_string(),
        required_concepts: vec!["superposition".to_string()],
        required_interactions: vec!["state manipulation".to_string()],
        visual_tone: Vec::new(),
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: Some(ChatArtifactQueryProfile {
            content_goals: vec![required_content_goal(
                ChatArtifactContentGoalKind::Explain,
                "Explain the selected state.",
            )],
            interaction_goals: vec![required_interaction_goal(
                ChatArtifactInteractionGoalKind::StateAdjust,
                "Adjust one visible state control.",
            )],
            evidence_goals: vec![required_evidence_goal(
                ChatArtifactEvidenceGoalKind::PrimarySurface,
                "Keep the adjusted state visible.",
            )],
            presentation_constraints: vec![required_presentation_constraint(
                ChatArtifactPresentationConstraintKind::ResponseRegion,
                "Keep a response region visible.",
            )],
        }),
    };
    let single_goal_blueprint = derive_chat_artifact_blueprint(&request, &single_goal_brief);
    let single_goal_ir =
        compile_chat_artifact_ir(&request, &single_goal_brief, &single_goal_blueprint);
    let single_goal_policy = build_chat_artifact_render_acceptance_policy(
        &request,
        &single_goal_brief,
        Some(&single_goal_blueprint),
        Some(&single_goal_ir),
    );

    let multi_goal_brief = sample_quantum_explainer_brief();
    let multi_goal_blueprint = derive_chat_artifact_blueprint(&request, &multi_goal_brief);
    let multi_goal_ir =
        compile_chat_artifact_ir(&request, &multi_goal_brief, &multi_goal_blueprint);
    let multi_goal_policy = build_chat_artifact_render_acceptance_policy(
        &request,
        &multi_goal_brief,
        Some(&multi_goal_blueprint),
        Some(&multi_goal_ir),
    );

    assert_eq!(single_goal_policy.minimum_actionable_affordances, 1);
    assert_eq!(multi_goal_policy.minimum_actionable_affordances, 2);
}

#[test]
fn interactive_html_brief_validation_rejects_single_word_interactions_and_missing_evidence() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "explain the rollout".to_string(),
        subject_domain: "Instacart MCP rollout".to_string(),
        artifact_thesis: "Explain the product rollout with charts.".to_string(),
        required_concepts: vec![
            "Instacart MCP".to_string(),
            "product rollout".to_string(),
            "charts".to_string(),
        ],
        required_interactions: vec!["interactive".to_string(), "explains".to_string()],
        visual_tone: Vec::new(),
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };

    let error = validate_chat_artifact_brief_against_request(&brief, &request, None)
        .expect_err("brief should fail validation");

    assert!(error.contains("single-word labels") || error.contains("evidence anchor"));
}

#[test]
fn interactive_html_brief_validation_rejects_ungrounded_widget_metaphors() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the launch page".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "Launch an editorial AI tools page with visible evidence surfaces."
            .to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "market landscape".to_string(),
        ],
        required_interactions: vec![
            "tool comparison slider".to_string(),
            "feature demo video player".to_string(),
        ],
        visual_tone: vec!["modern".to_string()],
        factual_anchors: vec![
            "industry expert opinions on AI tool usage".to_string(),
            "current AI tools market landscape".to_string(),
        ],
        style_directives: Vec::new(),
        reference_hints: vec!["recent tech industry publications".to_string()],
        query_profile: None,
    };

    let error = validate_chat_artifact_brief_against_request(&brief, &request, None)
        .expect_err("ungrounded interaction metaphors should be rejected");
    assert!(error.contains("grounded in request concepts"));
}

#[test]
fn canonicalize_brief_for_request_rewrites_identifier_style_interactions() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "inspect the rollout evidence".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "Explain the launch through evidence-rich comparison views.".to_string(),
        required_concepts: vec![
            "product rollout".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
        ],
        required_interactions: vec![
            "filterByTimePeriod".to_string(),
            "drillDownIntoData".to_string(),
            "highlightKeyInsights".to_string(),
            "filterByTimePeriod".to_string(),
        ],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["customer feedback".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: Vec::new(),
        query_profile: None,
    };

    let brief = canonicalize_chat_artifact_brief_for_request(brief, &request);

    assert_eq!(
        brief.required_interactions,
        vec![
            "filter by time period to update the visible chart and detail panel".to_string(),
            "drill down into data to update the visible chart and detail panel".to_string(),
            "highlight key insights to update the visible chart and detail panel".to_string(),
        ]
    );
    validate_chat_artifact_brief_against_request(&brief, &request, None)
        .expect("canonicalized interactions should satisfy HTML validation");
}

#[test]
fn parse_chat_artifact_edit_intent_coerces_scalar_and_object_shapes() {
    let intent = parse_chat_artifact_edit_intent(
        r#"{
              "mode": ["patch"],
              "summary": "Patch the chart section.",
              "patchExistingArtifact": "true",
              "preserveStructure": "true",
              "targetScope": ["chart section"],
              "targetPaths": "index.html",
              "requestedOperations": "replace chart data",
              "toneDirectives": "technical",
              "selectedTargets": {
                "sourceSurface": "render",
                "path": "index.html",
                "label": "chart section",
                "snippet": "Hero chart section should show adoption by channel."
              },
              "styleDirectives": null,
              "branchRequested": "false"
            }"#,
    )
    .expect("edit-intent coercion should parse");

    assert_eq!(intent.mode, ChatArtifactEditMode::Patch);
    assert!(intent.patch_existing_artifact);
    assert!(intent.preserve_structure);
    assert_eq!(intent.target_scope, "chart section");
    assert_eq!(intent.target_paths, vec!["index.html".to_string()]);
    assert_eq!(
        intent.requested_operations,
        vec!["replace chart data".to_string()]
    );
    assert_eq!(intent.selected_targets.len(), 1);
    assert_eq!(intent.style_directives, Vec::<String>::new());
    assert!(!intent.branch_requested);
}

#[test]
fn edit_intent_prompt_requires_json_wrapper_for_refinements() {
    let prompt = build_chat_artifact_edit_intent_prompt(
        "Make it feel more enterprise",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        &ChatArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "refine the rollout artifact".to_string(),
            subject_domain: "dog shampoo launch".to_string(),
            artifact_thesis: "Show the launch plan clearly.".to_string(),
            required_concepts: vec!["enterprise".to_string()],
            required_interactions: vec!["chart toggle".to_string()],
            visual_tone: vec!["technical".to_string()],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
            query_profile: None,
        },
        &ChatArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: ChatRendererKind::HtmlIframe,
            files: vec![],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
    )
    .expect("edit-intent prompt");
    let prompt_text = serde_json::to_string(&prompt).expect("prompt text");

    assert!(prompt_text.contains("Edit-intent output contract"));
    assert!(prompt_text.contains(
        "do not answer with raw prose, bullet notes, or commentary outside the JSON object"
    ));
    assert!(prompt_text.contains("Preserve explicit user steering words"));
    assert!(prompt_text.contains("make it feel X"));
}

#[test]
fn edit_intent_prompt_compacts_large_refinement_context() {
    let large_body = format!("START\n{}\nEND", "enterprise proof rail\n".repeat(500));
    let prompt = build_chat_artifact_edit_intent_prompt(
        "Make it feel more enterprise",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        &ChatArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "refine the rollout artifact".to_string(),
            subject_domain: "dog shampoo launch".to_string(),
            artifact_thesis: "Show the launch plan clearly.".to_string(),
            required_concepts: vec!["enterprise".to_string()],
            required_interactions: vec!["chart toggle".to_string()],
            visual_tone: vec!["technical".to_string()],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
            query_profile: None,
        },
        &ChatArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: ChatRendererKind::HtmlIframe,
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: large_body,
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
    )
    .expect("edit-intent prompt");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_chat_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("\"bodyPreview\""));
    assert!(prompt_text.contains("\"bodyChars\""));
    assert!(prompt_text.contains("START"));
    assert!(prompt_text.contains("END"));
    assert!(!prompt_text.contains(&"enterprise proof rail\n".repeat(250)));
}

#[test]
fn edit_intent_repair_prompt_requires_json_wrapper_after_missing_payload() {
    let prompt = build_chat_artifact_edit_intent_repair_prompt(
        "Make it feel more enterprise",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        &ChatArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "refine the rollout artifact".to_string(),
            subject_domain: "dog shampoo launch".to_string(),
            artifact_thesis: "Show the launch plan clearly.".to_string(),
            required_concepts: vec!["enterprise".to_string()],
            required_interactions: vec!["chart toggle".to_string()],
            visual_tone: vec!["technical".to_string()],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
            query_profile: None,
        },
        &ChatArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: ChatRendererKind::HtmlIframe,
            files: vec![],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
        "Patch the chart section while preserving structure.",
        "Chat artifact edit-intent output missing JSON payload",
    )
    .expect("edit-intent repair prompt");
    let prompt_text = serde_json::to_string(&prompt).expect("prompt text");

    assert!(prompt_text.contains("Edit-intent repair contract"));
    assert!(prompt_text.contains(
        "do not answer with raw prose, bullet notes, or commentary outside the JSON object"
    ));
    assert!(prompt_text.contains("Preserve explicit user steering words"));
    assert!(prompt_text.contains("make it feel X"));
}

#[test]
fn chat_artifact_production_sources_do_not_special_case_quantum_fixture() {
    for source in [
        include_str!("../planning.rs"),
        include_str!("../generation/mod.rs"),
        include_str!("../validation.rs"),
        include_str!("../payload.rs"),
    ] {
        assert!(
            !source.contains("html-quantum-explainer-baseline"),
            "production chat source must not special-case the quantum benchmark fixture"
        );
        assert!(
            !source.contains("if_prompt_contains_quantum"),
            "production chat source must not branch on quantum lexical triggers"
        );
        assert!(
            !source.contains("quantum benchmark"),
            "production chat source must not carry benchmark-only routing prose"
        );
    }
}

#[test]
fn artifact_brief_prompt_preserves_request_specific_concepts() {
    let prompt = build_chat_artifact_brief_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        None,
    )
    .expect("brief prompt");
    let prompt_text = serde_json::to_string(&prompt).expect("prompt text");
    assert!(prompt_text.contains(
        "Preserve the concrete differentiating nouns and framing words from the request"
    ));
    assert!(prompt_text.contains("requiredConcepts must include the request-specific concepts"));
    assert!(prompt_text.contains("Renderer-aware brief guidance"));
    assert!(prompt_text.contains("Name at least two concrete on-page interaction patterns"));
    assert!(prompt_text.contains(
        "Single-word labels like \\\"interactive\\\" or \\\"explains\\\" are not sufficient interaction plans"
    ));
    assert!(prompt_text.contains("Validation contract"));
    assert!(prompt_text.contains(
        "audience, jobToBeDone, subjectDomain, and artifactThesis must be non-empty request-grounded strings"
    ));
}

#[test]
fn artifact_brief_prompt_compacts_large_refinement_context() {
    let large_body = format!("START\n{}\nEND", "enterprise proof rail\n".repeat(500));
    let prompt = build_chat_artifact_brief_prompt(
        "Dog shampoo enterprise rollout",
        "Make it feel more enterprise",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        Some(&ChatArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-7".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: ChatRendererKind::HtmlIframe,
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: large_body,
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
    )
    .expect("brief prompt");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_chat_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("\"bodyPreview\""));
    assert!(prompt_text.contains("\"bodyChars\""));
    assert!(prompt_text.contains("START"));
    assert!(prompt_text.contains("END"));
    assert!(!prompt_text.contains(&"enterprise proof rail\n".repeat(250)));
}

#[test]
fn local_html_artifact_brief_prompt_is_compact_for_runtime() {
    let remote_prompt = build_chat_artifact_brief_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        None,
    )
    .expect("remote brief prompt");
    let local_prompt = build_chat_artifact_brief_prompt_for_runtime(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        None,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
    )
    .expect("local brief prompt");

    let remote_prompt_bytes = serde_json::to_vec(&remote_prompt).expect("remote prompt bytes");
    let local_prompt_bytes = serde_json::to_vec(&local_prompt).expect("local prompt bytes");
    let local_prompt_text = decode_chat_test_prompt(&local_prompt_bytes);

    assert!(local_prompt_bytes.len() < remote_prompt_bytes.len());
    assert!(local_prompt_text.contains("Artifact request focus JSON"));
    assert!(local_prompt_text.contains(
        "requiredInteractions must include at least two concrete multi-word on-page interactions with visible response"
    ));
    assert!(local_prompt_text
        .contains("Preserve the differentiating nouns and framing words from the request"));
    assert!(local_prompt_text.contains("AI tools editorial launch page"));
    assert!(!local_prompt_text.contains("Renderer-aware brief guidance"));
    assert!(!local_prompt_text.contains("Validation contract"));
}

#[test]
fn artifact_brief_field_repair_prompt_keeps_failure_previews() {
    let prompt = build_chat_artifact_brief_field_repair_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        None,
        "{\"audience\":\"\"}",
        "{\"subjectDomain\":\"\"}",
        "Chat artifact brief fields must not be empty.",
    )
    .expect("field repair prompt");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_chat_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("Planner output preview"));
    assert!(prompt_text.contains("Repair output preview"));
    assert!(prompt_text.contains("Chat artifact brief fields must not be empty."));
}

#[test]
fn jsx_materialization_prompt_uses_jsx_scaffold_contract_labels_and_hooks() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::JsxSandbox,
    );
    let brief = ChatArtifactBrief {
        audience: "Revenue operations lead".to_string(),
        job_to_be_done: "Compare pricing tiers and inspect cost deltas.".to_string(),
        subject_domain: "Pricing configurator".to_string(),
        artifact_thesis: "Show how plan changes alter pricing and feature access.".to_string(),
        required_concepts: vec![
            "pricing tiers".to_string(),
            "feature deltas".to_string(),
            "stateful comparison".to_string(),
        ],
        required_interactions: vec![
            "switch plans and update visible pricing".to_string(),
            "inspect a detail tray for the active tier".to_string(),
        ],
        visual_tone: vec!["editorial".to_string(), "calm".to_string()],
        factual_anchors: vec!["Starter $29".to_string(), "Scale $99".to_string()],
        style_directives: vec!["dense controls".to_string()],
        reference_hints: vec!["pricing grid".to_string()],
        query_profile: None,
    };

    let prompt = build_chat_artifact_materialization_prompt(
        "Pricing configurator",
        "Create a JSX artifact for a pricing configurator",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        4,
    )
    .expect("jsx materializer prompt");
    let prompt_text = serde_json::to_string(&prompt).expect("jsx prompt text");

    assert!(prompt_text.contains("Chat JSX design skill spine"));
    assert!(prompt_text.contains("Chat JSX scaffold contract"));
    assert!(prompt_text.contains("Chat JSX component pack contracts"));
    assert!(prompt_text.contains("useState"));
    assert!(prompt_text.contains("default export"));
    assert!(!prompt_text.contains("Chat HTML scaffold contract"));
}

#[test]
fn svg_materialization_prompt_uses_svg_scaffold_contract_labels() {
    let request = request_for(ChatArtifactClass::Visual, ChatRendererKind::Svg);
    let brief = ChatArtifactBrief {
        audience: "Brand stakeholders".to_string(),
        job_to_be_done: "Assess a bold vector concept.".to_string(),
        subject_domain: "AI tools brand system".to_string(),
        artifact_thesis: "Create a layered SVG concept that feels editorial and technical."
            .to_string(),
        required_concepts: vec![
            "brand signal".to_string(),
            "innovation".to_string(),
            "supporting labels".to_string(),
        ],
        required_interactions: Vec::new(),
        visual_tone: vec!["poster".to_string(), "technical".to_string()],
        factual_anchors: vec!["automation".to_string(), "operators".to_string()],
        style_directives: vec!["strong hierarchy".to_string()],
        reference_hints: vec!["diagram poster".to_string()],
        query_profile: None,
    };

    let prompt = build_chat_artifact_materialization_prompt(
        "SVG concept",
        "Create an SVG hero concept for an AI tools brand",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        3,
    )
    .expect("svg materializer prompt");
    let prompt_text = serde_json::to_string(&prompt).expect("svg prompt text");

    assert!(prompt_text.contains("Chat SVG design skill spine"));
    assert!(prompt_text.contains("Chat SVG scaffold contract"));
    assert!(prompt_text.contains("Chat SVG component pack contracts"));
    assert!(prompt_text.contains("stable viewBox"));
    assert!(!prompt_text.contains("Chat renderer scaffold contract"));
}

#[test]
fn pdf_materialization_prompt_uses_pdf_scaffold_contract_labels() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::PdfEmbed);
    let brief = ChatArtifactBrief {
        audience: "Launch stakeholders".to_string(),
        job_to_be_done: "Review a concise briefing artifact.".to_string(),
        subject_domain: "Launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a compact exported document.".to_string(),
        required_concepts: vec![
            "milestones".to_string(),
            "risks".to_string(),
            "ownership".to_string(),
        ],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: vec!["launch window".to_string(), "owner matrix".to_string()],
        style_directives: vec!["compact tables".to_string()],
        reference_hints: vec!["briefing note".to_string()],
        query_profile: None,
    };

    let prompt = build_chat_artifact_materialization_prompt(
        "Launch brief PDF",
        "Create a PDF artifact that summarizes a launch brief",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        9,
    )
    .expect("pdf materializer prompt");
    let prompt_text = serde_json::to_string(&prompt).expect("pdf prompt text");

    assert!(prompt_text.contains("Chat PDF design skill spine"));
    assert!(prompt_text.contains("Chat PDF scaffold contract"));
    assert!(prompt_text.contains("Chat PDF component pack contracts"));
    assert!(prompt_text.contains("compact briefing PDF"));
    assert!(!prompt_text.contains("Chat renderer scaffold contract"));
}

#[test]
fn materialization_repair_prompt_preserves_candidate_metadata_and_view() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "consumers interested in pet care products".to_string(),
        job_to_be_done:
            "understand the benefits and performance metrics of a new dog shampoo product rollout"
                .to_string(),
        subject_domain: "dog grooming and hygiene".to_string(),
        artifact_thesis:
            "Explain the key features and benefits of a new dog shampoo through interactive charts and data visualizations."
                .to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
        ],
        required_interactions: vec![
            "rollover effects for chart elements".to_string(),
            "clickable navigation between different types of charts".to_string(),
        ],
        visual_tone: vec!["informative".to_string()],
        factual_anchors: vec!["customer feedback".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["ingredient breakdowns".to_string()],
    query_profile: None,
};
    let raw_output = serde_json::json!({
        "summary": "Dog shampoo rollout evidence",
        "notes": ["candidate near miss"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect the evidence.</p><button type=\"button\" data-view=\"satisfaction\">Satisfaction</button><button type=\"button\" data-view=\"usage\">Usage</button></section><section data-view-panel=\"satisfaction\"><article><h2>Customer satisfaction</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo satisfaction\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\" data-detail=\"Retail satisfaction lift\" tabindex=\"0\"></rect><text x=\"20\" y=\"114\">Retail</text></svg></article></section><section data-view-panel=\"usage\" hidden><article><h2>Usage statistics</h2><p>Usage detail stays visible here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Retail satisfaction lift is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let repair_prompt = build_chat_artifact_materialization_repair_prompt(
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request,
        &brief,
        None,
        None,
        "candidate-2",
        99,
        &raw_output,
        "HTML iframe briefs that call for rollover detail must wire hover or focus handlers on visible marks to update shared detail on first paint.",
    )
    .expect("repair prompt");
    let repair_text = serde_json::to_string(&repair_prompt).expect("repair prompt text");
    assert!(repair_text.contains("candidateId"));
    assert!(repair_text.contains("candidate-2"));
    assert!(repair_text.contains("candidateSeed"));
    assert!(repair_text.contains("99"));
    assert!(repair_text.contains("Previous candidate view JSON"));
    assert!(repair_text.contains("bodyPreview"));
    assert!(repair_text.contains("patch it instead of restarting"));
    assert!(repair_text.contains("customer feedback"));
}
