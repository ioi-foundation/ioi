use super::generation::refine_studio_artifact_candidate_with_runtime;
use super::judging::candidate_generation_config;
use super::planning::{
    canonicalize_studio_artifact_brief_for_request, validate_studio_artifact_brief_against_request,
};
use super::*;
use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioArtifactDeliverableShape, StudioArtifactPersistenceMode, StudioExecutionSubstrate,
    StudioOutcomeArtifactScope, StudioOutcomeArtifactVerificationRequest,
    StudioPresentationSurface, StudioRuntimeProvenance, StudioRuntimeProvenanceKind,
};
use ioi_types::error::VmError;
use std::path::Path;
use std::sync::{Arc, Mutex};

fn decode_studio_test_prompt(input_context: &[u8]) -> String {
    let raw_prompt = String::from_utf8_lossy(input_context);
    serde_json::from_slice::<Vec<serde_json::Value>>(input_context)
        .ok()
        .map(|messages| {
            messages
                .into_iter()
                .filter_map(|message| {
                    message
                        .get("content")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .filter(|decoded| !decoded.is_empty())
        .unwrap_or_else(|| raw_prompt.to_string())
}

fn request_for(
    artifact_class: StudioArtifactClass,
    renderer: StudioRendererKind,
) -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class,
        deliverable_shape: if renderer == StudioRendererKind::WorkspaceSurface {
            StudioArtifactDeliverableShape::WorkspaceProject
        } else if renderer == StudioRendererKind::BundleManifest {
            StudioArtifactDeliverableShape::FileSet
        } else {
            StudioArtifactDeliverableShape::SingleFile
        },
        renderer,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: if renderer == StudioRendererKind::WorkspaceSurface {
            StudioArtifactPersistenceMode::WorkspaceFilesystem
        } else {
            StudioArtifactPersistenceMode::ArtifactScoped
        },
        execution_substrate: match renderer {
            StudioRendererKind::WorkspaceSurface => StudioExecutionSubstrate::WorkspaceRuntime,
            StudioRendererKind::PdfEmbed => StudioExecutionSubstrate::BinaryGenerator,
            StudioRendererKind::JsxSandbox
            | StudioRendererKind::HtmlIframe
            | StudioRendererKind::Svg
            | StudioRendererKind::Mermaid => StudioExecutionSubstrate::ClientSandbox,
            _ => StudioExecutionSubstrate::None,
        },
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: renderer == StudioRendererKind::WorkspaceSurface,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: renderer == StudioRendererKind::WorkspaceSurface,
            require_preview: renderer == StudioRendererKind::WorkspaceSurface,
            require_export: true,
            require_diff_review: false,
        },
    }
}

fn sample_html_brief() -> StudioArtifactBrief {
    StudioArtifactBrief {
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
            "view switching".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["customer feedback".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["ingredient analysis".to_string()],
    }
}

fn sample_quantum_explainer_brief() -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "curious learners".to_string(),
        job_to_be_done:
            "understand quantum computing concepts through interactive demonstrations"
                .to_string(),
        subject_domain: "quantum computing fundamentals".to_string(),
        artifact_thesis:
            "Explain superposition, entanglement, and gate transforms through visible state changes."
                .to_string(),
        required_concepts: vec![
            "superposition".to_string(),
            "entanglement".to_string(),
            "measurement probabilities".to_string(),
            "gate transforms".to_string(),
        ],
        required_interactions: vec![
            "state manipulation".to_string(),
            "detail inspection".to_string(),
            "sequence browsing".to_string(),
        ],
        visual_tone: vec!["editorial".to_string(), "technical".to_string()],
        factual_anchors: vec![
            "qubit state examples".to_string(),
            "measurement outcomes".to_string(),
        ],
        style_directives: vec![
            "clear hierarchy".to_string(),
            "strong visual labeling".to_string(),
        ],
        reference_hints: vec![
            "state diagrams".to_string(),
            "distribution comparisons".to_string(),
        ],
    }
}

fn studio_test_judge(
    classification: StudioArtifactJudgeClassification,
    deserves_primary_artifact_view: bool,
    request_faithfulness: u8,
    concept_coverage: u8,
    interaction_relevance: u8,
    layout_coherence: u8,
    visual_hierarchy: u8,
    completeness: u8,
) -> StudioArtifactJudgeResult {
    StudioArtifactJudgeResult {
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
        rationale: "Test rationale".to_string(),
    }
}

fn studio_test_candidate_summary(
    candidate_id: &str,
    judge: StudioArtifactJudgeResult,
) -> StudioArtifactCandidateSummary {
    StudioArtifactCandidateSummary {
        candidate_id: candidate_id.to_string(),
        seed: 1,
        model: "test-model".to_string(),
        temperature: 0.2,
        strategy: "test".to_string(),
        origin: StudioArtifactOutputOrigin::MockInference,
        provenance: Some(StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::MockRuntime,
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
        judge,
    }
}

fn studio_test_render_capture(
    viewport: StudioArtifactRenderCaptureViewport,
    visible_element_count: usize,
    visible_text_chars: usize,
    interactive_element_count: usize,
) -> StudioArtifactRenderCapture {
    StudioArtifactRenderCapture {
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

fn studio_test_render_evaluation(
    overall_score: u8,
    first_paint_captured: bool,
    findings: Vec<StudioArtifactRenderFinding>,
    captures: Vec<StudioArtifactRenderCapture>,
) -> StudioArtifactRenderEvaluation {
    StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured,
        interaction_capture_attempted: captures
            .iter()
            .any(|capture| capture.viewport == StudioArtifactRenderCaptureViewport::Interaction),
        captures,
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 4,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 4,
        overall_score,
        findings,
        summary: "Render evaluation completed.".to_string(),
    }
}

#[test]
fn derived_blueprint_for_html_brief_emits_structure_and_skill_needs() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let blueprint = derive_studio_artifact_blueprint(&request, &sample_html_brief());

    assert_eq!(blueprint.renderer, StudioRendererKind::HtmlIframe);
    assert_eq!(blueprint.scaffold_family, "comparison_story");
    assert!(blueprint.section_plan.len() >= 4);
    assert!(blueprint
        .interaction_plan
        .iter()
        .any(|interaction| interaction.family == "view_switching"));
    assert!(blueprint
        .skill_needs
        .iter()
        .any(|need| need.kind == StudioArtifactSkillNeedKind::VisualArtDirection));
    assert!(blueprint
        .skill_needs
        .iter()
        .any(|need| need.kind == StudioArtifactSkillNeedKind::AccessibilityReview));
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
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);

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
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let judge = studio_test_judge(
        StudioArtifactJudgeClassification::Pass,
        true,
        5,
        5,
        5,
        5,
        5,
        5,
    );
    let render_evaluation = studio_test_render_evaluation(
        8,
        false,
        vec![StudioArtifactRenderFinding {
            code: "first_paint_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: "First paint never stabilized.".to_string(),
        }],
        vec![studio_test_render_capture(
            StudioArtifactRenderCaptureViewport::Desktop,
            0,
            0,
            0,
        )],
    );

    let merged = merge_studio_artifact_render_evaluation_into_judge(
        &request,
        judge,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        StudioArtifactJudgeClassification::Blocked
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
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let judge = studio_test_judge(
        StudioArtifactJudgeClassification::Pass,
        true,
        4,
        4,
        4,
        4,
        4,
        4,
    );
    let render_evaluation = studio_test_render_evaluation(
        22,
        true,
        Vec::new(),
        vec![
            studio_test_render_capture(StudioArtifactRenderCaptureViewport::Desktop, 48, 420, 6),
            studio_test_render_capture(StudioArtifactRenderCaptureViewport::Mobile, 46, 405, 6),
        ],
    );

    let merged = merge_studio_artifact_render_evaluation_into_judge(
        &request,
        judge,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert!(merged.deserves_primary_artifact_view);
    assert!(merged
        .strengths
        .iter()
        .any(|value| value.contains("Desktop and mobile render captures")));
    assert!(merged.rationale.contains("Render evaluation"));
}

#[test]
fn exemplar_query_prefers_structural_grounding_over_text_copy() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let taste_memory = StudioArtifactTasteMemory {
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
        build_studio_artifact_exemplar_query(&brief, &blueprint, &artifact_ir, Some(&taste_memory));

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
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let selected_skills = vec![StudioArtifactSelectedSkill {
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
        matched_need_kinds: vec![StudioArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched the scaffold's visual art direction need.".to_string(),
        guidance_markdown: Some("Prefer editorial hierarchy.".to_string()),
    }];

    let design_spine =
        studio_html_promoted_design_skill_spine(&brief, &blueprint, &artifact_ir, &selected_skills)
            .expect("html design spine");
    let scaffold =
        studio_html_scaffold_contract(&blueprint, &artifact_ir, 7).expect("html scaffold");
    let component_packs = studio_html_component_pack_contracts(&blueprint);
    let digest = studio_html_scaffold_execution_digest(
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
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::JsxSandbox,
    );
    let brief = sample_html_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let selected_skills = vec![StudioArtifactSelectedSkill {
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
        matched_need_kinds: vec![StudioArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched the scaffold's visual art direction need.".to_string(),
        guidance_markdown: Some("Prefer editorial hierarchy.".to_string()),
    }];

    let design_spine =
        studio_jsx_promoted_design_skill_spine(&brief, &blueprint, &artifact_ir, &selected_skills)
            .expect("jsx design spine");
    let scaffold = studio_jsx_scaffold_contract(&blueprint, &artifact_ir, 7).expect("jsx scaffold");
    let component_packs = studio_jsx_component_pack_contracts(&blueprint);
    let digest =
        studio_jsx_scaffold_execution_digest(&brief, &blueprint, &artifact_ir, &selected_skills, 7)
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
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
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
fn parses_planning_payload_with_wrapped_text() {
    let parsed = parse_studio_outcome_planning_payload(
            "router output\n{\"outcomeKind\":\"conversation\",\"confidence\":0.6,\"needsClarification\":false,\"clarificationQuestions\":[],\"artifact\":null}",
        )
        .expect("planning payload");
    assert_eq!(
        parsed.outcome_kind,
        ioi_types::app::StudioOutcomeKind::Conversation
    );
}

#[test]
fn parses_planning_payload_with_missing_scope_and_verification_defaults() {
    let parsed = parse_studio_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "artifactClass": "document",
                "deliverableShape": "single_file",
                "renderer": "markdown",
                "presentationSurface": "side_panel",
                "persistence": "artifact_scoped",
                "executionSubstrate": "none",
                "workspaceRecipeId": null,
                "presentationVariantId": null
            }
        }"#,
    )
    .expect("planning payload should recover missing scope and verification");

    let artifact = parsed.artifact.expect("artifact payload");
    assert_eq!(artifact.renderer, StudioRendererKind::Markdown);
    assert_eq!(artifact.scope.target_project, None);
    assert!(!artifact.scope.create_new_workspace);
    assert!(artifact.scope.mutation_boundary.is_empty());
    assert!(!artifact.verification.require_render);
    assert!(!artifact.verification.require_build);
    assert!(!artifact.verification.require_preview);
    assert!(!artifact.verification.require_export);
    assert!(!artifact.verification.require_diff_review);
}

#[test]
fn parse_studio_artifact_brief_coerces_scalar_and_array_shapes() {
    let brief = parse_studio_artifact_brief(
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
fn interactive_html_brief_validation_rejects_single_word_interactions_and_missing_evidence() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
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
    };

    let error = validate_studio_artifact_brief_against_request(&brief, &request, None)
        .expect_err("brief should fail validation");

    assert!(error.contains("single-word labels") || error.contains("evidence anchor"));
}

#[test]
fn interactive_html_brief_validation_rejects_ungrounded_widget_metaphors() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
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
    };

    let error = validate_studio_artifact_brief_against_request(&brief, &request, None)
        .expect_err("ungrounded interaction metaphors should be rejected");
    assert!(error.contains("grounded in request concepts"));
}

#[test]
fn interactive_html_brief_validation_allows_follow_up_interactions_grounded_in_refinement() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "branch the current launch story".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "Reframe the current launch artifact with a sharper editorial tone."
            .to_string(),
        required_concepts: vec![
            "product launch".to_string(),
            "editorial story".to_string(),
            "sales figures".to_string(),
        ],
        required_interactions: vec![
            "dynamic panel switching".to_string(),
            "interactive chart exploration".to_string(),
        ],
        visual_tone: vec!["sharp".to_string()],
        factual_anchors: vec!["Q1 sales figures for dog shampoos".to_string()],
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };
    let refinement = StudioArtifactRefinementContext {
        artifact_id: Some("artifact-1".to_string()),
        revision_id: Some("revision-1".to_string()),
        title: "Dog shampoo rollout".to_string(),
        summary: "Current artifact compares channels and charts launch evidence.".to_string(),
        renderer: StudioRendererKind::HtmlIframe,
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: None,
            body: "<!doctype html><main><section><button type=\"button\">Compare chart view</button><article>Chart exploration stays visible.</article></section></main>".to_string(),
        }],
        selected_targets: vec![StudioArtifactSelectionTarget {
            source_surface: "render".to_string(),
            path: Some("index.html".to_string()),
            label: "Chart section".to_string(),
            snippet: "Interactive chart exploration".to_string(),
        }],
        taste_memory: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
    };

    validate_studio_artifact_brief_against_request(&brief, &request, Some(&refinement))
        .expect("follow-up refinement grounding should allow current artifact interactions");
}

#[test]
fn canonicalize_brief_for_request_rewrites_identifier_style_interactions() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
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
    };

    let brief = canonicalize_studio_artifact_brief_for_request(brief, &request);

    assert_eq!(
        brief.required_interactions,
        vec![
            "filter by time period to update the visible chart and detail panel".to_string(),
            "drill down into data to update the visible chart and detail panel".to_string(),
            "highlight key insights to update the visible chart and detail panel".to_string(),
        ]
    );
    validate_studio_artifact_brief_against_request(&brief, &request, None)
        .expect("canonicalized interactions should satisfy HTML validation");
}

#[test]
fn parse_studio_artifact_edit_intent_coerces_scalar_and_object_shapes() {
    let intent = parse_studio_artifact_edit_intent(
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

    assert_eq!(intent.mode, StudioArtifactEditMode::Patch);
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
    let prompt = build_studio_artifact_edit_intent_prompt(
        "Make it feel more enterprise",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
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
        },
        &StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
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
    let prompt = build_studio_artifact_edit_intent_prompt(
        "Make it feel more enterprise",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
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
        },
        &StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
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
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("\"bodyPreview\""));
    assert!(prompt_text.contains("\"bodyChars\""));
    assert!(prompt_text.contains("START"));
    assert!(prompt_text.contains("END"));
    assert!(!prompt_text.contains(&"enterprise proof rail\n".repeat(250)));
}

#[test]
fn edit_intent_repair_prompt_requires_json_wrapper_after_missing_payload() {
    let prompt = build_studio_artifact_edit_intent_repair_prompt(
        "Make it feel more enterprise",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
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
        },
        &StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
        "Patch the chart section while preserving structure.",
        "Studio artifact edit-intent output missing JSON payload",
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
fn outcome_router_prompt_spells_out_html_vs_jsx_contracts() {
    let prompt = build_studio_outcome_router_prompt(
        "Create an interactive HTML artifact that explains a product rollout with charts",
        None,
        None,
    );
    let prompt_text = serde_json::to_string(&prompt).expect("prompt text");
    assert!(prompt_text.contains("html_iframe = a single self-contained .html document"));
    assert!(prompt_text.contains("jsx_sandbox = a single .jsx source module with a default export"));
    assert!(prompt_text.contains(
        "Non-workspace artifact renderers should not request build or preview verification."
    ));
    assert!(prompt_text.contains(
        "Treat explicit medium-plus-deliverable requests as sufficiently specified artifact work."
    ));
    assert!(prompt_text
        .contains("Create an interactive HTML artifact for an AI tools editorial launch page"));
    assert!(prompt_text.contains("Do not use lexical fallbacks or benchmark phrase maps."));
}

#[test]
fn studio_artifact_production_sources_do_not_special_case_quantum_fixture() {
    for source in [
        include_str!("planning.rs"),
        include_str!("generation.rs"),
        include_str!("judging.rs"),
        include_str!("payload.rs"),
    ] {
        assert!(
            !source.contains("html-quantum-explainer-baseline"),
            "production studio source must not special-case the quantum benchmark fixture"
        );
        assert!(
            !source.contains("if_prompt_contains_quantum"),
            "production studio source must not branch on quantum lexical triggers"
        );
        assert!(
            !source.contains("quantum benchmark"),
            "production studio source must not carry benchmark-only routing prose"
        );
    }
}

#[test]
fn studio_artifact_corpus_summary_tracks_quantum_baseline_fixture() {
    let corpus_summary_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/evidence/studio-artifact-surface/corpus-summary.json");
    let raw = std::fs::read_to_string(&corpus_summary_path)
        .expect("generated artifact corpus summary should exist");
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).expect("artifact corpus summary should be valid JSON");
    let cases = parsed["cases"]
        .as_array()
        .expect("artifact corpus summary should contain a cases array");
    let quantum_case = cases
        .iter()
        .find(|entry| entry["id"] == "html-quantum-explainer-baseline")
        .expect("artifact corpus summary should include the quantum baseline fixture");

    assert_eq!(quantum_case["lane"], "fixture-lane");
    assert_eq!(quantum_case["renderer"], "html_iframe");
    assert_eq!(quantum_case["effectiveClassification"], "repairable");
    assert_eq!(quantum_case["shimDependent"], true);
}

#[test]
fn outcome_router_prompt_surfaces_active_artifact_context_for_follow_ups() {
    let prompt = build_studio_outcome_router_prompt(
        "Make it feel more enterprise",
        Some("artifact-1"),
        Some(&StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-2".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Interactive rollout artifact".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>".to_string(),
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
    );
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("Active artifact context JSON"));
    assert!(prompt_text.contains("\"renderer\":\"html_iframe\""));
    assert!(prompt_text.contains("patch or branch the current artifact by default"));
    assert!(prompt_text.contains("continue the active artifact"));
}

#[test]
fn artifact_brief_prompt_preserves_request_specific_concepts() {
    let prompt = build_studio_artifact_brief_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
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
    let prompt = build_studio_artifact_brief_prompt(
        "Dog shampoo enterprise rollout",
        "Make it feel more enterprise",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        Some(&StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-7".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
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
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("\"bodyPreview\""));
    assert!(prompt_text.contains("\"bodyChars\""));
    assert!(prompt_text.contains("START"));
    assert!(prompt_text.contains("END"));
    assert!(!prompt_text.contains(&"enterprise proof rail\n".repeat(250)));
}

#[test]
fn artifact_materializer_and_judge_prompts_penalize_generic_placeholder_outputs() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "launch an editorial page".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "Launch an editorial page for AI tools".to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial".to_string(),
            "launch".to_string(),
        ],
        required_interactions: vec!["scroll".to_string()],
        visual_tone: vec!["modern".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };
    let candidate = StudioGeneratedArtifactPayload {
        summary: "candidate".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><h1>AI tools</h1></body></html>".to_string(),
        }],
    };

    let materializer_prompt = build_studio_artifact_materialization_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        1,
    )
    .expect("materializer prompt");
    let materializer_text =
        serde_json::to_string(&materializer_prompt).expect("materializer prompt text");
    assert!(materializer_text.contains("Do not use placeholder image URLs"));
    assert!(materializer_text.contains("could fit many unrelated prompts"));
    assert!(materializer_text.contains("must use semantic HTML structure"));
    assert!(materializer_text.contains("must not use alert()"));
    assert!(materializer_text.contains("must not invent custom element tags"));
    assert!(materializer_text.contains("candidate seed to vary composition"));
    assert!(materializer_text.contains("abstract geometry alone does not count"));
    assert!(materializer_text.contains("shared detail, comparison, or explanation region"));
    assert!(materializer_text.contains("must not include placeholder comments"));
    assert!(materializer_text.contains("Do not use fragment-jump anchors"));
    assert!(materializer_text.contains("references to DOM ids"));
    assert!(materializer_text.contains("one chart plus generic prose is insufficient"));
    assert!(materializer_text.contains("single sentence paragraph"));
    assert!(materializer_text.contains("querySelectorAll or an equivalent collection"));
    assert!(materializer_text.contains("artifactThesis verbatim"));
    assert!(materializer_text.contains("control-to-panel mappings"));
    assert!(materializer_text.contains("Do not synthesize target ids"));
    assert!(materializer_text.contains("script after the closing </main>"));
    assert!(materializer_text.contains("panel.dataset.viewPanel !== button.dataset.view"));
    assert!(materializer_text.contains("Ground this candidate in a concrete evidence plan"));
    assert!(materializer_text.contains("AI tools"));
    assert!(materializer_text.contains("editorial"));
    assert!(materializer_text.contains("launch"));
    assert!(!materializer_text.contains("ingredients-panel"));
    assert!(!materializer_text.contains("Retail satisfaction lift"));
    assert!(
        materializer_text.contains("metric-card rail")
            || materializer_text.contains("comparison article")
            || materializer_text.contains("score table or evidence list")
    );

    let judge_prompt = build_studio_artifact_judge_prompt(
        "AI tools editorial launch page",
        &request,
        &brief,
        None,
        &candidate,
    )
    .expect("judge prompt");
    let judge_text = serde_json::to_string(&judge_prompt).expect("judge prompt text");
    assert!(judge_text.contains("requestFaithfulness and conceptCoverage must drop sharply"));
    assert!(judge_text.contains("Placeholder image URLs"));
    assert!(judge_text.contains("could fit many nearby prompts"));
    assert!(judge_text.contains("thin div shell"));
    assert!(judge_text.contains("invented custom tags"));
    assert!(judge_text.contains("single chart plus generic prose is insufficient"));
    assert!(judge_text.contains("collection-style iteration on a single selected element"));
    assert!(judge_text.contains("\"issueClasses\": [<string>]"));
    assert!(judge_text.contains("\"repairHints\": [<string>]"));
    assert!(judge_text.contains("\"strengths\": [<string>]"));
    assert!(judge_text.contains("\"blockedReasons\": [<string>]"));
    assert!(judge_text.contains("\"fileFindings\": [<string>]"));
    assert!(judge_text.contains("\"aestheticVerdict\": <string>"));
    assert!(judge_text.contains("\"interactionVerdict\": <string>"));
    assert!(judge_text.contains("\"truthfulnessWarnings\": [<string>]"));
    assert!(judge_text.contains("\"recommendedNextPass\": null | \"accept\""));
    assert!(judge_text.contains("first-paint evidence density"));
    assert!(judge_text.contains("design intentionality"));
}

#[test]
fn html_chart_prompts_require_multi_view_request_specific_repairs() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
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
            "product rollout".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
            "ingredient analysis".to_string(),
        ],
        required_interactions: vec![
            "rollover effects for chart elements".to_string(),
            "clickable navigation between different types of charts".to_string(),
        ],
        visual_tone: vec![
            "informative".to_string(),
            "professional".to_string(),
            "user-friendly".to_string(),
        ],
        factual_anchors: vec![
            "clinical trials data".to_string(),
            "customer feedback".to_string(),
            "sales performance metrics".to_string(),
        ],
        style_directives: vec![
            "clear and concise language".to_string(),
            "use of color to highlight key points".to_string(),
            "interactive elements should be intuitive".to_string(),
        ],
        reference_hints: vec![
            "charts showing pH levels, ingredient breakdowns, before-and-after condition comparisons"
                .to_string(),
        ],
    };
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Interactive HTML artifact explaining a new dog shampoo product rollout.".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "dog-shampoo-rollout.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect the launch evidence.</p><button type=\"button\" data-view=\"ph\">pH</button><button type=\"button\" data-view=\"ingredients\">Ingredients</button></section><section><article><h2>Launch chart</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo launch chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Retail</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">pH is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=`${button.dataset.view} selected.`;}));</script></main></body></html>".to_string(),
        }],
    };

    let materializer_prompt = build_studio_artifact_materialization_prompt(
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        7,
    )
    .expect("materializer prompt");
    let materializer_text =
        serde_json::to_string(&materializer_prompt).expect("materializer prompt text");
    assert!(materializer_text.contains("two distinct evidence views or chart families"));
    assert!(materializer_text.contains("One chart plus generic prose is insufficient"));
    assert!(materializer_text.contains("bare paragraph"));
    assert!(materializer_text.contains("querySelectorAll"));
    assert!(materializer_text
        .contains("Turn factualAnchors and referenceHints into visible annotations"));
    assert!(materializer_text
        .contains("When the brief combines clickable view switching with rollover detail"));
    assert!(materializer_text.contains("querySelectorAll('[data-view-panel]')"));
    assert!(materializer_text.contains("preserve both interaction families"));
    assert!(materializer_text.contains("tabindex=\\\"0\\\""));
    assert!(materializer_text.contains("Do not point every button only at the shared detail panel"));
    assert!(materializer_text.contains("data-view-panel=\\\"customer-feedback\\\""));
    assert!(materializer_text.contains("class=\\\"data-view-panel\\\" does not satisfy"));
    assert!(materializer_text.contains("id=\\\"customer-feedback-panel\\\""));
    assert!(materializer_text.contains("sales-performance-metrics-panel"));
    assert!(materializer_text.contains("target the enclosing section/article/div panel"));
    assert!(materializer_text.contains("Keep exactly one mapped panel visible in the raw markup"));
    assert!(materializer_text.contains("customer feedback"));
    assert!(materializer_text
        .contains("Empty mount divs like <div id=\\\"usage-chart\\\"></div> do not count"));
    assert!(materializer_text.contains("Artifact blueprint JSON"));
    assert!(materializer_text.contains("Artifact IR JSON"));
    assert!(materializer_text.contains("Selected skill guidance JSON"));
    assert!(materializer_text.contains("Promoted design skill spine JSON"));
    assert!(materializer_text.contains("HTML scaffold contract JSON"));
    assert!(materializer_text.contains("Component pack contract JSON"));
    assert!(materializer_text.contains("Scaffold execution digest"));

    let refinement_materializer_prompt = build_studio_artifact_materialization_prompt(
        "Dog shampoo rollout",
        "Make it feel more enterprise",
        &request,
        &brief,
        None,
        Some(&StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact summary".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: candidate.files.clone(),
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
        "candidate-1",
        7,
    )
    .expect("refinement materializer prompt");
    let refinement_materializer_text = serde_json::to_string(&refinement_materializer_prompt)
        .expect("refinement materializer prompt text");
    assert!(refinement_materializer_text.contains("Artifact blueprint JSON"));
    assert!(refinement_materializer_text.contains("Artifact IR JSON"));
    assert!(refinement_materializer_text.contains("Selected skill guidance JSON"));
    assert!(refinement_materializer_text.contains("Promoted design skill spine JSON"));
    assert!(refinement_materializer_text.contains("HTML scaffold contract JSON"));
    assert!(refinement_materializer_text.contains("Component pack contract JSON"));
    assert!(refinement_materializer_text.contains("Refinement output contract"));
    assert!(refinement_materializer_text.contains(
        "do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object"
    ));

    let refinement_prompt = build_studio_artifact_candidate_refinement_prompt(
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request,
        &brief,
        None,
        None,
        &candidate,
        &StudioArtifactJudgeResult {
            classification: StudioArtifactJudgeClassification::Repairable,
            request_faithfulness: 3,
            concept_coverage: 2,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 3,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: vec!["evidence_density".to_string()],
            repair_hints: vec![
                "Add a denser secondary evidence surface and stronger interactive chart behavior."
                    .to_string(),
            ],
            strengths: vec!["Covers the main rollout frame.".to_string()],
            blocked_reasons: Vec::new(),
            file_findings: vec!["index.html: secondary chart family is missing.".to_string()],
            aesthetic_verdict: "Hierarchy is solid but the evidence density still feels thin."
                .to_string(),
            interaction_verdict:
                "Interaction behavior exists, but it does not yet satisfy the requested chart work."
                    .to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some("structural_repair".to_string()),
            strongest_contradiction: Some(
                "Missing interactive charts and data visualizations.".to_string(),
            ),
            rationale: "Candidate needs denser request-specific evidence.".to_string(),
        },
        "candidate-1-refine-1",
        7,
    )
    .expect("refinement prompt");
    let refinement_text =
        serde_json::to_string(&refinement_prompt).expect("refinement prompt text");
    assert!(refinement_text.contains("Artifact blueprint JSON"));
    assert!(refinement_text.contains("Artifact IR JSON"));
    assert!(refinement_text.contains("Selected skill guidance JSON"));
    assert!(refinement_text.contains("Promoted design skill spine JSON"));
    assert!(refinement_text.contains("HTML scaffold contract JSON"));
    assert!(refinement_text.contains("Component pack contract JSON"));
    assert!(refinement_text.contains("two distinct evidence views or chart families"));
    assert!(refinement_text.contains("single chart with generic prose"));
    assert!(refinement_text.contains("querySelectorAll"));
    assert!(refinement_text.contains("secondary evidence view visible"));
    assert!(refinement_text.contains("Keep both interaction families simultaneously"));
    assert!(
        refinement_text.contains("Do not satisfy clickable navigation by deleting rollover detail")
    );
    assert!(refinement_text
        .contains("buttons[data-view] -> [data-view-panel] plus [data-detail] -> #detail-copy"));
    assert!(refinement_text.contains("class=\\\"data-view-panel\\\" does not count"));
    assert!(refinement_text.contains("target the enclosing section/article/div panel"));
    assert!(refinement_text.contains("Keep exactly one mapped panel visible in the raw markup"));
    assert!(refinement_text.contains("does not replace them"));
    assert!(refinement_text.contains("single-mark or unlabeled SVG shells"));
    assert!(refinement_text.contains("do not only echo the raw view id or button label"));
    assert!(refinement_text.contains("wrap querySelectorAll results with Array.from first"));
    assert!(refinement_text.contains("selected metric, milestone, or evidence sentence"));
    assert!(refinement_text.contains("Refinement output contract"));
    assert!(refinement_text.contains(
        "do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object"
    ));
}

#[test]
fn jsx_materialization_prompt_uses_jsx_scaffold_contract_labels_and_hooks() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::JsxSandbox,
    );
    let brief = StudioArtifactBrief {
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
    };

    let prompt = build_studio_artifact_materialization_prompt(
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

    assert!(prompt_text.contains("Studio JSX design skill spine"));
    assert!(prompt_text.contains("Studio JSX scaffold contract"));
    assert!(prompt_text.contains("Studio JSX component pack contracts"));
    assert!(prompt_text.contains("useState"));
    assert!(prompt_text.contains("default export"));
    assert!(!prompt_text.contains("Studio HTML scaffold contract"));
}

#[test]
fn svg_materialization_prompt_uses_svg_scaffold_contract_labels() {
    let request = request_for(StudioArtifactClass::Visual, StudioRendererKind::Svg);
    let brief = StudioArtifactBrief {
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
    };

    let prompt = build_studio_artifact_materialization_prompt(
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

    assert!(prompt_text.contains("Studio SVG design skill spine"));
    assert!(prompt_text.contains("Studio SVG scaffold contract"));
    assert!(prompt_text.contains("Studio SVG component pack contracts"));
    assert!(prompt_text.contains("stable viewBox"));
    assert!(!prompt_text.contains("Studio renderer scaffold contract"));
}

#[test]
fn pdf_materialization_prompt_uses_pdf_scaffold_contract_labels() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed);
    let brief = StudioArtifactBrief {
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
    };

    let prompt = build_studio_artifact_materialization_prompt(
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

    assert!(prompt_text.contains("Studio PDF design skill spine"));
    assert!(prompt_text.contains("Studio PDF scaffold contract"));
    assert!(prompt_text.contains("Studio PDF component pack contracts"));
    assert!(prompt_text.contains("compact briefing PDF"));
    assert!(!prompt_text.contains("Studio renderer scaffold contract"));
}

#[test]
fn materialization_repair_prompt_preserves_candidate_metadata_and_view() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
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

    let repair_prompt = build_studio_artifact_materialization_repair_prompt(
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

#[test]
fn materialization_repair_prompt_handles_missing_json_payload_for_html() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let repair_prompt = build_studio_artifact_materialization_repair_prompt(
        "Dog shampoo rollout",
        "Make it feel more enterprise",
        &request,
        &brief,
        None,
        None,
        "candidate-3",
        21,
        "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>",
        "Failed to parse Studio artifact materialization payload: Studio artifact materialization output missing JSON payload",
    )
    .expect("repair prompt");
    let repair_text = serde_json::to_string(&repair_prompt).expect("repair prompt text");

    assert!(repair_text.contains("exact JSON schema"));
    assert!(repair_text.contains("do not answer with raw HTML"));
    assert!(repair_text.contains("files[0].body"));
}

#[test]
fn normalization_repairs_hidden_mapped_panels_and_missing_rollover_payloads() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
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
            "ingredient analysis".to_string(),
        ],
        required_interactions: vec![
            "rollover effects for chart elements".to_string(),
            "clickable navigation between different types of charts".to_string(),
        ],
        visual_tone: vec![
            "informative".to_string(),
            "professional".to_string(),
            "user-friendly".to_string(),
        ],
        factual_anchors: vec![
            "clinical trials data".to_string(),
            "customer feedback".to_string(),
            "sales performance metrics".to_string(),
        ],
        style_directives: vec!["clear and concise language".to_string()],
        reference_hints: vec![
            "charts showing pH levels, ingredient breakdowns, before-and-after condition comparisons"
                .to_string(),
        ],
    };
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch across customer satisfaction, usage statistics, and ingredient analysis.</p><button type=\"button\" data-view=\"satisfaction\" aria-controls=\"satisfaction-panel\">Customer satisfaction</button><button type=\"button\" data-view=\"usage\" aria-controls=\"usage-panel\">Usage statistics</button><button type=\"button\" data-view=\"ingredients\" aria-controls=\"ingredients-panel\">Ingredient analysis</button></section><section id=\"satisfaction-panel\" role=\"tabpanel\" hidden><article><h2>Customer satisfaction</h2><svg viewBox=\"0 0 260 140\" role=\"img\" aria-label=\"Customer satisfaction chart\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><rect x=\"94\" y=\"36\" width=\"42\" height=\"80\"></rect><rect x=\"164\" y=\"28\" width=\"42\" height=\"88\"></rect><text x=\"24\" y=\"132\">Retail</text><text x=\"94\" y=\"132\">Subscription</text><text x=\"164\" y=\"132\">Vet</text></svg></article></section><section id=\"usage-panel\" role=\"tabpanel\" hidden><article><h2>Usage statistics</h2><p>Monthly wash frequency and repurchase lift stay visible here.</p></article></section><section id=\"ingredients-panel\" role=\"tabpanel\" hidden><article><h2>Ingredient analysis</h2><p>Oat protein support, pH balance, and low-residue fragrance control stay visible here.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Customer satisfaction stays selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[role=\"tabpanel\"]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});detail.textContent=button.textContent;}));</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should keep candidate parseable");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("normalization should repair hidden panels and rollover payloads");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html_has_visible_mapped_view_panel(&html));
    assert!(html_contains_rollover_detail_behavior(&html));
    assert!(html.contains("data-studio-rollover-repair=\"true\""));
    assert!(html.matches("data-detail=").count() >= 3);
}

#[test]
fn normalization_synthesizes_view_controls_from_pre_rendered_panels() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "overview".to_string(),
            "launch date".to_string(),
            "sales data".to_string(),
        ],
        required_interactions: vec![
            "clickable navigation between different chart views".to_string()
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect the overview, launch date, and sales data without leaving the artifact.</p></section><section data-view-panel=\"overview\"><article><h2>Overview</h2><p>Dog shampoo launch planning, packaging sign-off, and retailer timing stay visible here.</p></article></section><section data-view-panel=\"launch-date\"><article><h2>Launch date</h2><p>March 2026 regional release window with a two-week pilot buffer.</p></article></section><section data-view-panel=\"sales-data\"><article><h2>Sales data</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo sales data\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Pilot</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should synthesize a mapped control scaffold");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("brief-aware validation should accept synthesized view controls");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-view-controls-repair=\"true\""));
    assert!(html.contains("data-studio-view-switch-repair=\"true\""));
    assert!(html.contains("button type=\"button\" data-view=\"overview\""));
    assert!(html.contains("aria-controls=\"studio-view-panel-overview\""));
    assert!(html.contains("queryselectorall('[data-view-panel]')"));
}

#[test]
fn normalization_promotes_control_first_evidence_sections_into_view_panels() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "launch date".to_string(),
            "sales data".to_string(),
        ],
        required_interactions: vec![
            "clickable navigation between different chart views".to_string()
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec!["product launch date".to_string(), "sales data".to_string()],
        style_directives: vec![],
        reference_hints: vec![],
    };
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section id=\"overview\"><h1>Dog shampoo rollout</h1><p>Inspect launch timing and sales evidence without leaving the artifact.</p></section><section id=\"control-bar\"><button type=\"button\" data-view=\"launch-date\">Launch Date</button><button type=\"button\" data-view=\"sales-data\">Sales Data</button></section><section id=\"primary-evidence\"><article><h2>Launch Date</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo launch date\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\" data-detail=\"March regional launch\"></rect><text x=\"20\" y=\"114\">March</text></svg></article></section><section id=\"secondary-evidence\"><article><h2>Sales Data</h2><p>Projected first-month sales stay visible in this evidence section.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch Date is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should promote evidence sections into mapped panels");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("brief-aware validation should accept promoted mapped panels");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-view-panel-repair=\"true\""));
    assert!(html.contains("data-view-panel=\"launch-date\""));
    assert!(html.contains("data-view-panel=\"sales-data\""));
    assert!(html.contains("aria-controls=\"studio-view-panel-launch-date\""));
    assert!(html_contains_explicit_view_mapping(&html));
}

#[test]
fn normalization_prefers_evidence_panels_over_control_only_wrappers() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "AI tools users".to_string(),
        job_to_be_done: "review the launch".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show the launch evidence clearly".to_string(),
        required_concepts: vec![
            "AI tool capabilities".to_string(),
            "Editorial content".to_string(),
            "Launch event".to_string(),
        ],
        required_interactions: vec!["clickable navigation between evidence views".to_string()],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec!["AI tool features".to_string()],
        style_directives: vec![],
        reference_hints: vec![],
    };
    let raw = serde_json::json!({
        "summary": "AI tools launch artifact",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section data-view-panel=\"overview\"><p>Overview</p></section><section data-view-panel=\"control-bar\"><button type=\"button\">AI Tool Features</button><button type=\"button\">Editorial Content</button></section><section data-view-panel=\"primary-evidence\" hidden><article><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"AI tool launch\"><rect x=\"24\" y=\"52\" width=\"40\" height=\"56\"></rect><text x=\"24\" y=\"118\">Launch</text></svg></article></section><section data-view-panel=\"secondary-evidence\" hidden><article><h2>Editorial Content</h2><p>Editorial content stays visible in this panel.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should synthesize request-ready controls");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("brief-aware validation should accept synthesized controls");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-view-controls-repair=\"true\""));
    assert!(!html.contains("data-view=\"control-bar\""));
    assert!(html.contains("data-view=\"primary-evidence\""));
    assert!(html.contains("aria-controls=\"studio-view-panel-primary-evidence\""));
    assert!(html.contains(
        "data-view=\"primary-evidence\" aria-controls=\"studio-view-panel-primary-evidence\" aria-selected=\"true\""
    ));
}

#[test]
fn parse_and_validate_normalizes_html_mime_parameters_and_paths() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": [],
        "files": [{
            "path": "/files/interactive_single_file.html",
            "mime": "text/html; charset=UTF-8",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><button type=\"button\" data-view=\"launch\">Launch</button><button type=\"button\" data-view=\"sales\">Sales</button></section><section data-view-panel=\"launch\"><article><h2>Launch</h2><p>March regional launch.</p></article></section><section data-view-panel=\"sales\" hidden><article><h2>Sales</h2><p>Projected first-month sales.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should canonicalize mime parameters");

    assert_eq!(payload.files[0].path, "files/interactive_single_file.html");
    assert_eq!(payload.files[0].mime, "text/html");
}

#[test]
fn normalization_inserts_shared_detail_region_when_script_targets_detail_copy() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
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
        factual_anchors: vec!["sales data".to_string()],
        style_directives: vec!["clear and concise language".to_string()],
        reference_hints: vec!["dog grooming industry trends".to_string()],
    };
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><button type=\"button\" data-view=\"sales\" aria-controls=\"sales-panel\">Sales data</button><button type=\"button\" data-view=\"usage\" aria-controls=\"usage-panel\">Usage statistics</button></section><section id=\"sales-panel\" data-view-panel=\"sales\"><article><h2>Sales data</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Sales data chart\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><rect x=\"94\" y=\"36\" width=\"42\" height=\"80\"></rect><rect x=\"164\" y=\"28\" width=\"42\" height=\"88\"></rect><text x=\"24\" y=\"132\">Q1</text><text x=\"94\" y=\"132\">Q2</text><text x=\"164\" y=\"132\">Q3</text></svg></article></section><section id=\"usage-panel\" data-view-panel=\"usage\" hidden><article><h2>Usage statistics</h2><p>Repurchase lift stays visible here.</p></article></section><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.textContent;}));</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should repair missing detail-copy region");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("brief-aware validation should accept the injected detail region");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("id=\"detail-copy\""));
    assert!(!html_references_missing_dom_ids(&html));
    assert!(count_populated_html_detail_regions(&html) > 0);
}

#[test]
fn rollover_failure_directives_require_focusable_detail_marks() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe briefs that call for rollover detail must wire hover or focus handlers on visible marks to update shared detail on first paint.",
    );

    assert!(directives.contains("querySelectorAll('[data-detail]')"));
    assert!(directives.contains("tabindex=\"0\""));
    assert!(directives.contains("detailCopy.textContent = mark.dataset.detail"));
}

#[test]
fn view_switching_failure_directives_require_panel_scaffold() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe briefs that call for clickable view switching must map at least two controls to pre-rendered view panels with explicit static selectors.",
    );

    assert!(directives.contains("buttons[data-view]"));
    assert!(directives.contains("data-view-panel=\"customer-feedback\""));
    assert!(directives.contains("class=\"data-view-panel\""));
    assert!(directives.contains("class=\"overview-panel\""));
    assert!(directives.contains("id=\"customer-feedback-panel\""));
    assert!(directives.contains("panel.dataset.viewPanel !== button.dataset.view"));
    assert!(directives.contains("not directly at an SVG"));
    assert!(directives.contains("Keep exactly one mapped panel visibly selected"));
    assert!(directives.contains("Do not point every button at the shared detail panel"));
}

#[test]
fn main_region_failure_directives_require_markup_first_scaffold() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe artifacts must contain a <main> region.",
    );

    assert!(directives.contains("<!doctype html><html><body><main>"));
    assert!(directives.contains("script>...interactive wiring"));
    assert!(directives.contains("before the script tag"));
}

#[test]
fn charted_evidence_failure_directives_require_visible_secondary_surface() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe briefs with charted evidence must surface at least two populated evidence views on first paint.",
    );

    assert!(directives.contains("Empty mount divs like <div id=\"usage-chart\"></div>"));
    assert!(directives.contains("single sentence paragraph"));
    assert!(directives.contains("customer feedback"));
}

#[test]
fn pdf_parse_failure_directives_require_json_wrapping() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed);
    let brief = StudioArtifactBrief {
        audience: "launch stakeholders".to_string(),
        job_to_be_done: "review the brief".to_string(),
        subject_domain: "launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a compact PDF.".to_string(),
        required_concepts: vec!["launch".to_string(), "brief".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "Failed to parse Studio artifact materialization payload: Studio artifact materialization output missing JSON payload",
    );

    assert!(directives.contains("exact JSON schema"));
    assert!(directives.contains("raw document text"));
    assert!(directives.contains("files[0].body"));
}

#[test]
fn pdf_structure_failure_directives_require_visible_section_breaks() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed);
    let brief = StudioArtifactBrief {
        audience: "launch stakeholders".to_string(),
        job_to_be_done: "review the brief".to_string(),
        subject_domain: "launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a compact PDF.".to_string(),
        required_concepts: vec!["launch".to_string(), "brief".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "PDF source content needs clearer sections before it can lead the artifact stage.",
    );

    assert!(directives.contains("five short standalone section headings"));
    assert!(directives.contains("separated by blank lines"));
    assert!(directives.contains("Executive Summary"));
}

#[test]
fn pdf_placeholder_failure_directives_require_concrete_copy() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed);
    let brief = StudioArtifactBrief {
        audience: "launch stakeholders".to_string(),
        job_to_be_done: "review the brief".to_string(),
        subject_domain: "launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a compact PDF.".to_string(),
        required_concepts: vec!["launch".to_string(), "brief".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "PDF source content must not contain bracketed placeholder copy.",
    );

    assert!(directives.contains("bracketed template token"));
    assert!(directives.contains("request-grounded bullets"));
}

#[test]
fn html_local_runtime_candidate_generation_explores_multiple_candidates() {
    let (count, temperature, strategy) = candidate_generation_config(
        StudioRendererKind::HtmlIframe,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    assert_eq!(count, 2);
    assert!(temperature > 0.5);
    assert_eq!(strategy, "request-grounded_html");
}

#[test]
fn simple_local_runtime_renderers_use_single_candidate_budgets() {
    for (renderer, expected_temperature, expected_strategy) in [
        (StudioRendererKind::Markdown, 0.22, "outline-first_markdown"),
        (StudioRendererKind::Mermaid, 0.18, "pipeline-first_mermaid"),
        (StudioRendererKind::PdfEmbed, 0.2, "brief-first_pdf"),
        (
            StudioRendererKind::DownloadCard,
            0.12,
            "bundle-first_download",
        ),
        (
            StudioRendererKind::BundleManifest,
            0.12,
            "bundle-first_download",
        ),
    ] {
        let (count, temperature, strategy) =
            candidate_generation_config(renderer, StudioRuntimeProvenanceKind::RealLocalRuntime);
        assert_eq!(count, 1);
        assert!((temperature - expected_temperature).abs() < f32::EPSILON);
        assert_eq!(strategy, expected_strategy);
    }
}

#[test]
fn html_local_runtime_refinement_budget_limits_to_single_pass() {
    assert_eq!(
        super::judging::semantic_refinement_pass_limit(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        1
    );
}

#[test]
fn quantum_html_budget_expands_structurally_but_stays_bounded() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);

    let budget = super::generation::derive_studio_adaptive_search_budget(
        &request,
        &brief,
        Some(&blueprint),
        Some(&artifact_ir),
        &[],
        &[],
        None,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );

    assert_eq!(budget.initial_candidate_count, 2);
    assert_eq!(budget.max_candidate_count, 3);
    assert!(budget.shortlist_limit >= 2);
    assert!(budget.max_semantic_refinement_passes >= 1);
    assert!(budget.max_semantic_refinement_passes <= 2);
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::RendererComplexity));
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::BriefInteractionLoad));
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::BriefConceptLoad));
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::LocalGenerationConstraint));
}

#[test]
fn low_variance_near_misses_expand_to_budget_cap() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let mut budget = super::generation::derive_studio_adaptive_search_budget(
        &request,
        &brief,
        Some(&blueprint),
        Some(&artifact_ir),
        &[],
        &[],
        None,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    let candidate_summaries = vec![
        studio_test_candidate_summary(
            "candidate-1",
            studio_test_judge(
                StudioArtifactJudgeClassification::Repairable,
                false,
                4,
                4,
                4,
                4,
                4,
                4,
            ),
        ),
        studio_test_candidate_summary(
            "candidate-2",
            studio_test_judge(
                StudioArtifactJudgeClassification::Repairable,
                false,
                4,
                4,
                4,
                4,
                4,
                3,
            ),
        ),
    ];
    let ranked = super::generation::ranked_candidate_indices_by_score(&candidate_summaries);
    let expanded = super::generation::target_candidate_count_after_initial_search(
        &mut budget,
        &ranked,
        &candidate_summaries,
        0,
    );

    assert_eq!(expanded, budget.max_candidate_count);
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::LowCandidateVariance));
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::NoPrimaryViewCandidate));
}

#[test]
fn shortlist_widens_for_near_tied_primary_view_candidates() {
    let mut budget = StudioAdaptiveSearchBudget {
        initial_candidate_count: 2,
        max_candidate_count: 3,
        shortlist_limit: 1,
        max_semantic_refinement_passes: 1,
        plateau_limit: 1,
        min_score_delta: 1,
        target_judge_score_for_early_stop: 356,
        expansion_score_margin: 12,
        signals: Vec::new(),
    };
    let candidate_summaries = vec![
        studio_test_candidate_summary(
            "candidate-1",
            studio_test_judge(
                StudioArtifactJudgeClassification::Pass,
                true,
                5,
                5,
                5,
                5,
                5,
                5,
            ),
        ),
        studio_test_candidate_summary(
            "candidate-2",
            studio_test_judge(
                StudioArtifactJudgeClassification::Pass,
                true,
                5,
                5,
                5,
                5,
                5,
                4,
            ),
        ),
        studio_test_candidate_summary(
            "candidate-3",
            studio_test_judge(
                StudioArtifactJudgeClassification::Repairable,
                false,
                3,
                3,
                3,
                3,
                3,
                3,
            ),
        ),
    ];
    let ranked = super::generation::ranked_candidate_indices_by_score(&candidate_summaries);
    let shortlist = super::generation::shortlisted_candidate_indices_for_budget(
        &mut budget,
        &ranked,
        &candidate_summaries,
    );

    assert_eq!(shortlist, vec![0, 1]);
    assert_eq!(budget.shortlist_limit, 2);
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::LowCandidateVariance));
}

#[test]
fn html_local_runtime_materialization_repair_budget_limits_to_single_pass() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        1
    );
}

#[test]
fn html_remote_runtime_materialization_repair_budget_allows_three_passes() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
        ),
        3
    );
}

#[test]
fn pdf_materialization_repair_budget_allows_three_passes() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            StudioRendererKind::PdfEmbed,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        3
    );
}

#[test]
fn validates_generated_markdown_payload() {
    let payload = StudioGeneratedArtifactPayload {
        summary: "Prepared markdown artifact".to_string(),
        notes: vec!["Verified structure".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "brief.md".to_string(),
            mime: "text/markdown".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "# Brief".to_string(),
        }],
    };
    validate_generated_artifact_payload(
        &payload,
        &request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown),
    )
    .expect("payload should validate");
}

#[test]
fn rejects_generated_pdf_payload_when_source_is_too_short() {
    let payload = StudioGeneratedArtifactPayload {
        summary: "Launch brief".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "brief.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "Executive Summary\n\nThis launch brief is short.\n\nProject Scope\n\nA limited regional rollout.\n\nNext Steps\n\nFinalize owner review.".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed),
    )
    .expect_err("short PDF source should fail validation");

    assert!(error.contains("PDF source content is too short"));
}

#[test]
fn parse_generated_payload_tolerates_duplicate_json_fields() {
    let raw = r#"{
        "summary": "Dog shampoo rollout",
        "notes": [],
        "files": [
            {
                "path": "dog-shampoo-rollout.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "downloadable": false,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Dog shampoo</h1><button type=\"button\" data-view=\"overview\">Overview</button></section><article data-view-panel=\"overview\"><p>Metrics</p></article><aside><p id=\"detail-copy\">Overview selected.</p></aside><footer>Done</footer><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=`${button.dataset.view} selected.`;}));</script></main></body></html>"
            }
        ]
    }"#;

    let payload =
        parse_studio_generated_artifact_payload(raw).expect("duplicate fields should collapse");

    assert_eq!(payload.files.len(), 1);
    assert!(!payload.files[0].downloadable);
    validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("normalized payload should still validate");
}

#[test]
fn parse_and_validate_normalizes_absolute_generated_file_paths() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": [],
        "files": [{
            "path": "/index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect the launch evidence.</p></section><section><article><h2>Sales data</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Sales data chart\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Q1</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Sales data is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("absolute generated file paths should be normalized");

    assert_eq!(payload.files[0].path, "index.html");
}

#[test]
fn validates_generated_payloads_for_all_non_workspace_renderers() {
    let cases = vec![
            (
                request_for(
                    StudioArtifactClass::Document,
                    StudioRendererKind::HtmlIframe,
                ),
                StudioGeneratedArtifactPayload {
                    summary: "html".to_string(),
                    notes: Vec::new(),
                    files: vec![StudioGeneratedArtifactFile {
                        path: "index.html".to_string(),
                        mime: "text/html".to_string(),
                        role: StudioArtifactFileRole::Primary,
                        renderable: true,
                        downloadable: true,
                        encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                        body: "<!doctype html><html><body><main><section>Hello</section><article>Detail</article><footer>Done</footer></main></body></html>".to_string(),
                    }],
                },
            ),
            (
                request_for(
                    StudioArtifactClass::InteractiveSingleFile,
                    StudioRendererKind::JsxSandbox,
                ),
                StudioGeneratedArtifactPayload {
                    summary: "jsx".to_string(),
                    notes: Vec::new(),
                    files: vec![StudioGeneratedArtifactFile {
                        path: "Artifact.jsx".to_string(),
                        mime: "text/jsx".to_string(),
                        role: StudioArtifactFileRole::Primary,
                        renderable: true,
                        downloadable: true,
                        encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                        body: "export default function Artifact() { return <main>Hello</main>; }"
                            .to_string(),
                    }],
                },
            ),
            (
                request_for(StudioArtifactClass::Visual, StudioRendererKind::Svg),
                StudioGeneratedArtifactPayload {
                    summary: "svg".to_string(),
                    notes: Vec::new(),
                    files: vec![StudioGeneratedArtifactFile {
                        path: "chart.svg".to_string(),
                        mime: "image/svg+xml".to_string(),
                        role: StudioArtifactFileRole::Primary,
                        renderable: true,
                        downloadable: true,
                        encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                        body: "<svg viewBox=\"0 0 10 10\"></svg>".to_string(),
                    }],
                },
            ),
            (
                request_for(StudioArtifactClass::Visual, StudioRendererKind::Mermaid),
                StudioGeneratedArtifactPayload {
                    summary: "mermaid".to_string(),
                    notes: Vec::new(),
                    files: vec![StudioGeneratedArtifactFile {
                        path: "flow.mermaid".to_string(),
                        mime: "text/plain".to_string(),
                        role: StudioArtifactFileRole::Primary,
                        renderable: true,
                        downloadable: true,
                        encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                        body: "flowchart TD\nA-->B".to_string(),
                    }],
                },
            ),
            (
                request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed),
                StudioGeneratedArtifactPayload {
                    summary: "pdf".to_string(),
                    notes: Vec::new(),
                    files: vec![StudioGeneratedArtifactFile {
                        path: "brief.pdf".to_string(),
                        mime: "application/pdf".to_string(),
                        role: StudioArtifactFileRole::Primary,
                        renderable: true,
                        downloadable: true,
                        encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                        body: "Quarterly brief".to_string(),
                    }],
                },
            ),
            (
                request_for(
                    StudioArtifactClass::DownloadableFile,
                    StudioRendererKind::DownloadCard,
                ),
                StudioGeneratedArtifactPayload {
                    summary: "download".to_string(),
                    notes: Vec::new(),
                    files: vec![StudioGeneratedArtifactFile {
                        path: "export.csv".to_string(),
                        mime: "text/csv".to_string(),
                        role: StudioArtifactFileRole::Export,
                        renderable: false,
                        downloadable: true,
                        encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                        body: "name,value\nlaunch,1\n".to_string(),
                    }],
                },
            ),
            (
                request_for(
                    StudioArtifactClass::CompoundBundle,
                    StudioRendererKind::BundleManifest,
                ),
                StudioGeneratedArtifactPayload {
                    summary: "bundle".to_string(),
                    notes: Vec::new(),
                    files: vec![
                        StudioGeneratedArtifactFile {
                            path: "bundle.json".to_string(),
                            mime: "application/json".to_string(),
                            role: StudioArtifactFileRole::Primary,
                            renderable: true,
                            downloadable: true,
                            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                            body: "{\"items\":[\"report.md\"]}".to_string(),
                        },
                        StudioGeneratedArtifactFile {
                            path: "report.md".to_string(),
                            mime: "text/markdown".to_string(),
                            role: StudioArtifactFileRole::Supporting,
                            renderable: true,
                            downloadable: true,
                            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                            body: "# Report".to_string(),
                        },
                    ],
                },
            ),
        ];

    for (request, payload) in cases {
        validate_generated_artifact_payload(&payload, &request)
            .expect("generated payload should validate for renderer");
    }
}

#[test]
fn rejects_interactive_html_payloads_that_use_alert_only_interactions() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Launch</h1><button onclick=\"alert('demo')\">Demo</button></section><article>Guide</article><footer>Ship</footer></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("alert-only interactive HTML should fail validation");
    assert!(error.contains("must not use alert()"));
}

#[test]
fn rejects_html_payloads_with_scaffold_css_and_js_comments() {
    let payload = StudioGeneratedArtifactPayload {
        summary: "Prepared HTML artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><head><style>/* Add your CSS here */</style></head><body><main><section><h1>AI tools launch</h1><p>Inspect the launch evidence.</p></section><section><article><h2>Release chart</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"AI tools release chart\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Q1</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Release evidence is selected by default.</p></aside></main><script>// Add your JavaScript here</script></body></html>".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("scaffold comments should fail HTML validation");

    assert!(error.contains("placeholder-grade copy"));
}

#[test]
fn rejects_html_payloads_with_external_runtime_dependencies() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Launch</h1><button type=\"button\">Inspect</button><p>Use the chart to inspect launch readiness.</p></section><article><h2>Preview chart</h2><svg id=\"chart\" role=\"img\" aria-label=\"Launch chart\"><rect x=\"20\" y=\"40\" width=\"40\" height=\"60\"></rect><text x=\"20\" y=\"116\">Week 1</text></svg></article><footer><p>Supporting evidence stays inline.</p><script>const root = d3.select('#chart');</script></footer></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("external runtime dependencies should fail validation");
    assert!(error.contains("must not depend on external libraries"));
}

#[test]
fn rejects_html_payloads_with_empty_svg_placeholder_regions() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Channel metrics and launch steps stay visible.</p></section><article><button type=\"button\">Show adoption</button><svg width=\"400\" height=\"220\"><!-- chart data goes here --></svg></article><footer><p>Operators can review readiness inline.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("empty SVG chart shells should fail validation");
    assert!(error.contains("must render real SVG marks or labels on first paint"));
}

#[test]
fn rejects_html_payloads_with_empty_chart_container_regions() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Channel metrics and launch steps stay visible.</p></section><article><button type=\"button\">Show adoption</button><article id=\"conditionComparisonChart\"></article><article id=\"ingredientBreakdownChart\"><!-- chart fills later --></article></article><footer><p>Operators can review readiness inline.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("empty chart containers should fail validation");
    assert!(error.contains("must render visible chart content on first paint"));
}

#[test]
fn rejects_html_payloads_with_chart_headings_but_no_chart_implementation() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect the launch metrics and supporting evidence.</p></section><section class=\"chart-container\" id=\"phChart\"><h2>pH Levels Chart</h2><!-- chart goes here --></section><article class=\"chart-container\" id=\"ingredientChart\"><h2>Ingredient Breakdown Chart</h2><p>Ingredient chart details load later.</p></article><footer><button type=\"button\">Switch chart</button><p>Review the rollout notes inline.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("chart-labeled shells without chart implementation should fail validation");
    assert!(error.contains("must render visible chart content on first paint"));
}

#[test]
fn rejects_html_payloads_that_only_show_blank_canvas_chart_shells() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section class=\"chart-container\"><h1>Dog shampoo rollout</h1><p>Inspect the product rollout evidence and compare the ingredient story across launch stages.</p><canvas id=\"rolloutTimeline\" width=\"500\" height=\"300\"></canvas><p>The default rollout detail is visible here.</p></section><section class=\"chart-container\"><h2>Usage statistics</h2><canvas id=\"usageStats\" width=\"500\" height=\"300\"></canvas><p>Usage statistics copy stays visible on first paint.</p></section><aside><h2>Shared detail</h2><p>Hover a mark to inspect the rollout evidence.</p></aside><script>document.getElementById('usageStats').addEventListener('mouseenter',()=>{});</script></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("blank canvas shells should fail validation");
    assert!(error.contains("must render visible chart content on first paint"));
}

#[test]
fn rejects_html_payloads_with_placeholder_comments_and_missing_target_ids() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Explain the Key Features and Benefits of a New Dog Shampoo Through Interactive Charts and Data Visualizations</h1></section><section class=\"controls\"><button id=\"chart1\" class=\"control\">Chart 1: pH Levels</button><button id=\"chart2\" class=\"control\">Chart 2: Ingredient Breakdowns</button><button id=\"chart3\" class=\"control\">Chart 3: Before & After Condition Comparisons</button></section><section><div id=\"chart1-container\"><svg width=\"500\" height=\"300\" viewBox=\"0 0 500 300\"><!-- Placeholder SVG content for Chart 1 --><rect x=\"100\" y=\"100\" width=\"80\" height=\"100\" fill=\"#ffd700\"></rect></svg></div></section><aside id=\"detail-panel\"><h2>Product Rollout Details</h2><p>Key benefits and performance metrics for the new dog shampoo.</p></aside></main><script>const chartContainers=document.querySelectorAll('#chart1-container, #chart2-container, #chart3-container');document.getElementById('chart2').addEventListener('click',()=>{chartContainers.forEach((container)=>container.style.display='none');document.getElementById('chart2-container').style.display='flex';});</script></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("placeholder comments and missing target ids should fail validation");
    assert!(error.contains("must not contain placeholder-grade copy"));
}

#[test]
fn rejects_html_payloads_with_empty_shared_detail_regions() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Compare launch readiness, channel adoption, and formula proof points.</p><button type=\"button\" id=\"retail\">Retail</button><button type=\"button\" id=\"subscription\">Subscription</button></section><section><article class=\"chart\"><h2>Channel adoption</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo adoption chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><rect x=\"88\" y=\"34\" width=\"40\" height=\"66\"></rect><text x=\"20\" y=\"114\">Retail</text><text x=\"88\" y=\"114\">Subscription</text></svg><p>Retail stays selected by default.</p></article></section><aside id=\"detail-panel\"><h2>Comparison detail</h2><!-- default detail arrives later --></aside></main><script>const detail=document.getElementById('detail-panel');document.getElementById('retail').addEventListener('click',()=>{detail.dataset.view='retail';});document.getElementById('subscription').addEventListener('click',()=>{detail.dataset.view='subscription';});</script></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("empty shared detail regions should fail validation");
    assert!(error.contains("must populate them on first paint"));
}

#[test]
fn rejects_html_payloads_that_only_bootstrap_first_paint_from_empty_shells() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "product_rollout.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><button id=\"timeline-prev\">Previous</button></section><section><span id=\"timeline-label\"></span></section><section><button id=\"timeline-next\">Next</button></section><section><div id=\"chart-container\"><!-- chart bootstraps later --></div></section><script>document.getElementById('timeline-label').innerText='Phase 1';document.getElementById('chart-container').innerHTML='<svg width=\"200\" height=\"120\"><rect x=\"20\" y=\"40\" width=\"60\" height=\"60\"></rect></svg>';</script></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("script-bootstrapped first paint should fail validation");
    assert!(error.contains("at least three sectioning elements with first-paint content"));
}

#[test]
fn rejects_html_payloads_with_unlabeled_chart_svg_regions() {
    let payload = StudioGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Ingredient analysis and customer satisfaction stay visible.</p></section><article class=\"chart\"><button type=\"button\">Show adoption</button><svg width=\"300\" height=\"220\"><circle cx=\"110\" cy=\"110\" r=\"72\" stroke=\"#335\" stroke-width=\"18\" fill=\"none\"></circle><circle cx=\"110\" cy=\"110\" r=\"48\" stroke=\"#7aa\" stroke-width=\"18\" fill=\"none\"></circle></svg></article><footer><p>Operators can inspect the rollout plan inline.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect_err("unlabeled chart SVG shells should fail validation");
    assert!(error.contains("must include visible labels, legends, or aria labels"));
}

#[test]
fn parse_and_validate_normalizes_repairable_html_sectioning() {
    let raw = serde_json::json!({
            "summary": "Instacart rollout artifact",
            "notes": ["under-sectioned draft"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><div><h1>Instacart MCP rollout</h1><p>Track the rollout plan through live metrics.</p></div><div><button type=\"button\">Show adoption</button><div aria-live=\"polite\">Adoption by channel is visible on first paint.</div></div><footer><p>Launch owners and milestones remain visible.</p></footer><script>document.querySelector('button').addEventListener('click',()=>{document.querySelector('[aria-live]').textContent='Adoption by channel updated for Instacart MCP.';});</script></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("repairable HTML structure should normalize and validate");

    let html = &payload.files[0].body;
    assert!(html.contains("data-studio-normalized"));
    assert!(count_html_sectioning_elements(&html.to_ascii_lowercase()) >= 3);
}

#[test]
fn parse_and_validate_wraps_missing_body_content_inside_main() {
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout",
            "notes": [],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><head><title>Dog shampoo rollout</title></head><section><h1>Dog shampoo rollout</h1><button type=\"button\" data-view=\"overview\">Overview</button></section><article data-view-panel=\"overview\"><p>Metrics stay visible.</p></article><aside><p id=\"detail-copy\">Overview selected.</p></aside><footer>Done</footer><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=`${button.dataset.view} selected.`;}));</script></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("missing body content should normalize into a main region");

    let html = &payload.files[0].body;
    assert!(html.contains("<body data-studio-normalized=\"true\">"));
    assert!(html.contains("<main data-studio-normalized=\"true\">"));
}

#[test]
fn parse_and_validate_resections_nested_div_shells() {
    let raw = serde_json::json!({
            "summary": "AI tools editorial launch",
            "notes": ["nested div shell"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><div><div><h1>AI tools editorial launch</h1><p>Guide readers through the launch story.</p></div><div><button type=\"button\">Open the launch brief</button><div aria-live=\"polite\">Featured tools and sections are already visible.</div></div><div><p>Editorial notes, launch rationale, and next reads.</p></div></div><script>document.querySelector('button').addEventListener('click',()=>{document.querySelector('[aria-live]').textContent='Launch brief expanded for AI tools readers.';});</script></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("nested div shells should normalize into semantic sections");

    let html = &payload.files[0].body;
    assert!(html.contains("AI tools editorial launch"));
    assert!(count_html_sectioning_elements(&html.to_ascii_lowercase()) >= 3);
}

#[test]
fn parse_and_validate_normalizes_alert_only_html_into_inline_disclosure() {
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout artifact",
            "notes": ["alert-only interaction"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><button onclick=\"alert('Show proof')\">Show proof</button></section><article><p>Adoption by channel and launch sequencing stay visible.</p></article><footer><p>Operators can inspect the rollout plan inline.</p></footer></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("alert-only HTML should normalize into a valid inline disclosure");

    let html = &payload.files[0].body;
    assert!(!html.to_ascii_lowercase().contains("alert("));
    assert!(html.contains("data-studio-interaction=\"true\""));
    assert!(html.contains("<details"));
}

#[test]
fn parse_and_validate_injects_disclosure_when_html_lacks_interaction_hooks() {
    let raw = serde_json::json!({
            "summary": "Instacart rollout artifact",
            "notes": ["static html draft"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Instacart MCP rollout</h1><p>Launch sequencing and channel metrics are visible.</p></section><article><p>Adoption by channel is summarized inline.</p></article><footer><p>Operators can review readiness.</p></footer></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("static interactive HTML should gain a minimal inline disclosure");

    let html = &payload.files[0].body;
    assert!(html.contains("data-studio-interaction=\"true\""));
    assert!(contains_html_interaction_hooks(&html.to_ascii_lowercase()));
}

#[test]
fn parse_and_validate_repairs_missing_view_switch_and_rollover_wiring() {
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout artifact",
            "notes": ["missing interaction wiring"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect the launch evidence.</p><button type=\"button\" data-view=\"satisfaction\" aria-controls=\"satisfaction-panel\">Customer Satisfaction</button><button type=\"button\" data-view=\"usage\" aria-controls=\"usage-panel\">Usage Statistics</button><button type=\"button\" data-view=\"ingredients\" aria-controls=\"ingredients-panel\">Ingredient Analysis</button></section><section id=\"satisfaction-panel\" data-view-panel=\"satisfaction\"><article><h2>Customer satisfaction</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo satisfaction\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\" data-detail=\"Retail satisfaction lift\"></rect><text x=\"20\" y=\"114\">Retail</text></svg></article></section><section id=\"usage-panel\" data-view-panel=\"usage\" hidden><article><h2>Usage statistics</h2><p>Usage evidence stays here.</p></article></section><section id=\"ingredients-panel\" data-view-panel=\"ingredients\" hidden><article><h2>Ingredient analysis</h2><p>Ingredient evidence stays here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Retail satisfaction lift is selected by default.</p></aside></main></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let mut payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("interaction wiring should normalize into a valid interactive draft");

    let html = &payload.files[0].body;
    assert!(html.contains("data-studio-view-switch-repair=\"true\""));
    assert!(html.contains("data-studio-rollover-repair=\"true\""));
    assert!(html.contains("querySelectorAll('[data-view-panel]')"));
    assert!(html.contains("addEventListener('click'"));
    assert!(html.contains("addEventListener('mouseenter'"));

    let brief = StudioArtifactBrief {
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
            "product rollout".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
            "ingredient analysis".to_string(),
        ],
        required_interactions: vec![
            "rollover effects for chart elements".to_string(),
            "clickable navigation between different types of charts".to_string(),
        ],
        visual_tone: vec![
            "informative".to_string(),
            "professional".to_string(),
            "user-friendly".to_string(),
        ],
        factual_anchors: vec![
            "clinical trials data".to_string(),
            "customer feedback".to_string(),
            "sales performance metrics".to_string(),
        ],
        style_directives: vec![
            "clear and concise language".to_string(),
            "use of color to highlight key points".to_string(),
            "interactive elements should be intuitive".to_string(),
        ],
        reference_hints: vec![
            "charts showing pH levels, ingredient breakdowns, before-and-after condition comparisons"
                .to_string(),
        ],
    };
    enrich_generated_artifact_payload(&mut payload, &request, &brief);
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("brief-aware enrichment should satisfy the typed brief contract");
}

#[test]
fn enrich_generated_svg_payload_adds_brief_grounded_title_and_desc() {
    let mut payload = StudioGeneratedArtifactPayload {
            summary: "Prepared SVG artifact".to_string(),
            notes: Vec::new(),
            files: vec![StudioGeneratedArtifactFile {
                path: "hero-concept.svg".to_string(),
                mime: "image/svg+xml".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<svg width='1200' height='630' viewBox='0 0 1200 630' xmlns='http://www.w3.org/2000/svg'><text x='80' y='120'>AI</text><text x='80' y='220'>Tools</text></svg>".to_string(),
            }],
        };
    let brief = StudioArtifactBrief {
            audience: "AI tools brand stakeholders".to_string(),
            job_to_be_done: "Create a shareable hero concept.".to_string(),
            subject_domain: "AI technology and software solutions".to_string(),
            artifact_thesis: "Design a visually compelling SVG hero concept that encapsulates the essence of AI tools brand storytelling.".to_string(),
            required_concepts: vec!["AI".to_string(), "tools".to_string(), "brand".to_string()],
            required_interactions: Vec::new(),
            visual_tone: vec!["modern".to_string()],
            factual_anchors: vec!["automation".to_string()],
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        };

    enrich_generated_artifact_payload(
        &mut payload,
        &request_for(StudioArtifactClass::Visual, StudioRendererKind::Svg),
        &brief,
    );

    let svg = &payload.files[0].body;
    assert!(svg.contains(
        "<title>AI tools brand stakeholders - AI technology and software solutions</title>"
    ));
    assert!(svg.contains("<desc>"));
    assert!(svg.to_ascii_lowercase().contains("brand"));
}

#[test]
fn enrich_generated_html_payload_adds_brief_grounded_rollover_marks() {
    let mut payload = StudioGeneratedArtifactPayload {
        summary: "Prepared HTML artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Inspect the launch evidence.</p><button type=\"button\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"editorial\">Editorial</button></section><section data-view-panel=\"overview\"><article><h2>Overview</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"AI tools overview\"><circle cx=\"48\" cy=\"48\" r=\"28\"></circle></svg></article></section><section data-view-panel=\"editorial\" hidden><article><h2>Editorial content</h2><p>Editorial copy remains visible here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside></main></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "AI tools users".to_string(),
        job_to_be_done: "understand the launch page".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show editorial launch evidence clearly".to_string(),
        required_concepts: vec![
            "AI tool capabilities".to_string(),
            "Editorial content".to_string(),
            "Launch event".to_string(),
        ],
        required_interactions: vec![
            "Click to learn more about AI tool features".to_string(),
            "Hover to see editorial highlights".to_string(),
        ],
        visual_tone: vec!["informative".to_string()],
        factual_anchors: vec![
            "AI tool features".to_string(),
            "Editorial content".to_string(),
        ],
        style_directives: Vec::new(),
        reference_hints: vec!["AI tool documentation".to_string()],
    };

    enrich_generated_artifact_payload(
        &mut payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &brief,
    );

    let html = &payload.files[0].body;
    assert!(html.contains("data-studio-rollover-chip-rail=\"true\""));
    assert!(html.contains("data-detail=\"AI tool features\""));
    assert!(html.contains("data-detail=\"Editorial content\""));
    assert!(html.contains("data-studio-rollover-repair=\"true\""));
}

#[test]
fn enrich_generated_html_payload_adds_detail_targets_for_multi_interaction_chart_briefs() {
    let mut payload = StudioGeneratedArtifactPayload {
        summary: "Prepared HTML artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>AI tools launch</h1><p>Inspect the latest releases and reactions.</p><button type=\"button\" data-view=\"releases\">Releases</button><button type=\"button\" data-view=\"signals\">Signals</button></section><section data-view-panel=\"releases\"><article><h2>Latest AI tool releases</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"AI tools launch chart\"><rect x=\"20\" y=\"40\" width=\"40\" height=\"60\"></rect><text x=\"20\" y=\"114\">Launch</text></svg></article></section><section data-view-panel=\"signals\" hidden><article><h2>Industry signals</h2><p>Industry trends remain visible here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Releases are selected by default.</p></aside></main></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "AI tools readers".to_string(),
        job_to_be_done: "inspect the launch".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show launch evidence clearly".to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "interactive features".to_string(),
        ],
        required_interactions: vec![
            "tool demonstration to update the visible chart and detail panel".to_string(),
            "user feedback collection to update the visible chart and detail panel".to_string(),
        ],
        visual_tone: vec!["modern".to_string()],
        factual_anchors: vec![
            "latest AI tool releases".to_string(),
            "industry trends in AI technology".to_string(),
        ],
        style_directives: Vec::new(),
        reference_hints: vec!["Product Hunt listings for new tech products".to_string()],
    };

    enrich_generated_artifact_payload(
        &mut payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &brief,
    );

    let html = &payload.files[0].body;
    assert!(html.contains("data-studio-rollover-chip-rail=\"true\""));
    assert!(html.contains("data-detail=\"latest AI tool releases\""));
    assert!(html.contains("data-detail=\"industry trends in AI technology\""));
    assert!(html.contains("Select, hover, or focus a highlight"));
    assert!(html.contains("data-studio-rollover-repair=\"true\""));
}

#[test]
fn parse_and_validate_normalizes_external_chart_runtime_into_inline_svg_fallback() {
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout artifact",
            "notes": ["external chart runtime"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><head><script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script></head><body><main><section><h1>Dog shampoo rollout</h1><button type=\"button\">Inspect rollout</button></section><article><canvas id=\"chart\"></canvas></article><footer><script>const chart = new Chart(document.getElementById('chart'), {type:'bar'});</script></footer></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("external chart runtime should normalize into inline SVG fallback");

    let html = &payload.files[0].body;
    let lower = html.to_ascii_lowercase();
    assert!(!lower.contains("<script src="));
    assert!(!lower.contains("new chart("));
    assert!(lower.contains("inline chart fallback"));
    assert!(lower.contains("<svg"));
}

#[derive(Clone)]
struct StudioTestRuntime {
    provenance: StudioRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl StudioTestRuntime {
    fn new(
        kind: StudioRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            provenance: StudioRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
            role,
            calls,
        }
    }
}

#[async_trait]
impl InferenceRuntime for StudioTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else if prompt.contains("typed artifact judge") {
            "judge"
        } else {
            "unknown"
        };
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{stage}", self.role));

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "operators",
                "jobToBeDone": "explain the rollout",
                "subjectDomain": "rollout planning",
                "artifactThesis": "show the launch plan clearly",
                "requiredConcepts": ["rollout timeline", "launch owners", "readiness checkpoints"],
                "requiredInteractions": ["chart toggle", "detail comparison"],
                "visualTone": ["confident"],
                "factualAnchors": ["launch checkpoint review"],
                "styleDirectives": [],
                "referenceHints": []
            }),
            "materialize" => {
                if prompt.contains("\"renderer\": \"markdown\"")
                    || prompt.contains("\"renderer\":\"markdown\"")
                {
                    serde_json::json!({
                        "summary": "Prepared a rollout artifact",
                        "notes": ["request-grounded candidate"],
                        "files": [{
                            "path": "release-checklist.md",
                            "mime": "text/markdown",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "# Release checklist\n\n- Finalize branch\n- Run QA\n- Tag release"
                        }]
                    })
                } else {
                    serde_json::json!({
                        "summary": "Prepared a rollout artifact",
                        "notes": ["request-grounded candidate"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "<!doctype html><html><body><main><section><h1>Rollout</h1></section><article><p>Timeline and owners.</p></article><footer>Ready for review.</footer></main></body></html>"
                        }]
                    })
                }
            }
            "judge" => serde_json::json!({
                "classification": "pass",
                "requestFaithfulness": 5,
                "conceptCoverage": 4,
                "interactionRelevance": 4,
                "layoutCoherence": 4,
                "visualHierarchy": 4,
                "completeness": 4,
                "genericShellDetected": false,
                "trivialShellDetected": false,
                "deservesPrimaryArtifactView": true,
                "patchedExistingArtifact": null,
                "continuityRevisionUx": null,
                "strongestContradiction": null,
                "rationale": format!("judged by {}", self.role)
            }),
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[derive(Clone)]
struct StudioOutcomeTestRuntime {
    payload: String,
}

#[async_trait]
impl InferenceRuntime for StudioOutcomeTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(self.payload.clone().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-outcome".to_string(),
            model: Some("fixture".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact materialization repairer") {
            (
                "repair",
                serde_json::json!({
                    "summary": "Prepared an editorial launch page for AI tools.",
                    "notes": ["schema-repaired candidate"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><body><main><section><h1>AI Tools Editorial Launch</h1><button type=\"button\">Open walkthrough</button></section><article><p>Editor picks, launch notes, and featured tools.</p><details><summary>Why this launch matters</summary><p>It combines tool demos and guidance.</p></details></article><aside><p>Reader guidance and follow-up actions.</p></aside></main></body></html>"
                    }]
                }),
            )
        } else if prompt.contains("typed artifact materializer") {
            (
                "materialize",
                serde_json::json!({
                    "summary": "Initial candidate",
                    "notes": ["invalid schema candidate"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": serde_json::Value::Null
                    }]
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-repair".to_string(),
            model: Some("fixture-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioSecondRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioSecondRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let mut calls = self.calls.lock().expect("calls lock");
        let repair_attempt = calls
            .iter()
            .filter(|stage| stage.starts_with("repair"))
            .count();
        let (stage, response) = if prompt.contains("typed artifact materialization repairer") {
            if repair_attempt == 0 {
                (
                    "repair-1",
                    serde_json::json!({
                        "summary": "First repair attempt",
                        "notes": ["still too thin"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Compare launch readiness and customer reactions.</p><button type=\"button\" data-view=\"satisfaction\">Satisfaction</button><button type=\"button\" data-view=\"usage\">Usage</button></section><section data-view-panel=\"satisfaction\"><article><h2>Customer satisfaction</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo satisfaction\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Pilot</text></svg></article></section><section data-view-panel=\"usage\" hidden><article><h2>Usage evidence</h2><p>Usage detail comes from the shared detail panel.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Satisfaction is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=`${button.dataset.view} selected`; }));</script></main></body></html>"
                        }]
                    }),
                )
            } else {
                (
                    "repair-2",
                    serde_json::json!({
                        "summary": "Second repair attempt",
                        "notes": ["brief-aware repair"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout lab</h1><p>Compare ingredient analysis, customer satisfaction, and usage statistics without leaving the artifact.</p><button type=\"button\" data-view=\"ingredients\">Ingredients</button><button type=\"button\" data-view=\"satisfaction\">Satisfaction</button><button type=\"button\" data-view=\"usage\">Usage</button></section><section data-view-panel=\"ingredients\"><article><h2>Ingredient analysis</h2><ul><li>Oat protein support</li><li>pH-balanced rinse</li><li>Low-residue fragrance control</li></ul></article><article><h2>Customer satisfaction chart</h2><svg viewBox=\"0 0 260 140\" role=\"img\" aria-label=\"Dog shampoo satisfaction chart\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" data-detail=\"Retail satisfaction lift\"></rect><rect x=\"94\" y=\"36\" width=\"42\" height=\"80\" data-detail=\"Subscription repeat use\"></rect><rect x=\"164\" y=\"28\" width=\"42\" height=\"88\" data-detail=\"Vet channel confidence\"></rect><text x=\"24\" y=\"132\">Retail</text><text x=\"94\" y=\"132\">Subscription</text><text x=\"164\" y=\"132\">Vet</text></svg></article></section><section data-view-panel=\"satisfaction\" hidden><article><h2>Satisfaction detail</h2><p>Subscription confidence and repeat-use sentiment stay visible here.</p></article></section><section data-view-panel=\"usage\" hidden><article><h2>Usage statistics</h2><p>Monthly wash frequency and repurchase lift stay available here.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Ingredient analysis and satisfaction stay visible on first paint.</p></aside><footer><p>Usage statistics stay available through the shared detail panel.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=`${button.dataset.view} selected for dog shampoo rollout review.`;}));document.querySelectorAll('svg [data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=`Hover detail: ${mark.dataset.detail}`;});mark.addEventListener('focus',()=>{detail.textContent=`Focus detail: ${mark.dataset.detail}`;});});</script></main></body></html>"
                        }]
                    }),
                )
            }
        } else if prompt.contains("typed artifact materializer") {
            (
                "materialize",
                serde_json::json!({
                    "summary": "Initial candidate",
                    "notes": ["invalid schema candidate"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": serde_json::Value::Null
                    }]
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        calls.push(stage.to_string());
        drop(calls);
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-second-repair".to_string(),
            model: Some("fixture-second-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioRawHtmlRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioRawHtmlRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact materialization repairer") {
            (
                "repair",
                serde_json::json!({
                    "summary": "Enterprise dog shampoo rollout",
                    "notes": ["json-wrapped repair"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout enterprise brief</h1><p>Enterprise channel readiness, adoption by channel, and risk review stay visible on first paint.</p><button type=\"button\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"channels\">Channels</button></section><section data-view-panel=\"overview\"><article><h2>Overview</h2><p>Regional rollout sequencing and service readiness remain visible here.</p></article></section><section data-view-panel=\"channels\" hidden><article><h2>Adoption by channel</h2><svg viewBox=\"0 0 260 140\" role=\"img\" aria-label=\"Adoption by channel\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" data-detail=\"Retail adoption\"></rect><rect x=\"94\" y=\"36\" width=\"42\" height=\"80\" data-detail=\"Subscription adoption\"></rect><rect x=\"164\" y=\"28\" width=\"42\" height=\"88\" data-detail=\"Veterinary adoption\"></rect><text x=\"24\" y=\"132\">Retail</text><text x=\"94\" y=\"132\">Subscription</text><text x=\"164\" y=\"132\">Veterinary</text></svg></article></section><aside><h2>Decision detail</h2><p id=\"detail-copy\">Retail adoption is selected by default.</p></aside><footer><p>Enterprise positioning keeps compliance, rollout sequencing, and support readiness in view.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=`${button.dataset.view} selected for enterprise rollout review.`;}));document.querySelectorAll('svg [data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=`Hover detail: ${mark.dataset.detail}`;});mark.addEventListener('focus',()=>{detail.textContent=`Focus detail: ${mark.dataset.detail}`;});});</script></main></body></html>"
                    }]
                })
                .to_string(),
            )
        } else if prompt.contains("typed artifact materializer") {
            (
                "materialize",
                "<!doctype html><html><body><main><section><h1>Dog shampoo rollout enterprise brief</h1><p>Enterprise adoption and service readiness.</p></section></main></body></html>".to_string(),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-raw-html-repair".to_string(),
            model: Some("fixture-raw-html-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioBriefRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact brief repairer") {
            (
                "brief-repair",
                serde_json::json!({
                    "audience": "consumers interested in pet care products",
                    "jobToBeDone": "understand the product rollout and its supporting evidence",
                    "subjectDomain": "dog grooming and hygiene",
                    "artifactThesis": "Explain the dog shampoo rollout through labeled charts and interaction-driven detail.",
                    "requiredConcepts": ["dog shampoo", "ingredient analysis", "customer satisfaction"],
                    "requiredInteractions": ["rollover chart detail", "view switching"],
                    "visualTone": ["informative"],
                    "factualAnchors": ["customer feedback", "usage statistics"],
                    "styleDirectives": ["clear hierarchy"],
                    "referenceHints": []
                }),
            )
        } else if prompt.contains("typed artifact brief planner") {
            (
                "brief",
                serde_json::json!({
                    "audience": "consumers interested in pet care products",
                    "jobToBeDone": "understand the product rollout and its supporting evidence",
                    "subjectDomain": "dog grooming and hygiene",
                    "artifactThesis": "Explain the dog shampoo rollout through labeled charts and interaction-driven detail.",
                    "requiredConcepts": ["dog shampoo", "ingredient analysis", "customer satisfaction"],
                    "requiredInteractions": ["rollover chart detail", "view switching"],
                    "visualTone": "informative",
                    "factualAnchors": ["customer feedback", "usage statistics"],
                    "styleDirectives": ["clear hierarchy"],
                    "referenceHints": []
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-brief-repair".to_string(),
            model: Some("fixture-brief-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioBriefIdentifierInteractionTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefIdentifierInteractionTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact brief planner") {
            (
                "brief",
                serde_json::json!({
                    "audience": "growth operators",
                    "jobToBeDone": "inspect the rollout evidence and choose which slice needs attention",
                    "subjectDomain": "dog shampoo product rollout",
                    "artifactThesis": "Explain the dog shampoo rollout through evidence-rich charts and guided detail.",
                    "requiredConcepts": ["dog shampoo", "ingredient analysis", "customer satisfaction"],
                    "requiredInteractions": ["filterByTimePeriod", "drillDownIntoData", "highlightKeyInsights"],
                    "visualTone": ["informative"],
                    "factualAnchors": ["customer feedback by channel"],
                    "styleDirectives": ["clear hierarchy"],
                    "referenceHints": []
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-brief-identifier-normalizer".to_string(),
            model: Some("fixture-brief-identifier-normalizer".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioBriefQualityRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefQualityRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact brief repairer") {
            (
                "brief-repair",
                serde_json::json!({
                    "audience": "Instacart operators",
                    "jobToBeDone": "explain the rollout through inspectable evidence",
                    "subjectDomain": "Instacart MCP launch rollout",
                    "artifactThesis": "Explain the Instacart MCP rollout through evidence-rich launch views.",
                    "requiredConcepts": ["Instacart MCP", "channel adoption", "launch sequencing"],
                    "requiredInteractions": ["view switching", "detail comparison"],
                    "visualTone": ["grounded"],
                    "factualAnchors": ["merchant onboarding by channel"],
                    "styleDirectives": ["clear hierarchy"],
                    "referenceHints": ["launch readiness checkpoints"]
                }),
            )
        } else if prompt.contains("typed artifact brief planner") {
            (
                "brief",
                serde_json::json!({
                    "audience": "Instacart operators",
                    "jobToBeDone": "explain the rollout through charts",
                    "subjectDomain": "Instacart MCP rollout",
                    "artifactThesis": "Explain the rollout through an interactive artifact.",
                    "requiredConcepts": ["Instacart MCP", "product rollout", "charts"],
                    "requiredInteractions": ["interactive", "explains"],
                    "visualTone": ["grounded"],
                    "factualAnchors": [],
                    "styleDirectives": ["clear hierarchy"],
                    "referenceHints": []
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-brief-quality-repair".to_string(),
            model: Some("fixture-brief-quality-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioBriefFieldRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefFieldRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact brief field repairer") {
            (
                "brief-field-repair",
                serde_json::json!({
                    "audience": "AI editorial readers",
                    "jobToBeDone": "understand the launch story through inspectable sections",
                    "subjectDomain": "AI tools editorial launch page",
                    "artifactThesis": "Present an editorial launch page for AI tools with visible evidence-rich interaction points.",
                    "requiredConcepts": ["AI tools", "editorial launch", "launch page"],
                    "requiredInteractions": ["section jumping", "detail comparison"],
                    "visualTone": ["editorial"],
                    "factualAnchors": ["launch themes and editorial callouts"],
                    "styleDirectives": ["clear hierarchy"],
                    "referenceHints": ["launch page narrative structure"]
                }),
            )
        } else if prompt.contains("typed artifact brief repairer") {
            (
                "brief-repair",
                serde_json::json!({
                    "audience": "",
                    "jobToBeDone": "",
                    "subjectDomain": "",
                    "artifactThesis": "",
                    "requiredConcepts": [],
                    "requiredInteractions": [],
                    "visualTone": [],
                    "factualAnchors": [],
                    "styleDirectives": [],
                    "referenceHints": []
                }),
            )
        } else if prompt.contains("typed artifact brief planner") {
            (
                "brief",
                serde_json::json!({
                    "audience": "",
                    "jobToBeDone": "",
                    "subjectDomain": "",
                    "artifactThesis": "",
                    "requiredConcepts": [],
                    "requiredInteractions": [],
                    "visualTone": [],
                    "factualAnchors": [],
                    "styleDirectives": [],
                    "referenceHints": []
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-brief-field-repair".to_string(),
            model: Some("fixture-brief-field-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioEditIntentRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioEditIntentRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact edit-intent repairer") {
            (
                "edit-repair",
                serde_json::json!({
                    "mode": "patch",
                    "summary": "Patch the chart section while preserving the artifact structure.",
                    "patchExistingArtifact": true,
                    "preserveStructure": true,
                    "targetScope": "chart section",
                    "targetPaths": ["index.html"],
                    "requestedOperations": ["replace chart data", "update detail copy"],
                    "toneDirectives": ["technical"],
                    "selectedTargets": [{
                        "sourceSurface": "render",
                        "path": "index.html",
                        "label": "chart section",
                        "snippet": "Hero chart section should show adoption by channel."
                    }],
                    "styleDirectives": ["retain current palette"],
                    "branchRequested": false
                }),
            )
        } else if prompt.contains("typed artifact edit-intent planner") {
            (
                "edit",
                serde_json::json!({
                    "mode": "patch",
                    "summary": "Patch the chart section while preserving the artifact structure.",
                    "patchExistingArtifact": true,
                    "preserveStructure": true,
                    "targetScope": "chart section",
                    "targetPaths": "index.html",
                    "requestedOperations": ["replace chart data", "update detail copy"],
                    "toneDirectives": ["technical"],
                    "selectedTargets": [{
                        "sourceSurface": "render",
                        "path": "index.html",
                        "label": "chart section",
                        "snippet": "Hero chart section should show adoption by channel."
                    }],
                    "styleDirectives": ["retain current palette"],
                    "branchRequested": false
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-edit-intent-repair".to_string(),
            model: Some("fixture-edit-intent-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioEditIntentMissingJsonRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioEditIntentMissingJsonRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact edit-intent repairer") {
            (
                "edit-repair",
                serde_json::json!({
                    "mode": "patch",
                    "summary": "Patch the enterprise framing while preserving structure.",
                    "patchExistingArtifact": true,
                    "preserveStructure": true,
                    "targetScope": "overall artifact tone",
                    "targetPaths": ["index.html"],
                    "requestedOperations": ["tighten enterprise language", "preserve channel evidence"],
                    "toneDirectives": ["enterprise"],
                    "selectedTargets": [],
                    "styleDirectives": ["retain layout"],
                    "branchRequested": false
                })
                .to_string(),
            )
        } else if prompt.contains("typed artifact edit-intent planner") {
            (
                "edit",
                "Patch the enterprise framing while preserving the current structure.".to_string(),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-edit-intent-missing-json".to_string(),
            model: Some("fixture-edit-intent-missing-json".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioRefinementRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioRefinementRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact refinement repairer") {
            (
                "refine-repair",
                serde_json::json!({
                    "summary": "Refined dog shampoo rollout",
                    "notes": ["schema-repaired refinement"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Ingredient analysis, customer satisfaction, and usage statistics stay visible on first paint.</p><button type=\"button\" data-view=\"ingredients\">Ingredients</button><button type=\"button\" data-view=\"satisfaction\">Satisfaction</button><button type=\"button\" data-view=\"usage\">Usage</button></section><section data-view-panel=\"ingredients\"><article class=\"chart\"><h2>Rollout evidence</h2><svg viewBox=\"0 0 260 140\" role=\"img\" aria-label=\"Dog shampoo rollout evidence\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" data-detail=\"Ingredient analysis\"></rect><rect x=\"94\" y=\"36\" width=\"42\" height=\"80\" data-detail=\"Customer satisfaction\"></rect><rect x=\"164\" y=\"28\" width=\"42\" height=\"88\" data-detail=\"Usage statistics\"></rect><text x=\"24\" y=\"132\">Ingredients</text><text x=\"94\" y=\"132\">Satisfaction</text><text x=\"164\" y=\"132\">Usage</text></svg></article></section><section><article><h2>Customer satisfaction snapshot</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Satisfaction</td><td>4.8 / 5</td></tr><tr><td>Repeat purchase</td><td>31%</td></tr></table></article></section><section data-view-panel=\"satisfaction\" hidden><article><h2>Customer satisfaction</h2><p>Customer satisfaction detail stays available here.</p></article></section><section data-view-panel=\"usage\" hidden><article><h2>Usage statistics</h2><p>Usage statistics detail stays available here.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Ingredient analysis is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=`${button.dataset.view} selected for dog shampoo rollout review.`;}));document.querySelectorAll('svg [data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=`Hover detail: ${mark.dataset.detail}`;});mark.addEventListener('focus',()=>{detail.textContent=`Focus detail: ${mark.dataset.detail}`;});});</script></main></body></html>"
                    }]
                }),
            )
        } else if prompt.contains("typed artifact refiner") {
            (
                "refine",
                serde_json::json!({
                    "summary": "Broken refinement",
                    "notes": ["invalid refinement candidate"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": serde_json::Value::Null
                    }]
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-refine-repair".to_string(),
            model: Some("fixture-refine-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioJudgeRepairTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioJudgeRepairTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let (stage, response) = if prompt.contains("typed artifact judge repairer") {
            (
                "judge-repair",
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
                    "deservesPrimaryArtifactView": true,
                    "patchedExistingArtifact": null,
                    "continuityRevisionUx": null,
                    "strongestContradiction": null,
                    "rationale": "Repaired judge output."
                }),
            )
        } else if prompt.contains("typed artifact judge") {
            (
                "judge",
                serde_json::json!({
                    "classification": "pass",
                    "requestFaithfulness": 6,
                    "conceptCoverage": 4,
                    "interactionRelevance": 3,
                    "layoutCoherence": 4,
                    "visualHierarchy": 4,
                    "completeness": 4,
                    "genericShellDetected": false,
                    "trivialShellDetected": false,
                    "deservesPrimaryArtifactView": true,
                    "patchedExistingArtifact": null,
                    "continuityRevisionUx": null,
                    "strongestContradiction": null,
                    "rationale": "Invalid judge output."
                }),
            )
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };

        self.calls
            .lock()
            .expect("calls lock")
            .push(stage.to_string());
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture://studio-judge-repair".to_string(),
            model: Some("fixture-judge-repair".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioAcceptanceRetryTestRuntime {
    provenance: StudioRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl StudioAcceptanceRetryTestRuntime {
    fn new(
        kind: StudioRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            provenance: StudioRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
            role,
            calls,
        }
    }
}

#[async_trait]
impl InferenceRuntime for StudioAcceptanceRetryTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else if prompt.contains("typed artifact judge") {
            "judge"
        } else {
            "unknown"
        };
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{stage}", self.role));

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "operators",
                "jobToBeDone": "explain the rollout",
                "subjectDomain": "rollout planning",
                "artifactThesis": "show the launch plan clearly",
                "requiredConcepts": ["rollout timeline", "launch owners", "readiness checkpoints"],
                "requiredInteractions": ["chart toggle", "detail comparison"],
                "visualTone": ["confident"],
                "factualAnchors": ["launch checkpoint review"],
                "styleDirectives": [],
                "referenceHints": []
            }),
            "materialize" => {
                let candidate_id = if prompt.contains("\"candidateId\":\"candidate-1\"") {
                    "candidate-1"
                } else if prompt.contains("\"candidateId\":\"candidate-2\"") {
                    "candidate-2"
                } else {
                    "candidate-3"
                };
                serde_json::json!({
                    "summary": format!("{candidate_id} payload"),
                    "notes": [format!("{candidate_id} request-grounded candidate")],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": format!(
                            "<!doctype html><html><body><main><section><h1>{candidate_id}</h1><p>Inspect the rollout owners and timeline.</p><button type=\"button\" data-view=\"timeline\">Timeline</button><button type=\"button\" data-view=\"owners\">Owners</button></section><section data-view-panel=\"timeline\"><article class=\"chart\"><h2>Timeline evidence</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"{candidate_id} rollout timeline\"><rect x=\"20\" y=\"52\" width=\"40\" height=\"56\"></rect><rect x=\"90\" y=\"36\" width=\"40\" height=\"72\"></rect><text x=\"20\" y=\"118\">Plan</text><text x=\"90\" y=\"118\">Ship</text></svg></article></section><section data-view-panel=\"owners\" hidden><article><h2>Owners</h2><ul><li>Operations lead</li><li>Merchandising owner</li></ul></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Timeline is selected by default for {candidate_id}.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{{panels.forEach((panel)=>{{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;}});detail.textContent=button.dataset.view + ' selected for {candidate_id}.';}}));</script></main></body></html>"
                        )
                    }]
                })
            }
            "judge" => {
                if self.role == "acceptance" {
                    if prompt.contains("candidate-1 payload") {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 3,
                            "conceptCoverage": 3,
                            "interactionRelevance": 3,
                            "layoutCoherence": 3,
                            "visualHierarchy": 3,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": false,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "still too thin",
                            "rationale": "Acceptance downgraded candidate-1."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 5,
                            "conceptCoverage": 5,
                            "interactionRelevance": 4,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 4,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Acceptance cleared the fallback candidate."
                        })
                    }
                } else if prompt.contains("candidate-1 payload") {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 5,
                        "conceptCoverage": 5,
                        "interactionRelevance": 5,
                        "layoutCoherence": 5,
                        "visualHierarchy": 5,
                        "completeness": 5,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "Production prefers candidate-1 first."
                    })
                } else if prompt.contains("candidate-2 payload") {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 4,
                        "conceptCoverage": 4,
                        "interactionRelevance": 4,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 4,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "Production likes candidate-2."
                    })
                } else {
                    serde_json::json!({
                        "classification": "repairable",
                        "requestFaithfulness": 3,
                        "conceptCoverage": 3,
                        "interactionRelevance": 3,
                        "layoutCoherence": 3,
                        "visualHierarchy": 3,
                        "completeness": 3,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": false,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": "weak fallback",
                        "rationale": "Production downgraded candidate-3."
                    })
                }
            }
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[tokio::test]
async fn route_planning_canonicalizes_html_contract_fields() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioOutcomeTestRuntime {
            payload: r#"{
              "outcomeKind":"artifact",
              "confidence":0.88,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":{
                "artifactClass":"interactive_single_file",
                "deliverableShape":"single_file",
                "renderer":"html_iframe",
                "presentationSurface":"inline",
                "persistence":"artifact_scoped",
                "executionSubstrate":"workspace_runtime",
                "workspaceRecipeId":"vite-static-html",
                "presentationVariantId":"product-launch",
                "scope":{"targetProject":null,"createNewWorkspace":true,"mutationBoundary":[]},
                "verification":{"requireRender":true,"requireBuild":true,"requirePreview":true,"requireExport":true,"requireDiffReview":true}
              }
            }"#
            .to_string(),
        });

    let planned = plan_studio_outcome_with_runtime(
        runtime,
        "Create an interactive HTML artifact for a launch page",
        None,
        None,
    )
    .await
    .expect("route planning should parse");

    let artifact = planned.artifact.expect("artifact request");
    assert_eq!(artifact.renderer, StudioRendererKind::HtmlIframe);
    assert_eq!(
        artifact.artifact_class,
        StudioArtifactClass::InteractiveSingleFile
    );
    assert_eq!(
        artifact.deliverable_shape,
        StudioArtifactDeliverableShape::SingleFile
    );
    assert_eq!(
        artifact.presentation_surface,
        StudioPresentationSurface::SidePanel
    );
    assert_eq!(
        artifact.persistence,
        StudioArtifactPersistenceMode::SharedArtifactScoped
    );
    assert_eq!(
        artifact.execution_substrate,
        StudioExecutionSubstrate::ClientSandbox
    );
    assert!(artifact.workspace_recipe_id.is_none());
    assert!(!artifact.scope.create_new_workspace);
    assert_eq!(
        artifact.scope.mutation_boundary,
        vec!["artifact".to_string()]
    );
    assert!(!artifact.verification.require_build);
    assert!(!artifact.verification.require_preview);
    assert!(!artifact.verification.require_diff_review);
}

#[tokio::test]
async fn generate_bundle_uses_distinct_acceptance_runtime_for_judging() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "llama3.1",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
        "remote acceptance",
        "gpt-4.1",
        "https://api.openai.com/v1/chat/completions",
        "acceptance",
        calls.clone(),
    ));

    let bundle = generate_studio_artifact_bundle_with_runtimes(
        production_runtime,
        acceptance_runtime,
        "Rollout artifact",
        "Create an interactive rollout artifact",
        &request_for(
            StudioArtifactClass::Document,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("bundle should generate");

    assert_eq!(
        bundle.production_provenance.kind,
        StudioRuntimeProvenanceKind::RealLocalRuntime
    );
    assert_eq!(
        bundle.acceptance_provenance.kind,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime
    );
    assert_eq!(bundle.judge.rationale, "judged by acceptance");
    assert!(bundle.candidate_summaries.iter().all(|candidate| candidate
        .provenance
        .as_ref()
        .is_some_and(
            |provenance| provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        )));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert!(recorded_calls.iter().any(|call| call == "production:brief"));
    assert!(recorded_calls
        .iter()
        .any(|call| call == "production:materialize"));
    assert!(recorded_calls.iter().any(|call| call == "production:judge"));
    assert!(recorded_calls.iter().any(|call| call == "acceptance:judge"));
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:judge")
            .count(),
        2
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:judge")
            .count(),
        1
    );
}

#[tokio::test]
async fn materialization_repair_recovers_schema_invalid_candidate() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioRepairTestRuntime {
        calls: calls.clone(),
    });

    let payload = materialize_studio_artifact_candidate_with_runtime(
        runtime,
        "AI tools editorial launch",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
            audience: "readers".to_string(),
            job_to_be_done: "introduce the launch".to_string(),
            subject_domain: "AI tools editorial".to_string(),
            artifact_thesis: "highlight the editorial launch".to_string(),
            required_concepts: vec!["ai tools".to_string(), "editorial launch".to_string()],
            required_interactions: vec![],
            visual_tone: vec!["editorial".to_string()],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        None,
        None,
        "candidate-1",
        42,
        0.55,
    )
    .await
    .expect("schema repair should recover the candidate");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0].body.contains("AI Tools Editorial Launch"));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["materialize", "repair"]);
}

#[tokio::test]
async fn materialization_repair_recovers_raw_html_missing_json_candidate() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioRawHtmlRepairTestRuntime {
        calls: calls.clone(),
    });

    let payload = materialize_studio_artifact_candidate_with_runtime(
        runtime,
        "Dog shampoo rollout",
        "Make it feel more enterprise",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
            audience: "enterprise operators".to_string(),
            job_to_be_done: "review the enterprise rollout framing".to_string(),
            subject_domain: "dog shampoo enterprise launch".to_string(),
            artifact_thesis: "Patch the rollout artifact toward enterprise positioning."
                .to_string(),
            required_concepts: vec![
                "dog shampoo".to_string(),
                "enterprise".to_string(),
                "adoption by channel".to_string(),
            ],
            required_interactions: vec![
                "clickable navigation between different views".to_string(),
                "rollover effects for chart elements".to_string(),
            ],
            visual_tone: vec!["enterprise".to_string()],
            factual_anchors: vec!["channel adoption".to_string()],
            style_directives: vec!["preserve structure".to_string()],
            reference_hints: Vec::new(),
        },
        None,
        Some(&StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact summary".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>".to_string(),
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
        "candidate-1",
        42,
        0.55,
    )
    .await
    .expect("raw html repair should recover the candidate");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0].body.contains("enterprise brief"));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["materialize", "repair"]);
}

#[tokio::test]
async fn materialization_repair_accepts_normalized_html_near_miss_on_first_repair() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioSecondRepairTestRuntime {
        calls: calls.clone(),
    });

    let payload = materialize_studio_artifact_candidate_with_runtime(
        runtime,
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
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
                "product rollout".to_string(),
                "customer satisfaction".to_string(),
                "usage statistics".to_string(),
                "ingredient analysis".to_string(),
            ],
            required_interactions: vec![
                "rollover effects for chart elements".to_string(),
                "clickable navigation between different types of charts".to_string(),
            ],
            visual_tone: vec![
                "informative".to_string(),
                "professional".to_string(),
                "user-friendly".to_string(),
            ],
            factual_anchors: vec![
                "clinical trials data".to_string(),
                "customer feedback".to_string(),
                "sales performance metrics".to_string(),
            ],
            style_directives: vec![
                "clear and concise language".to_string(),
                "use of color to highlight key points".to_string(),
                "interactive elements should be intuitive".to_string(),
            ],
            reference_hints: vec![
                "charts showing pH levels, ingredient breakdowns, before-and-after condition comparisons"
                    .to_string(),
            ],
        },
        None,
        None,
        "candidate-1",
        42,
        0.55,
    )
    .await
    .expect("first repair should recover the normalized candidate");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0].body.contains("Customer satisfaction"));
    assert!(payload.files[0].body.contains("data-detail"));
    assert!(payload.files[0]
        .body
        .contains("data-studio-rollover-repair"));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["materialize", "repair-1"]);
}

#[tokio::test]
async fn brief_repair_recovers_scalar_array_mismatch() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioBriefRepairTestRuntime {
        calls: calls.clone(),
    });

    let brief = plan_studio_artifact_brief_with_runtime(
            runtime,
            "Dog shampoo rollout",
            "Create an interactive HTML artifact that explains a dog shampoo product rollout with charts for ingredient analysis, customer satisfaction, usage statistics, rollover details, and clickable navigation between views.",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            None,
        )
        .await
        .expect("brief repair should recover the brief");

    assert_eq!(brief.visual_tone, vec!["informative".to_string()]);
    assert!(brief.required_concepts.contains(&"dog shampoo".to_string()));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["brief"]);
}

#[tokio::test]
async fn brief_planner_normalizes_identifier_style_interactions_without_repair() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioBriefIdentifierInteractionTestRuntime {
            calls: calls.clone(),
        });

    let brief = plan_studio_artifact_brief_with_runtime(
        runtime,
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a dog shampoo product rollout with charts for ingredient analysis, customer satisfaction, and usage statistics.",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("brief planning should normalize identifier-shaped interactions");

    assert_eq!(
        brief.required_interactions,
        vec![
            "filter by time period to update the visible chart and detail panel".to_string(),
            "drill down into data to update the visible chart and detail panel".to_string(),
            "highlight key insights to update the visible chart and detail panel".to_string(),
        ]
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["brief"]);
}

#[tokio::test]
async fn brief_repair_recovers_vague_html_interactions_and_missing_evidence() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioBriefQualityRepairTestRuntime {
        calls: calls.clone(),
    });

    let brief = plan_studio_artifact_brief_with_runtime(
        runtime,
        "Instacart MCP rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("brief repair should recover the brief");

    assert_eq!(
        brief.required_interactions,
        vec![
            "view switching".to_string(),
            "detail comparison".to_string()
        ]
    );
    assert_eq!(
        brief.factual_anchors,
        vec!["merchant onboarding by channel".to_string()]
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["brief", "brief-repair"]);
}

#[tokio::test]
async fn brief_field_repair_recovers_empty_core_fields() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioBriefFieldRepairTestRuntime {
        calls: calls.clone(),
    });

    let brief = plan_studio_artifact_brief_with_runtime(
        runtime,
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("brief field repair should recover the brief");

    assert_eq!(brief.subject_domain, "AI tools editorial launch page");
    assert_eq!(
        brief.required_interactions,
        vec![
            "section jumping".to_string(),
            "detail comparison".to_string()
        ]
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls,
        vec!["brief", "brief-repair", "brief-field-repair"]
    );
}

#[tokio::test]
async fn edit_intent_repair_recovers_scalar_array_mismatch() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioEditIntentRepairTestRuntime {
        calls: calls.clone(),
    });

    let edit_intent = plan_studio_artifact_edit_intent_with_runtime(
        runtime,
        "Edit only this chart section to show adoption by channel.",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "inspect the rollout".to_string(),
            subject_domain: "dog shampoo launch".to_string(),
            artifact_thesis: "Show the launch plan clearly.".to_string(),
            required_concepts: vec!["channel adoption".to_string()],
            required_interactions: vec!["chart toggle".to_string()],
            visual_tone: vec!["technical".to_string()],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        &StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![],
            selected_targets: vec![StudioArtifactSelectionTarget {
                source_surface: "render".to_string(),
                path: Some("index.html".to_string()),
                label: "chart section".to_string(),
                snippet: "Hero chart section should show adoption by channel.".to_string(),
            }],
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
    )
    .await
    .expect("edit-intent repair should recover the intent");

    assert_eq!(edit_intent.mode, StudioArtifactEditMode::Patch);
    assert_eq!(edit_intent.target_paths, vec!["index.html".to_string()]);
    assert!(edit_intent.patch_existing_artifact);

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["edit"]);
}

#[tokio::test]
async fn edit_intent_repair_recovers_missing_json_payload() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioEditIntentMissingJsonRepairTestRuntime {
            calls: calls.clone(),
        });

    let edit_intent = plan_studio_artifact_edit_intent_with_runtime(
        runtime,
        "Make it feel more enterprise",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "refine the rollout".to_string(),
            subject_domain: "dog shampoo launch".to_string(),
            artifact_thesis: "Show the launch plan clearly.".to_string(),
            required_concepts: vec!["enterprise".to_string()],
            required_interactions: vec!["chart toggle".to_string()],
            visual_tone: vec!["technical".to_string()],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        &StudioArtifactRefinementContext {
            artifact_id: Some("artifact-1".to_string()),
            revision_id: Some("revision-1".to_string()),
            title: "Dog shampoo rollout".to_string(),
            summary: "Current artifact state".to_string(),
            renderer: StudioRendererKind::HtmlIframe,
            files: vec![],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
    )
    .await
    .expect("edit-intent repair should recover missing JSON output");

    assert_eq!(edit_intent.mode, StudioArtifactEditMode::Patch);
    assert!(edit_intent.patch_existing_artifact);
    assert!(edit_intent.preserve_structure);

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["edit", "edit-repair"]);
}

#[tokio::test]
async fn refinement_repair_recovers_schema_invalid_candidate() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioRefinementRepairTestRuntime {
        calls: calls.clone(),
    });

    let payload = refine_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
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
                    "product rollout".to_string(),
                    "customer satisfaction".to_string(),
                    "usage statistics".to_string(),
                    "ingredient analysis".to_string(),
                ],
                required_interactions: vec![
                    "rollover effects for chart elements".to_string(),
                    "clickable navigation between different types of charts".to_string(),
                ],
                visual_tone: vec![
                    "informative".to_string(),
                    "professional".to_string(),
                    "user-friendly".to_string(),
                ],
                factual_anchors: vec![
                    "clinical trials data".to_string(),
                    "customer feedback".to_string(),
                    "sales performance metrics".to_string(),
                ],
                style_directives: vec![
                    "clear and concise language".to_string(),
                    "use of color to highlight key points".to_string(),
                    "interactive elements should be intuitive".to_string(),
                ],
                reference_hints: vec![
                    "charts showing pH levels, ingredient breakdowns, before-and-after condition comparisons".to_string(),
                ],
            },
            None,
            None,
            &[],
            &[],
            None,
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Interactive HTML artifact explaining a new dog shampoo product rollout with charts and data visualizations.".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Initial chart draft.</p></section><article><svg width=\"300\" height=\"200\"><rect x=\"20\" y=\"50\" width=\"40\" height=\"100\"></rect></svg></article><footer><p>Needs better interactions.</p></footer></main></body></html>".to_string(),
                }],
            },
            &StudioArtifactJudgeResult {
                classification: StudioArtifactJudgeClassification::Repairable,
                request_faithfulness: 3,
                concept_coverage: 4,
                interaction_relevance: 2,
                layout_coherence: 4,
                visual_hierarchy: 4,
                completeness: 3,
                generic_shell_detected: false,
                trivial_shell_detected: false,
                deserves_primary_artifact_view: false,
                patched_existing_artifact: None,
                continuity_revision_ux: None,
                issue_classes: vec!["interaction_truthfulness".to_string()],
                repair_hints: vec![
                    "Wire rollover detail and view switching into pre-rendered evidence panels."
                        .to_string(),
                ],
                strengths: vec!["Concept coverage is already respectable.".to_string()],
                blocked_reasons: Vec::new(),
                file_findings: vec!["index.html: interactions do not cover both requested modes."
                    .to_string()],
                aesthetic_verdict: "Layout is readable but still underpowered for an interactive artifact."
                    .to_string(),
                interaction_verdict:
                    "The evidence surface lacks the requested rollover and clickable comparison behaviors."
                        .to_string(),
                truthfulness_warnings: Vec::new(),
                recommended_next_pass: Some("structural_repair".to_string()),
                strongest_contradiction: Some(
                    "Charts lack rollover effects and clickable navigation.".to_string(),
                ),
                rationale: "Candidate covers concepts but lacks interactive features."
                    .to_string(),
            },
            "candidate-1-refine-1",
            42,
            0.18,
        )
        .await
        .expect("refinement repair should recover the candidate");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0]
        .body
        .contains("Ingredient analysis, customer satisfaction, and usage statistics"));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["refine", "refine-repair"]);
}

#[tokio::test]
async fn judge_repair_recovers_out_of_range_scores() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioJudgeRepairTestRuntime {
        calls: calls.clone(),
    });

    let result = judge_studio_artifact_candidate_with_runtime(
        runtime,
        "Release checklist",
        &request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "document the checklist".to_string(),
            subject_domain: "release checklist".to_string(),
            artifact_thesis: "capture the release steps".to_string(),
            required_concepts: vec!["release".to_string(), "checklist".to_string()],
            required_interactions: vec![],
            visual_tone: vec!["clear".to_string()],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        None,
        &StudioGeneratedArtifactPayload {
            summary: "Release checklist".to_string(),
            notes: vec![],
            files: vec![StudioGeneratedArtifactFile {
                path: "checklist.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "# Release checklist\n\n- Cut release branch".to_string(),
            }],
        },
    )
    .await
    .expect("judge repair should recover the judgment");

    assert_eq!(result.request_faithfulness, 5);
    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Pass
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["judge"]);
}

#[tokio::test]
async fn judge_contract_downgrades_empty_svg_placeholder_shells() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec!["channel adoption".to_string(), "launch steps".to_string()],
                required_interactions: vec!["chart inspection".to_string()],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Channel metrics and launch steps stay visible.</p></section><article><button type=\"button\">Show adoption</button><svg width=\"400\" height=\"220\"><!-- chart data goes here --></svg></article><footer><p>Operators can review readiness inline.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade empty SVG shells");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML chart regions are empty placeholder shells on first paint.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_empty_chart_container_shells() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec!["channel adoption".to_string(), "launch steps".to_string()],
                required_interactions: vec!["chart inspection".to_string()],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Channel metrics and launch steps stay visible.</p></section><article><button type=\"button\">Show adoption</button><article id=\"conditionComparisonChart\"></article><article id=\"ingredientBreakdownChart\"><!-- chart fills later --></article></article><footer><p>Operators can review readiness inline.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade empty chart containers");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML chart containers are empty placeholder shells on first paint.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_unlabeled_chart_svg_shells() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec!["channel adoption".to_string(), "launch steps".to_string()],
                required_interactions: vec!["chart inspection".to_string()],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Channel metrics and launch steps stay visible.</p></section><article class=\"chart\"><button type=\"button\">Show adoption</button><svg width=\"400\" height=\"220\"><circle cx=\"120\" cy=\"110\" r=\"82\" stroke=\"#335\" stroke-width=\"18\" fill=\"none\"></circle><circle cx=\"120\" cy=\"110\" r=\"56\" stroke=\"#7aa\" stroke-width=\"18\" fill=\"none\"></circle></svg></article><footer><p>Operators can review readiness inline.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade unlabeled chart SVG shells");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML chart SVG regions are unlabeled on first paint.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_html_with_placeholder_comments_and_missing_target_ids() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec!["channel adoption".to_string(), "launch steps".to_string()],
                required_interactions: vec!["chart toggle".to_string()],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Explain the Key Features and Benefits of a New Dog Shampoo Through Interactive Charts and Data Visualizations</h1></section><section class=\"controls\"><button id=\"chart1\" class=\"control\">Chart 1: pH Levels</button><button id=\"chart2\" class=\"control\">Chart 2: Ingredient Breakdowns</button><button id=\"chart3\" class=\"control\">Chart 3: Before & After Condition Comparisons</button></section><section><div id=\"chart1-container\"><svg width=\"500\" height=\"300\" viewBox=\"0 0 500 300\"><!-- Placeholder SVG content for Chart 1 --><rect x=\"100\" y=\"100\" width=\"80\" height=\"100\" fill=\"#ffd700\"></rect></svg></div></section><aside id=\"detail-panel\"><h2>Product Rollout Details</h2><p>Key benefits and performance metrics for the new dog shampoo.</p></aside></main><script>const chartContainers=document.querySelectorAll('#chart1-container, #chart2-container, #chart3-container');document.getElementById('chart2').addEventListener('click',()=>{chartContainers.forEach((container)=>container.style.display='none');document.getElementById('chart2-container').style.display='flex';});</script></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade placeholder comments and missing target ids");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML still contains placeholder-grade copy or comments on first paint.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_html_with_empty_shared_detail_regions() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec!["channel adoption".to_string(), "launch steps".to_string()],
                required_interactions: vec!["chart toggle".to_string()],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Compare launch readiness, channel adoption, and formula proof points.</p><button type=\"button\" id=\"retail\">Retail</button><button type=\"button\" id=\"subscription\">Subscription</button></section><section><article class=\"chart\"><h2>Channel adoption</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo adoption chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><rect x=\"88\" y=\"34\" width=\"40\" height=\"66\"></rect><text x=\"20\" y=\"114\">Retail</text><text x=\"88\" y=\"114\">Subscription</text></svg><p>Retail stays selected by default.</p></article></section><aside id=\"detail-panel\"><h2>Comparison detail</h2><!-- default detail arrives later --></aside></main><script>const detail=document.getElementById('detail-panel');document.getElementById('retail').addEventListener('click',()=>{detail.dataset.view='retail';});document.getElementById('subscription').addEventListener('click',()=>{detail.dataset.view='subscription';});</script></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade empty shared detail regions");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML shared detail or comparison regions are empty on first paint.")
    );
}

#[test]
fn rejects_html_payloads_with_empty_sectioning_shells() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
            summary: "Dog shampoo rollout artifact".to_string(),
            notes: vec![],
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section id=\"hero\"></section><section id=\"scenario\"></section><aside id=\"evidence\"></aside><details><summary>Inspect supporting detail</summary><p>Inline detail.</p></details></main></body></html>".to_string(),
            }],
        };

    let error = validate_generated_artifact_payload(&payload, &request)
        .expect_err("empty section shells should fail validation");
    assert!(error.contains("sectioning elements with first-paint content"));
}

#[test]
fn materialization_keeps_soft_html_quality_failures_available_for_judging() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout artifact",
            "notes": [],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": false,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing and channel metrics stay visible.</p></section><article><button type=\"button\">Show adoption</button><article id=\"conditionComparisonChart\"></article><article id=\"ingredientBreakdownChart\"><!-- chart fills later --></article></article><footer><p>Readiness owners stay visible.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("soft HTML quality failures should stay available for judging");
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("soft validation")));
}

#[test]
fn materialization_keeps_navigation_only_html_failures_available_for_judging() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
            "summary": "Instacart rollout artifact",
            "notes": [],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": false,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Instacart rollout</h1><button type=\"button\" id=\"eng\">Engineering</button></section><section><h2>Timeline</h2><p>Inspect the rollout phases.</p></section><aside><h2>Dependencies</h2><p>Review launch blockers.</p></aside><script>document.getElementById('eng').addEventListener('click',()=>{document.querySelector('aside').scrollIntoView();console.info('eng');});</script></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("navigation-only HTML failures should stay available for judging");
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("soft validation")));
}

#[test]
fn brief_aware_validation_requires_detail_panel_for_interactive_html() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect adoption and launch sequencing.</p><button type=\"button\">Sales</button><button type=\"button\">Reviews</button></section><section><article class=\"chart\"><h2>Sales performance</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"Sales performance\"><rect x=\"24\" y=\"52\" width=\"40\" height=\"56\"></rect><rect x=\"94\" y=\"36\" width=\"40\" height=\"72\"></rect><text x=\"24\" y=\"118\">Retail</text><text x=\"94\" y=\"118\">Subscription</text></svg></article></section><footer><p>Inspect the rollout evidence inline.</p></footer></main><script>document.querySelectorAll('button').forEach((button)=>button.addEventListener('click',()=>{button.classList.toggle('active');}));</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec!["dog shampoo".to_string(), "sales".to_string()],
        required_interactions: vec![
            "view switching".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("interactive html should need a populated detail panel");
    assert!(error.contains("required interactions must include a populated shared detail"));
}

#[test]
fn brief_aware_validation_requires_structured_secondary_evidence_for_charted_briefs() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "AI tools editorial launch artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Inspect research trends and launch applications.</p><button type=\"button\" data-view=\"research\" aria-controls=\"research-panel\" aria-selected=\"true\">Latest AI research trends</button><button type=\"button\" data-view=\"applications\" aria-controls=\"applications-panel\">Industry-standard AI tool applications</button></section><section id=\"research-panel\" data-view-panel=\"research\"><article><h2>Research momentum</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"Research momentum chart\"><rect x=\"20\" y=\"52\" width=\"36\" height=\"48\"></rect><rect x=\"84\" y=\"36\" width=\"36\" height=\"64\"></rect><rect x=\"148\" y=\"24\" width=\"36\" height=\"76\"></rect><text x=\"20\" y=\"114\">Labs</text><text x=\"84\" y=\"114\">Deploy</text><text x=\"148\" y=\"114\">Spend</text></svg></article></section><section id=\"applications-panel\" data-view-panel=\"applications\" hidden><article><h2>Industry-standard AI tool applications</h2><p>Industry-standard AI tool applications include copilots across sales, support, and operations.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Latest AI research trends are selected by default.</p></aside><footer><p>Use the controls to inspect the editorial evidence.</p></footer></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.textContent + ' selected.';}));</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "AI tools users".to_string(),
        job_to_be_done: "review the launch".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show the editorial launch evidence clearly".to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "interactive features".to_string(),
        ],
        required_interactions: vec![
            "tool demonstration to update the visible chart and detail panel".to_string(),
            "user feedback collection to update the visible chart and detail panel".to_string(),
        ],
        visual_tone: vec!["modern".to_string(), "innovative".to_string()],
        factual_anchors: vec![
            "latest AI research trends".to_string(),
            "industry-standard AI tool applications".to_string(),
        ],
        style_directives: vec![],
        reference_hints: vec![
            "interactive product demos".to_string(),
            "real-time user feedback mechanisms".to_string(),
        ],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("charted briefs should require structured secondary evidence");
    assert!(error.contains("charted evidence must surface at least two populated evidence views"));
}

#[test]
fn brief_aware_validation_allows_selection_scoped_chart_patch_to_preserve_other_evidence() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo targeted chart patch".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect adoption by channel inside the existing artifact.</p><button type=\"button\" data-view=\"launch\" aria-controls=\"launch-panel\">Launch</button><button type=\"button\" data-view=\"adoption\" aria-controls=\"adoption-panel\">Adoption</button></section><section id=\"launch-panel\" data-view-panel=\"launch\"><article><h2>Channel adoption</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"Channel adoption chart\"><rect x=\"20\" y=\"48\" width=\"36\" height=\"52\" tabindex=\"0\" data-detail=\"Retail adoption\"></rect><rect x=\"84\" y=\"36\" width=\"36\" height=\"64\" tabindex=\"0\" data-detail=\"Subscription adoption\"></rect><rect x=\"148\" y=\"24\" width=\"36\" height=\"76\" tabindex=\"0\" data-detail=\"Vet channel adoption\"></rect><text x=\"20\" y=\"114\">Retail</text><text x=\"84\" y=\"114\">Subscription</text><text x=\"148\" y=\"114\">Vet</text></svg></article></section><section id=\"adoption-panel\" data-view-panel=\"adoption\"><article><h2>Existing comparison view</h2><p>Untouched comparison content remains in the current artifact outside the targeted chart edit.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Retail adoption is selected by default.</p></aside></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.textContent + ' selected.';}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "channel adoption".to_string(),
            "launch evidence".to_string(),
        ],
        required_interactions: vec![
            "clickable navigation between different chart views".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["technical".to_string()],
        factual_anchors: vec!["channel adoption by launch phase".to_string()],
        style_directives: vec![],
        reference_hints: vec!["existing comparison view".to_string()],
    };
    let edit_intent = StudioArtifactEditIntent {
        mode: StudioArtifactEditMode::Patch,
        summary: "Patch the chart section while preserving the artifact structure.".to_string(),
        patch_existing_artifact: true,
        preserve_structure: true,
        target_scope: "chart section".to_string(),
        target_paths: vec!["index.html".to_string()],
        requested_operations: vec!["update chart".to_string()],
        tone_directives: vec!["technical".to_string()],
        selected_targets: vec![StudioArtifactSelectionTarget {
            source_surface: "render".to_string(),
            path: Some("index.html".to_string()),
            label: "chart section".to_string(),
            snippet: "Hero chart section should show adoption by channel.".to_string(),
        }],
        style_directives: vec!["retain layout".to_string()],
        branch_requested: false,
    };

    validate_generated_artifact_payload_against_brief_with_edit_intent(
        &payload,
        &request,
        &brief,
        Some(&edit_intent),
    )
    .expect("selection-scoped chart patches should not fail the global multi-view check");
}

#[test]
fn brief_aware_validation_requires_rollover_handlers_for_rollover_briefs() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Compare adoption and satisfaction.</p><button type=\"button\" data-view=\"sales\">Sales</button><button type=\"button\" data-view=\"reviews\">Reviews</button></section><section data-view-panel=\"sales\"><article class=\"chart\"><h2>Sales performance</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"Sales performance\"><rect x=\"24\" y=\"52\" width=\"40\" height=\"56\" data-detail=\"Retail launch\"></rect><rect x=\"94\" y=\"36\" width=\"40\" height=\"72\" data-detail=\"Subscription lift\"></rect><rect x=\"164\" y=\"28\" width=\"40\" height=\"80\" data-detail=\"Vet channel proof\"></rect><text x=\"24\" y=\"118\">Retail</text><text x=\"94\" y=\"118\">Subscription</text><text x=\"164\" y=\"118\">Vet</text></svg></article></section><section data-view-panel=\"reviews\" hidden><article><h2>Review detail</h2><p>Subscriber reviews and groomer notes appear in this panel.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Retail is selected by default.</p></aside><footer><p>Compare the rollout evidence without leaving the artifact.</p></footer></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=`${button.dataset.view} selected`; }));</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec!["dog shampoo".to_string(), "sales".to_string()],
        required_interactions: vec![
            "rollover chart detail".to_string(),
            "view switching".to_string(),
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("rollover briefs should need hover or focus handlers");
    assert!(error.contains("call for rollover detail must wire hover or focus handlers"));
}

#[test]
fn brief_aware_validation_requires_multiple_rollover_marks_for_rollover_briefs() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "AI tools launch artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Hover the overview to inspect the editorial evidence.</p><button type=\"button\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"editorial\">Editorial</button></section><section data-view-panel=\"overview\"><article class=\"chart\"><h2>Overview</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"AI tools overview\"><circle cx=\"48\" cy=\"48\" r=\"28\" data-detail=\"Overview\"></circle></svg></article></section><section data-view-panel=\"editorial\" hidden><article><h2>Editorial content</h2><p>Editorial content remains visible here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Inspect the AI tools launch without leaving the artifact.</p></footer></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.textContent;}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "AI tools users".to_string(),
        job_to_be_done: "review the launch".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show the launch evidence clearly".to_string(),
        required_concepts: vec!["AI tools".to_string(), "editorial".to_string()],
        required_interactions: vec!["hover detail".to_string(), "view switching".to_string()],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![
            "AI tool features".to_string(),
            "Editorial content".to_string(),
        ],
        style_directives: vec![],
        reference_hints: vec!["Launch event".to_string()],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("rollover briefs should need multiple detail marks");
    assert!(error.contains(
        "call for rollover detail must surface at least three visible data-detail marks"
    ));
}

#[test]
fn brief_aware_validation_requires_explicit_view_mapping_for_clickable_navigation() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch across the rollout evidence.</p><button id=\"satisfaction-btn\" aria-selected=\"true\">Customer satisfaction</button><button id=\"usage-btn\" aria-selected=\"false\">Usage statistics</button></section><article class=\"chart-container\"><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Customer satisfaction\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Pilot</text></svg></article><aside><table><caption>Usage statistics</caption><tr><th>Month</th><th>Units</th></tr><tr><td>Jan</td><td>1200</td></tr></table></aside><aside><p id=\"detail-copy\">Customer satisfaction stays selected by default.</p></aside></main><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=button.textContent;}));</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
        ],
        required_interactions: vec![
            "clickable navigation between different chart views".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("clickable navigation should need explicit view mappings");
    assert!(error.contains("clickable view switching"));
}

#[test]
fn brief_aware_validation_rejects_control_ids_without_panel_containers() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch across the rollout evidence.</p><button id=\"satisfaction\" data-view=\"satisfaction\">Customer satisfaction</button><button id=\"usage\" data-view=\"usage\">Usage statistics</button></section><div class=\"chart-container\"><svg viewBox=\"0 0 220 120\" role=\"img\" aria-hidden=\"true\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Pilot</text></svg><svg viewBox=\"0 0 220 120\" role=\"img\" aria-hidden=\"true\"><rect x=\"20\" y=\"32\" width=\"40\" height=\"68\"></rect><text x=\"20\" y=\"114\">Repeat</text></svg></div><aside><p id=\"detail-copy\">Customer satisfaction stays selected by default.</p></aside></main><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.querySelector(`[data-view-panel=\"${button.dataset.view}\"]`).hidden=false;detail.textContent=button.textContent;}));</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
        ],
        required_interactions: vec![
            "clickable navigation between different chart views".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("control ids alone should not satisfy view panel mapping");
    assert!(error.contains("clickable view switching"));
}

#[test]
fn brief_aware_validation_requires_one_visible_mapped_view_panel_on_first_paint() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch across the rollout evidence.</p><button type=\"button\" data-view=\"satisfaction\" aria-controls=\"satisfaction-panel\">Customer satisfaction</button><button type=\"button\" data-view=\"usage\" aria-controls=\"usage-panel\">Usage statistics</button></section><section id=\"satisfaction-panel\" role=\"tabpanel\" hidden><article><h2>Customer satisfaction</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Customer satisfaction\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Pilot</text></svg></article></section><section id=\"usage-panel\" role=\"tabpanel\" hidden><article><h2>Usage statistics</h2><p>Usage evidence is pre-rendered here.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Customer satisfaction stays selected by default.</p></aside></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[role=\"tabpanel\"]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});detail.textContent=button.textContent;}));</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
        ],
        required_interactions: vec![
            "clickable navigation between different chart views".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("all mapped panels hidden on first paint should fail validation");
    assert!(error.contains("populated mapped evidence panel visible on first paint"));
}

#[test]
fn brief_aware_validation_requires_populated_mapped_view_panels_on_first_paint() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch between launch and sales evidence.</p></section><nav aria-label=\"Artifact views\"><button type=\"button\" data-view=\"launch\" aria-controls=\"launch-panel\" aria-selected=\"true\">Launch</button><button type=\"button\" data-view=\"sales\" aria-controls=\"sales-panel\">Sales</button></nav><section id=\"launch-panel\" data-view-panel=\"launch\"></section><section id=\"sales-panel\" data-view-panel=\"sales\" hidden></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch selected by default.</p></aside><footer><p>Compare rollout evidence without leaving the artifact.</p></footer><script>const controls=document.querySelectorAll('button[data-view]');const panels=document.querySelectorAll('[data-view-panel]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');panel.setAttribute('aria-hidden',String(panel.hidden));});document.getElementById('detail-copy').textContent=button.textContent;}));</script></main></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "launch evidence".to_string(),
            "sales comparison".to_string(),
        ],
        required_interactions: vec![
            "clickable navigation between different chart views".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("empty mapped panels should fail validation");
    assert!(error.contains("every mapped evidence panel pre-rendered with first-paint content"));
}

#[test]
fn payload_validation_rejects_duplicate_mapped_view_tokens() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Duplicate mapped view tokens".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #ccc;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"overview\" hidden><article><h2>Metrics</h2><p>Metrics evidence should not reuse the overview token.</p></article></section><aside><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(&payload, &request)
        .expect_err("duplicate mapped view tokens should fail payload validation");
    assert!(error.contains("must not duplicate mapped view-panel tokens"));
}

#[test]
fn payload_validation_rejects_multiple_visible_mapped_panels() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Multiple visible mapped panels".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #ccc;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\"><article><h2>Metrics</h2><p>Metrics evidence should start hidden until selected.</p></article></section><aside><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(&payload, &request)
        .expect_err("multiple visible mapped panels should fail payload validation");
    assert!(error.contains("exactly one populated panel visible on first paint"));
}

#[test]
fn payload_validation_rejects_custom_font_claims_without_loading() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Custom font claims without loading".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><head><style>:root{--display-font:'Newsreader',serif;}body{font-family:'Newsreader',serif;background:#0f172a;color:#f8fafc;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #334155;}button{font-family:'Instrument Sans',sans-serif;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics</h2><p>Metrics evidence stays pre-rendered.</p></article></section><aside><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(&payload, &request)
        .expect_err("custom font claims without loading should fail payload validation");
    assert!(error.contains("declare custom font families must load them"));
}

#[test]
fn payload_validation_rejects_unfocusable_rollover_marks() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Unfocusable rollover marks".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #cbd5e1;border-radius:12px;}svg{width:100%;max-width:320px;height:auto;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness, adoption, and support demand through a focused rollout story with visible evidence marks.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button></section><section id=\"overview-panel\"><article><h2>Overview</h2><p>Overview evidence stays visible here with trend notes, operator context, and one shared detail region.</p><svg viewBox=\"0 0 320 120\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"24\" y=\"28\" width=\"52\" height=\"64\" fill=\"#2563eb\" data-detail=\"Readiness signal\"></rect><rect x=\"104\" y=\"16\" width=\"52\" height=\"76\" fill=\"#0f766e\" data-detail=\"Adoption signal\"></rect><rect x=\"184\" y=\"36\" width=\"52\" height=\"56\" fill=\"#b45309\" data-detail=\"Support signal\"></rect></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Readiness signal is selected by default.</p></aside><footer><p>Footer note summarizing next steps and verification posture.</p></footer><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('focus',()=>{detail.textContent=mark.getAttribute('data-detail');});mark.addEventListener('mouseenter',()=>{detail.textContent=mark.getAttribute('data-detail');});});</script></main></body></html>".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(&payload, &request)
        .expect_err("unfocusable rollover marks should fail payload validation");
    assert!(error.contains("data-detail marks keyboard-focusable"));
}

#[test]
fn brief_aware_validation_rejects_static_aria_controls_without_click_driven_panel_state() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<html><head><title>New Dog Shampoo Product Rollout</title><style>body { font-family: Arial, sans-serif; }.chart-container { margin-bottom: 20px; }.chart-legend { margin-top: 10px; }</style></head><body><main><h1>New Dog Shampoo Product Rollout</h1><nav role=\"navigation\"><button data-view=\"satisfaction\" aria-controls=\"satisfaction-panel\">Customer Satisfaction</button><button data-view=\"usage\" aria-controls=\"usage-panel\">Usage Statistics</button><button data-view=\"ingredients\" aria-controls=\"ingredients-panel\">Ingredient Analysis</button></nav><section id=\"satisfaction-panel\" class=\"chart-container\"><svg width=\"400\" height=\"300\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" tabindex=\"0\" data-detail=\"Retail satisfaction lift\"/><text x=\"70\" y=\"130\">Customer Satisfaction</text></svg></section><section id=\"usage-panel\" class=\"chart-container\"><svg width=\"400\" height=\"300\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" tabindex=\"0\" data-detail=\"Usage frequency increase\"/><text x=\"70\" y=\"130\">Usage Statistics</text></svg></section><section id=\"ingredients-panel\" class=\"chart-container\"><svg width=\"400\" height=\"300\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" tabindex=\"0\" data-detail=\"Key ingredient breakdown\"/><text x=\"70\" y=\"130\">Ingredient Analysis</text></svg></section><aside id=\"detail-copy\"><p>Retail satisfaction lift is selected by default.</p></aside></main><script>const chartViews = document.querySelectorAll('[data-view-panel]');const detailCopy = document.getElementById('detail-copy');function updateDetail(e) { detailCopy.textContent = e.target.dataset.detail; }for (const view of chartViews) { view.addEventListener('mouseenter', updateDetail); view.addEventListener('focus', updateDetail); }</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
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
            "product rollout".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
            "ingredient analysis".to_string(),
        ],
        required_interactions: vec![
            "rollover effects for chart elements".to_string(),
            "clickable navigation between different types of charts".to_string(),
        ],
        visual_tone: vec![
            "informative".to_string(),
            "professional".to_string(),
            "user-friendly".to_string(),
        ],
        factual_anchors: vec![
            "clinical trials data".to_string(),
            "customer feedback".to_string(),
            "sales performance metrics".to_string(),
        ],
        style_directives: vec![
            "clear and concise language".to_string(),
            "use of color to highlight key points".to_string(),
            "interactive elements should be intuitive".to_string(),
        ],
        reference_hints: vec![
            "charts showing pH levels, ingredient breakdowns, before-and-after condition comparisons"
                .to_string(),
        ],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("static aria-controls without click-driven panel mutation should fail");
    assert!(error.contains("change panel visibility or selection state on click"));
}

#[test]
fn brief_aware_validation_does_not_treat_view_panels_as_shared_detail_regions() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout artifact".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect product evidence.</p></section><nav><button data-view=\"satisfaction\" aria-controls=\"satisfaction-panel\">Customer satisfaction</button><button data-view=\"usage\" aria-controls=\"usage-panel\">Usage statistics</button><button data-view=\"ingredients\" aria-controls=\"ingredients-panel\">Ingredient analysis</button></nav><section class=\"chart-container\"><div id=\"satisfaction-panel\" data-view-panel=\"satisfaction\" hidden><h2>Customer Satisfaction</h2><svg viewBox=\"0 0 1000 500\" role=\"img\" aria-label=\"Customer satisfaction chart\"><rect x=\"50\" y=\"450\" width=\"900\" height=\"50\"></rect><text x=\"55\" y=\"425\">Very satisfied</text></svg><p id=\"detail-copy\" class=\"hidden\"></p></div><div id=\"usage-panel\" data-view-panel=\"usage\"><h2>Usage Statistics</h2><svg viewBox=\"0 0 1000 500\" role=\"img\" aria-label=\"Usage chart\"><rect x=\"50\" y=\"450\" width=\"900\" height=\"50\"></rect><text x=\"55\" y=\"425\">Monthly usage</text></svg></div><div id=\"ingredients-panel\" data-view-panel=\"ingredients\"><h2>Ingredient Analysis</h2><svg viewBox=\"0 0 1000 500\" role=\"img\" aria-label=\"Ingredient chart\"><rect x=\"50\" y=\"450\" width=\"900\" height=\"50\"></rect><text x=\"55\" y=\"425\">Key ingredients</text></svg></div></section></main><script>const controls=document.querySelectorAll('button[data-view]');const panels=document.querySelectorAll('[data-view-panel]');const detailCopy=document.querySelector('#detail-copy');controls.forEach((control)=>{control.addEventListener('click',(e)=>{e.preventDefault();panels.forEach((panel)=>panel.hidden=true);const matchingPanel=document.querySelector(`[data-view-panel=\"${control.dataset.view}\"]`);if(matchingPanel){matchingPanel.hidden=false;}detailCopy.textContent=control.innerText;});control.addEventListener('focus',()=>{control.setAttribute('aria-selected','true');});control.addEventListener('blur',()=>{control.setAttribute('aria-selected','false');});});</script></body></html>".to_string(),
        }],
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "review the rollout".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "show the launch plan clearly".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
            "ingredient analysis".to_string(),
        ],
        required_interactions: vec![
            "rollover chart detail".to_string(),
            "clickable navigation between different chart views".to_string(),
        ],
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec![],
        style_directives: vec![],
        reference_hints: vec![],
    };

    let error = validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect_err("view panels should not count as a populated shared detail region");
    assert!(error.contains("shared detail or comparison region"));
}

#[tokio::test]
async fn judge_contract_downgrades_empty_sectioning_shells() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec!["channel adoption".to_string(), "launch steps".to_string()],
                required_interactions: vec!["chart toggle".to_string()],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section id=\"hero\"></section><section id=\"scenario\"></section><aside id=\"evidence\"></aside><details><summary>Inspect supporting detail</summary><p>Inline detail.</p></details></main></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade empty section shells");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML sectioning regions are empty shells on first paint.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_navigation_only_html_interactions() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Instacart rollout artifact",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "inspect the rollout".to_string(),
                subject_domain: "Instacart MCP rollout".to_string(),
                artifact_thesis: "show the rollout plan clearly".to_string(),
                required_concepts: vec!["rollout".to_string(), "dependencies".to_string()],
                required_interactions: vec!["compare stakeholders".to_string()],
                visual_tone: vec!["clear".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Instacart rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Instacart rollout</h1><button type=\"button\" id=\"eng\">Engineering</button></section><section><h2>Timeline</h2><p>Inspect the rollout phases.</p></section><aside><h2>Dependencies</h2><p>Review launch blockers.</p></aside><script>document.getElementById('eng').addEventListener('click',()=>{document.querySelector('aside').scrollIntoView();console.info('eng');});</script></main></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade navigation-only interactions");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML interactions are navigation-only and do not update shared detail state.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_sparse_svg_primary_view() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
        runtime,
        "AI tools hero concept",
        &request_for(StudioArtifactClass::Visual, StudioRendererKind::Svg),
        &StudioArtifactBrief {
            audience: "AI tool buyers".to_string(),
            job_to_be_done: "scan the concept quickly".to_string(),
            subject_domain: "AI tools brand story".to_string(),
            artifact_thesis: "Show a strong visual hero for AI tools.".to_string(),
            required_concepts: vec![
                "AI".to_string(),
                "tools".to_string(),
                "innovation".to_string(),
            ],
            required_interactions: Vec::new(),
            visual_tone: vec!["bold".to_string()],
            factual_anchors: vec!["automation".to_string()],
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        },
        None,
        &StudioGeneratedArtifactPayload {
            summary: "AI tools hero concept".to_string(),
            notes: vec![],
            files: vec![StudioGeneratedArtifactFile {
                path: "hero-concept.svg".to_string(),
                mime: "image/svg+xml".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<svg width=\"100%\" height=\"100%\" viewBox=\"0 0 800 500\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"100%\" height=\"100%\" fill=\"#111827\" /><text x=\"120\" y=\"220\" fill=\"#fff\">AI Tools</text><text x=\"120\" y=\"280\" fill=\"#9ca3af\">Move faster</text></svg>".to_string(),
            }],
        },
    )
    .await
    .expect("judge contract should downgrade sparse SVG output");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("SVG output is too sparse to stand as the primary visual artifact.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_missing_rollover_behavior_from_brief() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec!["channel adoption".to_string(), "launch steps".to_string()],
                required_interactions: vec![
                    "rollover chart detail".to_string(),
                    "view switching".to_string(),
                ],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Compare launch readiness across channels.</p><button type=\"button\" data-view=\"retail\">Retail</button><button type=\"button\" data-view=\"subscription\">Subscription</button></section><section data-view-panel=\"retail\"><article class=\"chart\"><h2>Channel adoption</h2><svg viewBox=\"0 0 260 140\" role=\"img\" aria-label=\"Dog shampoo channel adoption\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" data-detail=\"Retail launch\"></rect><rect x=\"94\" y=\"36\" width=\"42\" height=\"80\" data-detail=\"Subscription lift\"></rect><rect x=\"164\" y=\"28\" width=\"42\" height=\"88\" data-detail=\"Vet channel proof\"></rect><text x=\"24\" y=\"132\">Retail</text><text x=\"94\" y=\"132\">Subscription</text><text x=\"164\" y=\"132\">Vet</text></svg></article></section><section data-view-panel=\"subscription\"><article><h2>Subscription retention</h2><p>Subscription retention detail stays in this pre-rendered panel.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Retail is selected by default.</p></aside><footer><p>Keep the chart evidence request-faithful.</p></footer></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=`${button.dataset.view} selected`; }));</script></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade missing rollover behavior");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML lacks hover or focus detail behavior for rollover interactions.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_missing_explicit_view_mapping_from_brief() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec![
                    "customer satisfaction".to_string(),
                    "usage statistics".to_string(),
                    "ingredient analysis".to_string(),
                ],
                required_interactions: vec![
                    "clickable navigation between different chart views".to_string(),
                    "detail comparison".to_string(),
                ],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch across the rollout evidence.</p><button id=\"satisfaction-btn\" aria-selected=\"true\">Customer satisfaction</button><button id=\"usage-btn\" aria-selected=\"false\">Usage statistics</button></section><article class=\"chart-container\"><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Customer satisfaction\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\" data-detail=\"Pilot satisfaction\"></rect><rect x=\"90\" y=\"36\" width=\"40\" height=\"64\" data-detail=\"Repeat use\"></rect><text x=\"20\" y=\"114\">Pilot</text><text x=\"90\" y=\"114\">Repeat</text></svg></article><aside><table><caption>Usage statistics</caption><tr><th>Month</th><th>Units</th></tr><tr><td>Jan</td><td>1200</td></tr></table></aside><aside><p id=\"detail-copy\">Customer satisfaction stays selected by default.</p></aside></main><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=button.textContent;}));</script></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade missing explicit view mapping");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML clickable navigation does not map controls to pre-rendered views.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_hidden_mapped_view_panels_from_brief() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec![
                    "customer satisfaction".to_string(),
                    "usage statistics".to_string(),
                    "ingredient analysis".to_string(),
                ],
                required_interactions: vec![
                    "clickable navigation between different chart views".to_string(),
                    "detail comparison".to_string(),
                ],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch across the rollout evidence.</p><button type=\"button\" data-view=\"satisfaction\" aria-controls=\"satisfaction-panel\">Customer satisfaction</button><button type=\"button\" data-view=\"usage\" aria-controls=\"usage-panel\">Usage statistics</button></section><section id=\"satisfaction-panel\" role=\"tabpanel\" hidden><article><h2>Customer satisfaction</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Customer satisfaction\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Pilot</text></svg></article></section><section id=\"usage-panel\" role=\"tabpanel\" hidden><article><h2>Usage statistics</h2><p>Usage evidence is pre-rendered here.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Customer satisfaction stays selected by default.</p></aside></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[role=\"tabpanel\"]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});detail.textContent=button.textContent;}));</script></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade hidden mapped view panels");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML clickable navigation does not keep a populated mapped evidence panel visible on first paint.")
    );
}

#[tokio::test]
async fn judge_contract_downgrades_empty_mapped_view_panels_from_brief() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::FixtureRuntime,
        "fixture://judge-contract",
        "fixture-judge",
        "fixture://judge-contract",
        "acceptance",
        calls,
    ));

    let result = judge_studio_artifact_candidate_with_runtime(
            runtime,
            "Dog shampoo rollout",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &StudioArtifactBrief {
                audience: "operators".to_string(),
                job_to_be_done: "review the rollout".to_string(),
                subject_domain: "dog shampoo launch".to_string(),
                artifact_thesis: "show the launch plan clearly".to_string(),
                required_concepts: vec![
                    "launch evidence".to_string(),
                    "sales comparison".to_string(),
                ],
                required_interactions: vec![
                    "clickable navigation between different chart views".to_string(),
                    "detail comparison".to_string(),
                ],
                visual_tone: vec!["confident".to_string()],
                factual_anchors: vec![],
                style_directives: vec![],
                reference_hints: vec![],
            },
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Dog shampoo rollout artifact".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch between launch and sales evidence.</p></section><nav aria-label=\"Artifact views\"><button type=\"button\" data-view=\"launch\" aria-controls=\"launch-panel\" aria-selected=\"true\">Launch</button><button type=\"button\" data-view=\"sales\" aria-controls=\"sales-panel\">Sales</button></nav><section id=\"launch-panel\" data-view-panel=\"launch\"></section><section id=\"sales-panel\" data-view-panel=\"sales\" hidden></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch selected by default.</p></aside><footer><p>Compare rollout evidence without leaving the artifact.</p></footer><script>const controls=document.querySelectorAll('button[data-view]');const panels=document.querySelectorAll('[data-view-panel]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');panel.setAttribute('aria-hidden',String(panel.hidden));});document.getElementById('detail-copy').textContent=button.textContent;}));</script></main></body></html>".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade empty mapped panels");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("HTML clickable navigation maps controls to empty pre-rendered panels.")
    );
}

#[test]
fn judge_prompt_uses_compact_candidate_view_for_large_files() {
    let payload = build_studio_artifact_judge_prompt(
        "Release checklist",
        &request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "review the checklist".to_string(),
            subject_domain: "release operations".to_string(),
            artifact_thesis: "capture the release checklist".to_string(),
            required_concepts: vec!["release checklist".to_string()],
            required_interactions: vec![],
            visual_tone: vec![],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        None,
        &StudioGeneratedArtifactPayload {
            summary: "Release checklist draft".to_string(),
            notes: vec!["expanded checklist".to_string()],
            files: vec![StudioGeneratedArtifactFile {
                path: "release-checklist.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: format!("START\n{}\nEND", "cut release branch\n".repeat(600)),
            }],
        },
    )
    .expect("judge prompt should build");

    let user_content = payload[1]["content"]
        .as_str()
        .expect("user content should be a string");
    assert!(user_content.contains("\"bodyPreview\""));
    assert!(user_content.contains("START"));
    assert!(user_content.contains("END"));
    assert!(user_content.contains("[truncated"));
    assert!(!user_content.contains(&"cut release branch\n".repeat(300)));
}

#[test]
fn judge_prompt_compacts_typed_context_json() {
    let payload = build_studio_artifact_judge_prompt(
        "Release checklist",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "review the checklist".to_string(),
            subject_domain: "release operations".to_string(),
            artifact_thesis: "capture the release checklist".to_string(),
            required_concepts: vec!["release checklist".to_string()],
            required_interactions: vec![],
            visual_tone: vec![],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        None,
        &StudioGeneratedArtifactPayload {
            summary: "Release checklist draft".to_string(),
            notes: vec!["expanded checklist".to_string()],
            files: vec![StudioGeneratedArtifactFile {
                path: "release-checklist.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "# Release checklist".to_string(),
            }],
        },
    )
    .expect("judge prompt should build");

    let user_content = payload[1]["content"]
        .as_str()
        .expect("user content should be a string");
    assert!(user_content.contains("Request focus JSON:\n{"));
    assert!(user_content.contains("\"artifactClass\":\"interactive_single_file\""));
    assert!(user_content.contains("Brief focus JSON:\n{"));
    assert!(user_content.contains("\"audience\":\"operators\""));
    assert!(user_content.contains("Edit intent focus JSON:\nnull"));
    assert!(!user_content.contains("Request focus JSON:\n{\n"));
    assert!(!user_content.contains("Brief focus JSON:\n{\n"));
    assert!(!user_content.contains("Candidate JSON:\n{\n"));
}

#[test]
fn markdown_judge_prompt_uses_document_contract() {
    let payload = build_studio_artifact_judge_prompt(
        "Release checklist",
        &request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "review the checklist".to_string(),
            subject_domain: "release operations".to_string(),
            artifact_thesis: "capture the release checklist".to_string(),
            required_concepts: vec!["release checklist".to_string()],
            required_interactions: vec![],
            visual_tone: vec![],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        None,
        &StudioGeneratedArtifactPayload {
            summary: "Release checklist draft".to_string(),
            notes: vec!["expanded checklist".to_string()],
            files: vec![StudioGeneratedArtifactFile {
                path: "release-checklist.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "# Release checklist".to_string(),
            }],
        },
    )
    .expect("judge prompt should build");

    let user_content = payload[1]["content"]
        .as_str()
        .expect("user content should be a string");
    assert!(user_content.contains("Brief focus JSON:"));
    assert!(user_content.contains("\"audience\":\"operators\""));
    assert!(!user_content.contains("Artifact request JSON:"));
    assert!(user_content.contains("Empty deliverables, placeholder filler"));
    assert!(!user_content.contains("thin div shell"));
    assert!(!user_content.contains("sequence-browsing penalties"));
}

#[test]
fn judge_prompt_carries_interaction_contract_flags() {
    let payload = build_studio_artifact_judge_prompt(
        "Dog shampoo rollout",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &StudioArtifactBrief {
            audience: "dog owners".to_string(),
            job_to_be_done: "inspect the rollout with interactive charts".to_string(),
            subject_domain: "pet care".to_string(),
            artifact_thesis: "Explain the dog shampoo rollout through interactive charts."
                .to_string(),
            required_concepts: vec![
                "dog shampoo".to_string(),
                "product rollout".to_string(),
                "customer satisfaction".to_string(),
            ],
            required_interactions: vec![
                "click to compare sales data".to_string(),
                "hover to inspect market trends".to_string(),
            ],
            visual_tone: vec!["informative".to_string()],
            factual_anchors: vec!["APPA market data".to_string()],
            style_directives: vec![],
            reference_hints: vec![],
        },
        None,
        &StudioGeneratedArtifactPayload {
            summary: "Dog shampoo rollout draft".to_string(),
            notes: vec!["interactive evidence".to_string()],
            files: vec![StudioGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section><section><article><h2>Sales</h2><svg viewBox=\"0 0 200 120\"><rect x=\"20\" y=\"40\" width=\"40\" height=\"60\"></rect><text x=\"20\" y=\"114\">Q1</text></svg></article></section><aside><p id=\"detail-copy\">Sales are selected by default.</p></aside></main></body></html>".to_string(),
            }],
        },
    )
    .expect("judge prompt should build");

    let user_content = payload[1]["content"]
        .as_str()
        .expect("user content should be a string");
    assert!(user_content.contains("\"sequenceBrowsingRequired\":false"));
    assert!(user_content.contains(
        "Apply sequence-browsing penalties only when interactionContract.sequenceBrowsingRequired is true."
    ));
    assert!(user_content.contains(
        "Judge requiredInteractions by the visible response behavior and interactionContract"
    ));
}

#[test]
fn judge_contract_ignores_sequence_penalties_when_brief_does_not_require_them() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "dog owners".to_string(),
        job_to_be_done: "inspect the rollout with interactive charts".to_string(),
        subject_domain: "pet care".to_string(),
        artifact_thesis: "Explain the dog shampoo rollout through interactive charts.".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "product rollout".to_string(),
            "customer satisfaction".to_string(),
        ],
        required_interactions: vec![
            "click to compare sales data".to_string(),
            "hover to inspect market trends".to_string(),
        ],
        visual_tone: vec!["informative".to_string()],
        factual_anchors: vec!["APPA market data".to_string()],
        style_directives: vec![],
        reference_hints: vec![],
    };
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Dog shampoo rollout draft".to_string(),
        notes: vec!["interactive evidence".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect sales and customer feedback.</p><button type=\"button\" data-view=\"sales\">Sales</button><button type=\"button\" data-view=\"feedback\">Feedback</button></section><section data-view-panel=\"sales\"><article><h2>Sales chart</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo sales\"><rect x=\"20\" y=\"44\" width=\"32\" height=\"56\" tabindex=\"0\" data-detail=\"Sales by month\"></rect><rect x=\"78\" y=\"32\" width=\"32\" height=\"68\" tabindex=\"0\" data-detail=\"Market share\"></rect><rect x=\"136\" y=\"20\" width=\"32\" height=\"80\" tabindex=\"0\" data-detail=\"Customer satisfaction\"></rect><text x=\"20\" y=\"114\">Q1</text><text x=\"78\" y=\"114\">Share</text><text x=\"136\" y=\"114\">Satisfaction</text></svg></article></section><section data-view-panel=\"feedback\"><article><h2>Customer feedback</h2><p>APPA market data and survey highlights stay visible here.</p></article></section><aside><p id=\"detail-copy\">Sales are selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>".to_string(),
        }],
    };
    let judge = StudioArtifactJudgeResult {
        classification: StudioArtifactJudgeClassification::Repairable,
        request_faithfulness: 4,
        concept_coverage: 4,
        interaction_relevance: 3,
        layout_coherence: 4,
        visual_hierarchy: 4,
        completeness: 3,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: true,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes: vec!["sequence_browsing".to_string()],
        repair_hints: vec!["If sequence browsing is truly required, add a visible progression control."
            .to_string()],
        strengths: vec!["View switching and detail inspection are already strong.".to_string()],
        blocked_reasons: Vec::new(),
        file_findings: vec!["index.html: missing progression control.".to_string()],
        aesthetic_verdict: "Evidence hierarchy is strong enough to support the artifact."
            .to_string(),
        interaction_verdict:
            "Sequence browsing is the only notable gap; the rest of the interaction contract is strong."
                .to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("structural_repair".to_string()),
        strongest_contradiction: Some("Missing sequence browsing for timeline.".to_string()),
        rationale:
            "Candidate covers key concepts but lacks interactive sequence browsing as required."
                .to_string(),
    };

    let result = enforce_renderer_judge_contract(&request, &brief, &candidate, judge);

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert!(result.interaction_relevance >= 4);
    assert!(result.completeness >= 4);
    assert_eq!(result.strongest_contradiction, None);
    assert_eq!(
        result.rationale,
        "Complies with the interaction contract and stays request-faithful."
    );
}

#[test]
fn parse_studio_artifact_judge_result_normalizes_score_ranges() {
    let result = parse_studio_artifact_judge_result(
        &serde_json::json!({
            "classification": "pass",
            "requestFaithfulness": "7",
            "conceptCoverage": 0,
            "interactionRelevance": 3.6,
            "layoutCoherence": "2",
            "visualHierarchy": 4,
            "completeness": 9,
            "genericShellDetected": "false",
            "trivialShellDetected": false,
            "deservesPrimaryArtifactView": "true",
            "patchedExistingArtifact": "false",
            "continuityRevisionUx": "8",
            "strongestContradiction": null,
            "rationale": "Compact acceptance judgment."
        })
        .to_string(),
    )
    .expect("judge parser should normalize recoverable score drift");

    assert_eq!(result.request_faithfulness, 5);
    assert_eq!(result.concept_coverage, 1);
    assert_eq!(result.interaction_relevance, 4);
    assert_eq!(result.layout_coherence, 2);
    assert_eq!(result.visual_hierarchy, 4);
    assert_eq!(result.completeness, 5);
    assert_eq!(result.continuity_revision_ux, Some(5));
    assert_eq!(result.patched_existing_artifact, Some(false));
    assert!(result.deserves_primary_artifact_view);
    assert_eq!(result.strongest_contradiction, None);
    assert_eq!(
        result.issue_classes,
        vec!["request_faithfulness".to_string()]
    );
    assert!(result.repair_hints.is_empty());
    assert_eq!(
        result.strengths,
        vec![
            "Request concepts stay visible and specific.".to_string(),
            "Hierarchy reads as deliberate instead of default scaffolding.".to_string(),
            "Interactive affordances respond truthfully to the typed interaction contract."
                .to_string(),
        ]
    );
    assert!(result.blocked_reasons.is_empty());
    assert!(result.file_findings.is_empty());
    assert_eq!(
        result.aesthetic_verdict,
        "Typography and layout feel deliberate enough to carry the artifact."
    );
    assert_eq!(
        result.interaction_verdict,
        "Interaction model is visible and materially changes the page state."
    );
    assert_eq!(
        result.truthfulness_warnings,
        vec![
            "Candidate may be substituting generic filler for the typed request concepts."
                .to_string()
        ]
    );
    assert_eq!(result.recommended_next_pass.as_deref(), Some("polish_pass"));
}

#[test]
fn parse_studio_artifact_judge_result_recovers_plaintext_labeled_output() {
    let result = parse_studio_artifact_judge_result(
        r#"
Classification: repairable
Request faithfulness: 4/5
Concept coverage: 4
Interaction relevance: 3
Layout coherence: 4
Visual hierarchy: 3
Completeness: 4
Generic shell detected: no
Trivial shell detected: false
Deserves primary artifact view: no
Issue classes:
- metadata_gap
Repair hints: add manifest metadata, explain CSV columns
Strengths:
- CSV and README both exist
Blocked reasons: none
File findings: README.md: missing column descriptions
Aesthetic verdict: utilitarian but clear.
Interaction verdict: download-only surface matches the request.
Recommended next pass: structural repair
Strongest contradiction: The bundle lacks enough metadata to feel complete.
Rationale: Candidate is close, but the README still underspecifies the bundle.
"#,
    )
    .expect("plaintext judge output should recover");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert_eq!(result.request_faithfulness, 4);
    assert_eq!(result.concept_coverage, 4);
    assert_eq!(result.interaction_relevance, 3);
    assert_eq!(result.layout_coherence, 4);
    assert_eq!(result.visual_hierarchy, 3);
    assert_eq!(result.completeness, 4);
    assert!(!result.generic_shell_detected);
    assert!(!result.trivial_shell_detected);
    assert!(!result.deserves_primary_artifact_view);
    assert_eq!(result.issue_classes, vec!["metadata_gap".to_string()]);
    assert_eq!(
        result.repair_hints,
        vec![
            "add manifest metadata".to_string(),
            "explain CSV columns".to_string()
        ]
    );
    assert_eq!(
        result.strengths,
        vec!["CSV and README both exist".to_string()]
    );
    assert_eq!(result.blocked_reasons, Vec::<String>::new());
    assert_eq!(
        result.file_findings,
        vec!["README.md: missing column descriptions".to_string()]
    );
    assert_eq!(
        result.recommended_next_pass.as_deref(),
        Some("structural_repair")
    );
    assert_eq!(
        result.strongest_contradiction.as_deref(),
        Some("The bundle lacks enough metadata to feel complete.")
    );
    assert_eq!(
        result.rationale,
        "Candidate is close, but the README still underspecifies the bundle."
    );
}

#[test]
fn parse_studio_artifact_judge_result_recovers_plaintext_first_line_classification() {
    let result = parse_studio_artifact_judge_result(
        r#"
Repairable
Request faithfulness: 4
Concept coverage: 4
Interaction relevance: 3
Layout coherence: 3
Visual hierarchy: 3
Completeness: 3
Repair hints:
- Explain what the CSV columns mean in the README.
- Add a manifest that names the downloadable files.
The bundle is close, but the README omits enough context that the download package still feels incomplete.
"#,
    )
    .expect("plaintext first-line classification should recover");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert_eq!(
        result.repair_hints,
        vec![
            "Explain what the CSV columns mean in the README.".to_string(),
            "Add a manifest that names the downloadable files.".to_string(),
        ]
    );
    assert_eq!(
        result.rationale,
        "The bundle is close, but the README omits enough context that the download package still feels incomplete."
    );
}

#[test]
fn parse_studio_artifact_judge_result_recovers_truncated_compact_json() {
    let result = parse_studio_artifact_judge_result(
        r#"{"classification":"pass","requestFaithfulness":5,"conceptCoverage":5,"interactionRelevance":5,"layoutCoherence":5,"visualHierarchy":0,"completeness":5,"genericShellDetected":false,"trivialShellDetected":false,"deservesPrimaryArtifactView":true,"strengths":["Includes both CSV and README files as requested."],"recommendedNextPass":"accept","aestheticVerdict":"Clear and concise documentation.","interactionVerdict":"Inter"#,
    )
    .expect("truncated compact json should recover");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_eq!(result.request_faithfulness, 5);
    assert_eq!(result.concept_coverage, 5);
    assert_eq!(result.interaction_relevance, 5);
    assert_eq!(result.layout_coherence, 5);
    assert_eq!(result.visual_hierarchy, 1);
    assert_eq!(result.completeness, 5);
    assert!(result.deserves_primary_artifact_view);
    assert_eq!(
        result.strengths,
        vec!["Includes both CSV and README files as requested.".to_string()]
    );
    assert_eq!(result.recommended_next_pass.as_deref(), Some("accept"));
    assert_eq!(result.aesthetic_verdict, "Clear and concise documentation.");
}

#[tokio::test]
async fn acceptance_retries_ranked_candidates_until_one_clears_primary_view() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioAcceptanceRetryTestRuntime::new(
            StudioRuntimeProvenanceKind::FixtureRuntime,
            "fixture producer",
            "qwen2.5:7b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioAcceptanceRetryTestRuntime::new(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote acceptance",
            "gpt-4.1",
            "https://api.openai.com/v1/chat/completions",
            "acceptance",
            calls.clone(),
        ));

    let bundle = generate_studio_artifact_bundle_with_runtimes(
        production_runtime,
        acceptance_runtime,
        "Rollout artifact",
        "Create an interactive rollout artifact",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("bundle should generate");

    assert_eq!(bundle.winning_candidate_id, "candidate-2");
    assert_eq!(
        bundle.judge.rationale,
        "Acceptance cleared the fallback candidate."
    );
    assert_eq!(
        bundle
            .candidate_summaries
            .iter()
            .find(|candidate| candidate.selected)
            .map(|candidate| candidate.candidate_id.as_str()),
        Some("candidate-2")
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:judge")
            .count(),
        2
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:judge")
            .count(),
        2
    );
}

#[derive(Clone)]
struct StudioSemanticRefinementTestRuntime {
    provenance: StudioRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
    fail_second_candidate: bool,
}

impl StudioSemanticRefinementTestRuntime {
    fn new(
        kind: StudioRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self::new_with_options(kind, label, model, endpoint, role, calls, false)
    }

    fn new_with_options(
        kind: StudioRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        fail_second_candidate: bool,
    ) -> Self {
        Self {
            provenance: StudioRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
            role,
            calls,
            fail_second_candidate,
        }
    }
}

#[async_trait]
impl InferenceRuntime for StudioSemanticRefinementTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materialization repairer") {
            "materialize_repair"
        } else if prompt.contains("typed artifact materialization repairer") {
            "materialize_repair"
        } else if prompt.contains("typed artifact refinement repairer") {
            "refine_repair"
        } else if prompt.contains("typed artifact refiner") {
            "refine"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else if prompt.contains("typed artifact judge") {
            "judge"
        } else {
            "unknown"
        };
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{stage}", self.role));

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "Instacart MCP operators",
                "jobToBeDone": "understand the rollout with interactive evidence",
                "subjectDomain": "Instacart MCP rollout",
                "artifactThesis": "show the rollout through charts, milestones, and click-through details",
                "requiredConcepts": ["Instacart", "MCP", "charts", "product rollout"],
                "requiredInteractions": ["rollover tooltips", "clickable elements"],
                "visualTone": ["data-driven"],
                "factualAnchors": ["key milestones", "performance metrics"],
                "styleDirectives": ["concise labels", "clear hierarchy"],
                "referenceHints": []
            }),
            "materialize" | "materialize_repair" => {
                let candidate_id = if prompt.contains("\"candidateId\":\"candidate-1\"") {
                    "candidate-1"
                } else {
                    "candidate-2"
                };
                if self.fail_second_candidate && candidate_id == "candidate-2" {
                    serde_json::json!({
                        "summary": "Broken second candidate",
                        "notes": ["schema invalid"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": serde_json::Value::Null
                        }]
                    })
                } else {
                    serde_json::json!({
                        "summary": format!("{candidate_id} rollout lab"),
                        "notes": [format!("{candidate_id} initial draft")],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": format!(
                                "<!doctype html><html><body><main><section><h1>Instacart MCP rollout</h1><p>Inspect the rollout stages and early metrics.</p><button type=\"button\" data-view=\"timeline\" aria-controls=\"timeline-panel\" aria-selected=\"true\">Timeline</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics</button></section><section id=\"timeline-panel\" data-view-panel=\"timeline\"><article class=\"chart\"><h2>Rollout chart preview</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"{candidate_id} rollout preview\"><rect x=\"20\" y=\"48\" width=\"36\" height=\"52\" tabindex=\"0\" data-detail=\"Pilot stores\"></rect><rect x=\"82\" y=\"36\" width=\"36\" height=\"64\" tabindex=\"0\" data-detail=\"Launch readiness\"></rect><rect x=\"144\" y=\"28\" width=\"36\" height=\"72\" tabindex=\"0\" data-detail=\"Owner sign-off\"></rect><text x=\"20\" y=\"114\">Pilot</text><text x=\"82\" y=\"114\">Launch</text><text x=\"144\" y=\"114\">Owners</text></svg></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics evidence</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Order accuracy</td><td>99%</td></tr><tr><td>Support deflection</td><td>18%</td></tr></table></article></section><aside><h2>Clickable detail panel</h2><p id=\"detail-copy\">Timeline is selected by default for {candidate_id}.</p></aside><footer><p>Charts and metrics need denser interactions before acceptance.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{{panels.forEach((panel)=>{{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;}});document.querySelectorAll('button[data-view]').forEach((control)=>{{control.setAttribute('aria-selected', String(control===button));}});detail.textContent=button.dataset.view + ' selected for {candidate_id}.';}}));document.querySelectorAll('svg [data-detail]').forEach((mark)=>{{mark.addEventListener('mouseenter',()=>{{detail.textContent='Tooltip: ' + mark.dataset.detail;}});mark.addEventListener('focus',()=>{{detail.textContent='Focus: ' + mark.dataset.detail;}});}});</script></main></body></html>"
                            )
                        }]
                    })
                }
            }
            "refine" | "refine_repair" => serde_json::json!({
                "summary": "Refined rollout lab",
                "notes": ["semantic refinement pass"],
                "files": [{
                    "path": "index.html",
                    "mime": "text/html",
                    "role": "primary",
                    "renderable": true,
                    "downloadable": true,
                    "encoding": "utf8",
                    "body": "<!doctype html><html><body><main><section><h1>Instacart MCP product rollout</h1><p>Hover the milestone rail and click each metric card to inspect the launch evidence.</p><button type=\"button\" data-view=\"timeline\" aria-controls=\"timeline-panel\" aria-selected=\"true\">Timeline view</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics view</button></section><section id=\"timeline-panel\" data-view-panel=\"timeline\"><article><h2>Milestone timeline</h2><ul><li tabindex=\"0\" data-detail=\"dark-store pilot\">Pilot stores onboarded</li><li tabindex=\"0\" data-detail=\"regional launch\">Regional launch review</li><li tabindex=\"0\" data-detail=\"owner sign-off\">Owner sign-off</li></ul></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Charts and metrics</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Adoption lift</td><td>24%</td></tr><tr><td>Order accuracy</td><td>99%</td></tr><tr><td>Support deflection</td><td>18%</td></tr></table><p>Adoption lift, order accuracy, and support deflection are visible on first paint.</p></article></section><article><h2>Owner evidence</h2><ul><li>Ops captain owns pilot approvals and milestone sequencing.</li><li>Support lead owns launch-day triage and retailer readiness notes.</li></ul></article><aside><h2>Clickable detail panel</h2><p>Select a milestone or metric card to compare owners, timing, and impact.</p></aside><footer><p>Instacart MCP launch evidence stays request-faithful and interactive.</p></footer><script>const buttons=document.querySelectorAll('button[data-view]');const panels=document.querySelectorAll('[data-view-panel]');const detail=document.querySelector('aside p');buttons.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});buttons.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=`${button.dataset.view} selected for Instacart MCP rollout review.`;}));document.querySelectorAll('[data-detail]').forEach((item)=>{item.addEventListener('mouseenter',()=>{detail.textContent=`Tooltip: ${item.dataset.detail}`;});item.addEventListener('click',()=>{detail.textContent=`Clicked milestone: ${item.dataset.detail}`;});item.addEventListener('focus',()=>{detail.textContent=`Focus: ${item.dataset.detail}`;});});</script></main></body></html>"
                }]
            }),
            "judge" => {
                if self.role == "acceptance" {
                    if prompt.contains("Refined rollout lab") {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 5,
                            "conceptCoverage": 5,
                            "interactionRelevance": 5,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 4,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Acceptance cleared the refined creative candidate."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 3,
                            "conceptCoverage": 3,
                            "interactionRelevance": 2,
                            "layoutCoherence": 3,
                            "visualHierarchy": 3,
                            "completeness": 2,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "needs real charts and denser interactions",
                            "rationale": "Acceptance requires a stronger request-faithful artifact."
                        })
                    }
                } else if prompt.contains("candidate-1 rollout lab") {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 4,
                        "conceptCoverage": 4,
                        "interactionRelevance": 3,
                        "layoutCoherence": 4,
                        "visualHierarchy": 3,
                        "completeness": 3,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "Production prefers candidate-1 before refinement."
                    })
                } else {
                    serde_json::json!({
                        "classification": "repairable",
                        "requestFaithfulness": 3,
                        "conceptCoverage": 3,
                        "interactionRelevance": 3,
                        "layoutCoherence": 3,
                        "visualHierarchy": 3,
                        "completeness": 2,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": "draft is still too thin",
                        "rationale": "Production saw a repairable draft."
                    })
                }
            }
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };

        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[tokio::test]
async fn creative_renderer_refines_best_candidate_before_final_selection() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioSemanticRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            "local producer",
            "qwen2.5:7b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioSemanticRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote acceptance",
            "gpt-4.1",
            "https://api.openai.com/v1/chat/completions",
            "acceptance",
            calls.clone(),
        ));

    let bundle = generate_studio_artifact_bundle_with_runtimes(
            production_runtime,
            acceptance_runtime,
            "Instacart rollout artifact",
            "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            None,
        )
        .await
        .expect("bundle should generate");

    assert_eq!(bundle.winning_candidate_id, "candidate-1-refine-1");
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_eq!(
        bundle.judge.rationale,
        "Acceptance cleared the refined creative candidate."
    );
    assert_eq!(
        bundle
            .candidate_summaries
            .iter()
            .find(|candidate| candidate.selected)
            .map(|candidate| candidate.candidate_id.as_str()),
        Some("candidate-1-refine-1")
    );
    let refined_summary = bundle
        .candidate_summaries
        .iter()
        .find(|candidate| candidate.candidate_id == "candidate-1-refine-1")
        .expect("refined summary should exist");
    let convergence = refined_summary
        .convergence
        .as_ref()
        .expect("refined summary should record convergence");
    assert_eq!(convergence.lineage_root_id, "candidate-1");
    assert_eq!(
        convergence.parent_candidate_id.as_deref(),
        Some("candidate-1")
    );
    assert_eq!(convergence.pass_kind, "structural_repair");
    assert_eq!(convergence.pass_index, 1);
    assert!(convergence.score_total > 0);
    assert!(convergence.score_delta_from_parent.unwrap_or_default() > 0);
    assert_eq!(
        convergence.terminated_reason.as_deref(),
        Some("selected_after_primary_view_clear")
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert!(recorded_calls
        .iter()
        .any(|call| call == "acceptance:refine"));
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:judge")
            .count(),
        2
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:judge")
            .count(),
        2
    );
}

#[derive(Clone)]
struct StudioConvergencePlateauTestRuntime {
    provenance: StudioRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioConvergencePlateauTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materialization repairer") {
            "materialize_repair"
        } else if prompt.contains("typed artifact refinement repairer") {
            "refine_repair"
        } else if prompt.contains("typed artifact refiner") {
            "refine"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else if prompt.contains("typed artifact judge") {
            "judge"
        } else {
            "unknown"
        };
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{stage}", self.role));

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "launch operators",
                "jobToBeDone": "review rollout evidence with charts and detail panels",
                "subjectDomain": "Instacart MCP launch",
                "artifactThesis": "show readiness, metrics, and owners in an interactive artifact",
                "requiredConcepts": ["Instacart", "MCP", "readiness", "metrics"],
                "requiredInteractions": ["clickable navigation", "rollover detail"],
                "visualTone": ["operational"],
                "factualAnchors": ["launch readiness"],
                "styleDirectives": ["clear hierarchy"],
                "referenceHints": []
            }),
            "materialize" | "materialize_repair" => {
                let candidate_id = if prompt.contains("\"candidateId\":\"candidate-1\"") {
                    "candidate-1"
                } else {
                    "candidate-2"
                };
                let body = if candidate_id == "candidate-1" {
                    "<!doctype html><html><body><main><section><h1>Instacart MCP launch review</h1><p>Inspect readiness, metrics, and launch owners.</p><button type=\"button\" data-view=\"readiness\" aria-controls=\"readiness-panel\" aria-selected=\"true\">Readiness</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics</button></section><section id=\"readiness-panel\" data-view-panel=\"readiness\"><article><h2>Readiness chart</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Readiness chart\"><rect x=\"20\" y=\"52\" width=\"40\" height=\"48\" tabindex=\"0\" data-detail=\"Pilot approvals\"></rect><rect x=\"84\" y=\"38\" width=\"40\" height=\"62\" tabindex=\"0\" data-detail=\"Support readiness\"></rect><text x=\"20\" y=\"114\">Pilot</text><text x=\"84\" y=\"114\">Support</text></svg></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics table</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Order accuracy</td><td>99%</td></tr><tr><td>Support deflection</td><td>18%</td></tr></table></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Readiness is selected by default.</p></aside><footer><p>The first draft still needs denser evidence.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');const controls=document.querySelectorAll('button[data-view]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});controls.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=button.dataset.view + ' selected.';}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
                } else {
                    "<!doctype html><html><body><main><section><h1>Backup launch review</h1><p>Thinner backup layout.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\" aria-selected=\"true\">Overview</button><button type=\"button\" data-view=\"owners\" aria-controls=\"owners-panel\" aria-selected=\"false\">Owners</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Backup evidence.</p></article></section><section id=\"owners-panel\" data-view-panel=\"owners\" hidden><article><h2>Owners</h2><p>Backup ownership notes stay pre-rendered for comparison.</p></article></section><aside><p id=\"detail-copy\">Overview is selected.</p></aside><footer><p>Weaker backup.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');const controls=document.querySelectorAll('button[data-view]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});controls.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
                };
                serde_json::json!({
                    "summary": format!("{candidate_id} plateau draft"),
                    "notes": [format!("{candidate_id} initial draft")],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": body
                    }]
                })
            }
            "refine" | "refine_repair" => serde_json::json!({
                "summary": "Plateau refined rollout lab",
                "notes": ["plateau refinement pass"],
                "files": [{
                    "path": "index.html",
                    "mime": "text/html",
                    "role": "primary",
                    "renderable": true,
                    "downloadable": true,
                    "encoding": "utf8",
                    "body": "<!doctype html><html><body><main><section><h1>Instacart MCP launch review</h1><p>Inspect readiness, metrics, and owner evidence.</p><button type=\"button\" data-view=\"readiness\" aria-controls=\"readiness-panel\" aria-selected=\"true\">Readiness</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics</button></section><section id=\"readiness-panel\" data-view-panel=\"readiness\"><article><h2>Readiness chart</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Readiness chart\"><rect x=\"20\" y=\"52\" width=\"40\" height=\"48\" tabindex=\"0\" data-detail=\"Pilot approvals\"></rect><rect x=\"84\" y=\"38\" width=\"40\" height=\"62\" tabindex=\"0\" data-detail=\"Support readiness\"></rect><text x=\"20\" y=\"114\">Pilot</text><text x=\"84\" y=\"114\">Support</text></svg></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics table</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Order accuracy</td><td>99%</td></tr><tr><td>Support deflection</td><td>18%</td></tr></table></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Readiness is selected by default.</p></aside><footer><p>The refinement stayed truthful but did not improve the score.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');const controls=document.querySelectorAll('button[data-view]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});controls.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=button.dataset.view + ' selected.';}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
                }]
            }),
            "judge" => {
                if self.role == "acceptance" {
                    if prompt.contains("Plateau refined rollout lab") {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 4,
                            "conceptCoverage": 4,
                            "interactionRelevance": 3,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "issueClasses": ["evidence_density"],
                            "repairHints": ["Increase first-paint evidence density."],
                            "strengths": ["The artifact stays request-faithful."],
                            "blockedReasons": [],
                            "fileFindings": ["index.html: evidence density is unchanged."],
                            "aestheticVerdict": "Hierarchy remains stable.",
                            "interactionVerdict": "Interactions are truthful but unchanged.",
                            "truthfulnessWarnings": [],
                            "recommendedNextPass": "structural_repair",
                            "strongestContradiction": "Evidence density did not improve.",
                            "rationale": "Acceptance still wants denser evidence."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 4,
                            "conceptCoverage": 4,
                            "interactionRelevance": 3,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "issueClasses": ["evidence_density"],
                            "repairHints": ["Increase first-paint evidence density."],
                            "strengths": ["The artifact is request-faithful."],
                            "blockedReasons": [],
                            "fileFindings": ["index.html: evidence density is still thin."],
                            "aestheticVerdict": "Hierarchy is serviceable.",
                            "interactionVerdict": "Interactions are visible but still thin.",
                            "truthfulnessWarnings": [],
                            "recommendedNextPass": "structural_repair",
                            "strongestContradiction": "Evidence density is still thin.",
                            "rationale": "Acceptance wants denser evidence before promotion."
                        })
                    }
                } else if prompt.contains("candidate-1 plateau draft") {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 4,
                        "conceptCoverage": 4,
                        "interactionRelevance": 4,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 4,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "Production prefers the primary plateau draft."
                    })
                } else {
                    serde_json::json!({
                        "classification": "repairable",
                        "requestFaithfulness": 2,
                        "conceptCoverage": 2,
                        "interactionRelevance": 2,
                        "layoutCoherence": 2,
                        "visualHierarchy": 2,
                        "completeness": 2,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": false,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": "Backup draft is too thin.",
                        "rationale": "Production sees a weak backup."
                    })
                }
            }
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };

        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[tokio::test]
async fn semantic_refinement_stops_after_plateau_and_preserves_best_candidate() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioConvergencePlateauTestRuntime {
            provenance: StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "local producer".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            },
            role: "production",
            calls: calls.clone(),
        });
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioConvergencePlateauTestRuntime {
            provenance: StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
                label: "remote acceptance".to_string(),
                model: Some("gpt-4.1".to_string()),
                endpoint: Some("https://api.openai.com/v1/chat/completions".to_string()),
            },
            role: "acceptance",
            calls: calls.clone(),
        });

    let bundle = generate_studio_artifact_bundle_with_runtimes(
        production_runtime,
        acceptance_runtime,
        "Instacart launch artifact",
        "Create an interactive HTML artifact that explains an Instacart MCP launch",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("bundle should generate");

    assert_eq!(bundle.winning_candidate_id, "candidate-1");
    let plateau_summary = bundle
        .candidate_summaries
        .iter()
        .find(|candidate| candidate.candidate_id == "candidate-1-refine-1")
        .expect("plateau refinement should be recorded");
    let convergence = plateau_summary
        .convergence
        .as_ref()
        .expect("plateau refinement should record convergence");
    assert_eq!(convergence.lineage_root_id, "candidate-1");
    assert_eq!(
        convergence.parent_candidate_id.as_deref(),
        Some("candidate-1")
    );
    assert_eq!(convergence.pass_kind, "structural_repair");
    assert_eq!(convergence.pass_index, 1);
    assert_eq!(convergence.score_delta_from_parent, Some(0));
    assert_eq!(
        convergence.terminated_reason.as_deref(),
        Some("plateau_after_rejudge")
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:refine")
            .count(),
        2
    );
}

#[tokio::test]
async fn local_creative_renderer_surfaces_draft_before_local_acceptance() {
    #[derive(Clone)]
    struct LocalDraftFastPathRuntime {
        provenance: StudioRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for LocalDraftFastPathRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief"
            } else if prompt.contains("typed artifact brief repair") {
                "brief"
            } else if prompt.contains("typed artifact refiner") {
                "refine"
            } else if prompt.contains("typed artifact materializer") {
                "materialize"
            } else if prompt.contains("typed artifact judge") {
                "judge"
            } else {
                "unknown"
            };
            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("{}:{stage}", self.role));

            if self.role == "acceptance" && stage == "judge" {
                return Err(VmError::HostError(
                    "local acceptance should not run before surfacing the draft".to_string(),
                ));
            }

            let response = match stage {
                "brief" => serde_json::json!({
                    "audience": "launch operators",
                    "jobToBeDone": "review the rollout draft interactively",
                    "subjectDomain": "launch planning",
                    "artifactThesis": "surface a request-faithful interactive launch draft",
                    "requiredConcepts": ["launch plan", "owners", "readiness"],
                    "requiredInteractions": [
                        "click to compare launch phases",
                        "hover to inspect owner details"
                    ],
                    "visualTone": ["clear", "operational"],
                    "factualAnchors": ["launch readiness"],
                    "styleDirectives": ["compact hierarchy"],
                    "referenceHints": []
                }),
                "materialize" => {
                    let candidate_id = if prompt.contains("\"candidateId\":\"candidate-1\"") {
                        "candidate-1"
                    } else {
                        "candidate-2"
                    };
                    let is_primary_candidate = candidate_id == "candidate-1";
                    serde_json::json!({
                        "summary": format!("{candidate_id} launch review"),
                        "notes": [format!("{candidate_id} draft")],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": if is_primary_candidate {
                                "<!doctype html><html><head><style>body{font-family:system-ui;background:#f6f1e7;color:#201a14;}main{display:grid;gap:1rem;padding:1.5rem;}section,article,aside,footer{background:#fffdf8;border:1px solid #d7ccb8;border-radius:16px;padding:1rem;}nav{display:flex;gap:0.5rem;flex-wrap:wrap;}button{border:1px solid #8d6e3f;background:#f2e3c7;border-radius:999px;padding:0.45rem 0.8rem;}strong{display:block;margin-bottom:0.35rem;}</style></head><body><main><section><h1>Launch review command deck</h1><p>Review readiness, owner handoffs, and launch-day support coverage from one draft artifact.</p><nav><button type=\"button\" data-view=\"readiness\">Readiness</button><button type=\"button\" data-view=\"owners\">Owners</button></nav></section><article data-view-panel=\"readiness\"><strong>Readiness snapshot</strong><p>Regional approvals, support staffing, and launch-day comms are visible on first paint so the draft already supports follow-up edits.</p></article><article data-view-panel=\"owners\" hidden><strong>Owner handoff</strong><p>Each phase maps the release manager, support lead, and analytics reviewer to the next decision point.</p></article><aside><strong>Shared detail</strong><p id=\"detail-copy\">Readiness is selected by default.</p></aside><footer><p>This draft is request-faithful and intentionally compact so refinement can deepen the artifact without restarting from scratch.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected for launch review.';}));</script></main></body></html>"
                            } else {
                                "<!doctype html><html><head><style>body{font-family:system-ui;background:#f7f4ef;color:#241f1a;}main{display:grid;gap:1rem;padding:1.5rem;}section,article,aside,footer{background:#fffdf8;border:1px solid #ddd1be;border-radius:16px;padding:1rem;}button{border:1px solid #9b8359;background:#efe1c9;border-radius:999px;padding:0.45rem 0.8rem;}</style></head><body><main><section><h1>Launch review</h1><p>Compact rollout copy with lighter evidence density.</p><button type=\"button\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"risks\">Risks</button></section><article data-view-panel=\"overview\"><p>Overview panel stays visible on first paint.</p></article><article data-view-panel=\"risks\" hidden><p>Risk panel remains pre-rendered for comparison.</p></article><aside><p id=\"detail-copy\">Overview is selected.</p></aside><footer><p>Needs a stronger owner model.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
                            }
                        }]
                    })
                }
                "judge" => {
                    if prompt.contains("candidate-1 launch review") {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 4,
                            "conceptCoverage": 4,
                            "interactionRelevance": 4,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 4,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Production prefers the stronger launch draft."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 3,
                            "conceptCoverage": 3,
                            "interactionRelevance": 3,
                            "layoutCoherence": 3,
                            "visualHierarchy": 3,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "Needs denser owner evidence.",
                            "rationale": "Production sees a weaker backup draft."
                        })
                    }
                }
                _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
            };

            Ok(response.to_string().into_bytes())
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            self.provenance.clone()
        }
    }

    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(LocalDraftFastPathRuntime {
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "local producer".to_string(),
            model: Some("qwen2.5:7b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        role: "production",
        calls: calls.clone(),
    });
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(LocalDraftFastPathRuntime {
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "local acceptance".to_string(),
            model: Some("qwen2.5:14b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        role: "acceptance",
        calls: calls.clone(),
    });

    let bundle = generate_studio_artifact_bundle_with_runtimes(
        production_runtime,
        acceptance_runtime,
        "Launch review artifact",
        "Create an interactive HTML artifact that explains a launch review",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("bundle should generate");

    assert_eq!(bundle.winning_candidate_id, "candidate-1");
    assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Draft);
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert_eq!(
        bundle.judge.strongest_contradiction.as_deref(),
        Some("Acceptance judging is still pending for this draft.")
    );
    assert_eq!(
        bundle
            .candidate_summaries
            .iter()
            .find(|candidate| candidate.selected)
            .map(|candidate| candidate.candidate_id.as_str()),
        Some("candidate-1")
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:judge")
            .count(),
        2
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:judge")
            .count(),
        0
    );
}

#[test]
fn html_materialization_prompt_prioritizes_factual_anchors_in_first_paint_guidance() {
    let brief = StudioArtifactBrief {
        audience: "Instacart MCP team members".to_string(),
        job_to_be_done: "understand the rollout with interactive visualizations".to_string(),
        subject_domain: "Instacart operations".to_string(),
        artifact_thesis: "Provide an interactive HTML artifact that explains the product rollout."
            .to_string(),
        required_concepts: vec![
            "product rollout".to_string(),
            "charts".to_string(),
            "Instacart".to_string(),
            "MCP".to_string(),
        ],
        required_interactions: vec![
            "rollover tooltips".to_string(),
            "clickable elements".to_string(),
            "scrolling through timeline".to_string(),
        ],
        visual_tone: vec!["informative".to_string(), "data-driven".to_string()],
        factual_anchors: vec![
            "key milestones of the product rollout".to_string(),
            "performance metrics related to the product".to_string(),
        ],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["previous product rollouts at Instacart".to_string()],
    };

    let prompt = build_studio_artifact_materialization_prompt(
        "Instacart rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &brief,
        None,
        None,
        "candidate-1",
        42,
    )
    .expect("prompt should build");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains(
        "primary evidence section that visualizes key milestones of the product rollout"
    ));
    assert!(prompt_text.contains(
        "secondary evidence section or comparison article that surfaces performance metrics related to the product"
    ));
    assert!(prompt_text.contains(
        "Dedicate a first-paint evidence surface directly to this factual anchor: key milestones of the product rollout."
    ));
    assert!(prompt_text.contains(
        "Dedicate a second named evidence surface or comparison rail directly to this factual anchor: performance metrics related to the product."
    ));
    assert!(prompt_text.contains(
        "A static chart plus unrelated panel toggles does not satisfy sequence browsing."
    ));
}

#[test]
fn html_materialization_prompt_marks_sequence_browsing_as_optional_when_not_required() {
    let brief = StudioArtifactBrief {
        audience: "dog owners".to_string(),
        job_to_be_done: "inspect the rollout with interactive charts".to_string(),
        subject_domain: "pet care".to_string(),
        artifact_thesis: "Explain the dog shampoo rollout through interactive charts.".to_string(),
        required_concepts: vec![
            "dog shampoo".to_string(),
            "product rollout".to_string(),
            "customer satisfaction".to_string(),
        ],
        required_interactions: vec![
            "click to compare sales data".to_string(),
            "hover to inspect market trends".to_string(),
        ],
        visual_tone: vec!["informative".to_string()],
        factual_anchors: vec!["APPA market data".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: Vec::new(),
    };

    let prompt = build_studio_artifact_materialization_prompt(
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &brief,
        None,
        None,
        "candidate-1",
        7,
    )
    .expect("prompt should build");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("\"sequenceBrowsingRequired\": false"));
    assert!(prompt_text.contains(
        "Apply sequence-browsing requirements only when interactionContract.sequenceBrowsingRequired is true."
    ));
    assert!(!prompt_text.contains(
        "- When a requiredInteraction implies sequence browsing, timeline traversal, or scrolling through staged evidence, give it its own visible progression mechanism on first paint such as a stepper, previous/next controls, a scrubber, or a scroll-snap evidence rail."
    ));
}

#[test]
fn pdf_materialization_prompt_requests_bullets_and_metric_tables() {
    let brief = StudioArtifactBrief {
        audience: "launch stakeholders".to_string(),
        job_to_be_done: "review the launch brief quickly".to_string(),
        subject_domain: "launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a concise PDF.".to_string(),
        required_concepts: vec![
            "launch brief".to_string(),
            "milestones".to_string(),
            "risks".to_string(),
            "timeline".to_string(),
        ],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: vec![
            "target audience".to_string(),
            "marketing strategy".to_string(),
            "budget constraints".to_string(),
        ],
        style_directives: vec![
            "use bullet points for clarity".to_string(),
            "include relevant charts or graphs if space allows".to_string(),
        ],
        reference_hints: Vec::new(),
    };

    let prompt = build_studio_artifact_materialization_prompt(
        "Launch brief PDF",
        "Create a PDF artifact that summarizes a launch brief",
        &request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed),
        &brief,
        None,
        None,
        "candidate-1",
        11,
    )
    .expect("prompt should build");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("Use a compact briefing structure"));
    assert!(prompt_text.contains("plain document text"));
    assert!(prompt_text.contains("Do not emit LaTeX"));
    assert!(prompt_text.contains("Write at least 120 words"));
    assert!(prompt_text.contains("at least five non-empty sections"));
    assert!(prompt_text.contains("no trailing colon"));
    assert!(prompt_text.contains("Do not use square-bracket placeholder tokens"));
    assert!(prompt_text.contains("bullet lists"));
    assert!(prompt_text.contains("compact text table"));
    assert!(prompt_text.contains("metric tables"));
}

#[test]
fn svg_materialization_prompt_requires_layered_supporting_marks() {
    let brief = StudioArtifactBrief {
        audience: "AI tools brand stakeholders".to_string(),
        job_to_be_done: "review a bold visual concept".to_string(),
        subject_domain: "AI tools brand storytelling".to_string(),
        artifact_thesis: "Create a strong hero concept for an AI tools brand.".to_string(),
        required_concepts: vec![
            "AI".to_string(),
            "tools".to_string(),
            "innovation".to_string(),
        ],
        required_interactions: Vec::new(),
        visual_tone: vec!["modern".to_string()],
        factual_anchors: vec!["automation".to_string()],
        style_directives: vec!["strong hierarchy".to_string()],
        reference_hints: Vec::new(),
    };

    let prompt = build_studio_artifact_materialization_prompt(
        "AI tools hero",
        "Create an SVG hero concept for an AI tools brand",
        &request_for(StudioArtifactClass::Visual, StudioRendererKind::Svg),
        &brief,
        None,
        None,
        "candidate-1",
        5,
    )
    .expect("prompt should build");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("at least six visible SVG content elements"));
    assert!(prompt_text.contains("Pair the focal motif with supporting labels"));
    assert!(prompt_text.contains("Do not stop at one background shape plus one headline"));
}

#[test]
fn pdf_artifact_bytes_emit_real_pdf_structure() {
    let pdf = pdf_artifact_bytes(
        "Launch brief",
        "Executive summary\n\nThis launch brief includes the goals, rollout plan, owner table, milestone timeline, and verification notes for the artifact stage.",
    );
    let pdf_text = String::from_utf8_lossy(&pdf);

    assert!(pdf.starts_with(b"%PDF-1.4\n"));
    assert!(pdf.len() > 800);
    assert!(!pdf_text.contains("Studio mock PDF"));
    assert!(pdf_text.contains("xref"));
    assert!(pdf_text.contains("Launch brief"));
}

#[test]
fn extract_searchable_pdf_text_recovers_visible_copy() {
    let pdf = pdf_artifact_bytes(
        "Launch brief",
        "Executive summary\n\nThis launch brief includes goals, rollout plan, owner table, and verification notes.",
    );
    let extracted = extract_searchable_pdf_text(&pdf);

    assert!(extracted.contains("Launch brief"));
    assert!(extracted.contains("Executive summary"));
    assert!(extracted.contains("Launch brief\n\nExecutive summary"));
    assert!(count_pdf_structural_sections(&extracted) >= 2);
    assert!(!extracted.contains("xref"));
}

#[test]
fn rejects_generated_pdf_payload_when_source_uses_latex_markup() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed);
    let payload = StudioGeneratedArtifactPayload {
        summary: "Launch brief PDF".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "launch-brief.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "\\documentclass{article}\n\\begin{document}\n\\section*{Executive Summary}\nLaunch brief body.\n\\end{document}".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(&payload, &request)
        .expect_err("latex-backed PDF source should be rejected");
    assert!(error.contains("plain document text"));
}

#[test]
fn rejects_generated_pdf_payload_when_source_uses_bracket_placeholders() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::PdfEmbed);
    let payload = StudioGeneratedArtifactPayload {
        summary: "Launch brief PDF".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "launch-brief.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "Executive Summary\n\nThis launch brief summarizes project scope, target audience, rollout timing, and risk review for the approval meeting.\n\nProject Scope\n\n- Objective: [Detailed objective]\n- Deliverables: launch plan and support readiness.\n\nTarget Audience\n\n- Audience: [Detailed audience segment]\n- Regions: North America and Europe.\n\nMarketing Strategy\n\n- Channels: paid search, email, and retail partners.\n- Message: practical value and trust.\n\nTimeline and Milestones\n\n- Kickoff: May.\n- Launch: June.\n\nNext Steps and Risks\n\n- Action: finalize owner signoff.\n- Risk: [Detailed risk note]".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(&payload, &request)
        .expect_err("bracket placeholder PDF source should be rejected");
    assert!(error.contains("bracketed placeholder copy"));
}

#[test]
fn download_card_materialization_prompt_requires_non_empty_csv_and_readme() {
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "download the bundle exports".to_string(),
        subject_domain: "artifact bundles".to_string(),
        artifact_thesis: "Deliver a CSV and README bundle.".to_string(),
        required_concepts: vec![
            "csv export".to_string(),
            "readme".to_string(),
            "bundle contents".to_string(),
        ],
        required_interactions: Vec::new(),
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec!["launch metrics".to_string()],
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };

    let prompt = build_studio_artifact_materialization_prompt(
        "Download bundle",
        "Create a downloadable artifact bundle with a CSV and README",
        &request_for(
            StudioArtifactClass::DownloadableFile,
            StudioRendererKind::DownloadCard,
        ),
        &brief,
        None,
        None,
        "candidate-1",
        19,
    )
    .expect("prompt should build");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("non-empty export files only"));
    assert!(prompt_text.contains("README.md"));
    assert!(prompt_text.contains("header row plus at least two data rows"));
    assert!(prompt_text.contains("do not mark any file renderable"));
}

#[test]
fn html_refinement_prompt_keeps_anchor_specific_evidence_surfaces() {
    let brief = StudioArtifactBrief {
        audience: "Instacart MCP team members".to_string(),
        job_to_be_done: "understand the rollout with interactive visualizations".to_string(),
        subject_domain: "Instacart operations".to_string(),
        artifact_thesis: "Provide an interactive HTML artifact that explains the product rollout."
            .to_string(),
        required_concepts: vec![
            "product rollout".to_string(),
            "charts".to_string(),
            "Instacart".to_string(),
            "MCP".to_string(),
        ],
        required_interactions: vec![
            "rollover tooltips".to_string(),
            "clickable elements".to_string(),
            "scrolling through timeline".to_string(),
        ],
        visual_tone: vec!["informative".to_string(), "data-driven".to_string()],
        factual_anchors: vec![
            "key milestones of the product rollout".to_string(),
            "performance metrics related to the product".to_string(),
        ],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["previous product rollouts at Instacart".to_string()],
    };
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Interactive rollout overview".to_string(),
        notes: vec!["initial pass".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>Instacart rollout</h1></section></main></body></html>".to_string(),
        }],
    };
    let judge = StudioArtifactJudgeResult {
        classification: StudioArtifactJudgeClassification::Repairable,
        request_faithfulness: 3,
        concept_coverage: 3,
        interaction_relevance: 2,
        layout_coherence: 4,
        visual_hierarchy: 4,
        completeness: 2,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: true,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes: vec!["interaction_truthfulness".to_string()],
        repair_hints: vec![
            "Add the missing timeline, metrics, and interactive response surfaces.".to_string(),
        ],
        strengths: vec!["The rollout framing is established.".to_string()],
        blocked_reasons: Vec::new(),
        file_findings: vec![
            "index.html: missing requested timeline and metrics surfaces.".to_string(),
        ],
        aesthetic_verdict: "The surface is too thin to sustain the requested artifact hierarchy."
            .to_string(),
        interaction_verdict:
            "The artifact still lacks the requested interactive timeline and metrics behaviors."
                .to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("structural_repair".to_string()),
        strongest_contradiction: Some(
            "Missing interactive timeline and performance metrics.".to_string(),
        ),
        rationale: "Candidate lacks required interactions and visual elements.".to_string(),
    };

    let prompt = build_studio_artifact_candidate_refinement_prompt(
        "Instacart rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &brief,
        None,
        None,
        &candidate,
        &judge,
        "candidate-1",
        42,
    )
    .expect("refinement prompt should build");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains(
        "Dedicate one named first-paint evidence surface directly to this factual anchor: key milestones of the product rollout."
    ));
    assert!(prompt_text.contains(
        "Dedicate a second named evidence surface, comparison rail, or preview directly to this factual anchor: performance metrics related to the product."
    ));
    assert!(prompt_text.contains(
        "Do not satisfy a multi-interaction brief with only one button row and a single shared panel toggle."
    ));
    assert!(prompt_text.contains(
        "A static chart plus unrelated panel toggles does not satisfy sequence browsing."
    ));
}

#[tokio::test]
async fn creative_renderer_refinement_survives_failed_materialization_candidates() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioSemanticRefinementTestRuntime::new_with_options(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote producer",
            "gpt-4.1-mini",
            "https://api.openai.com/v1/chat/completions",
            "production",
            calls.clone(),
            true,
        ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioSemanticRefinementTestRuntime::new_with_options(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote acceptance",
            "gpt-4.1",
            "https://api.openai.com/v1/chat/completions",
            "acceptance",
            calls.clone(),
            true,
        ));

    let bundle = generate_studio_artifact_bundle_with_runtimes(
        production_runtime,
        acceptance_runtime,
        "Instacart rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("bundle should generate");

    assert_eq!(bundle.winning_candidate_id, "candidate-1-refine-1");
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert!(bundle
        .candidate_summaries
        .iter()
        .any(|candidate| candidate.candidate_id == "candidate-2" && candidate.failure.is_some()));
    assert_eq!(
        bundle
            .candidate_summaries
            .iter()
            .find(|candidate| candidate.selected)
            .map(|candidate| candidate.candidate_id.as_str()),
        Some("candidate-1-refine-1")
    );
}

#[derive(Clone)]
struct StudioFallbackRefinementTestRuntime {
    provenance: StudioRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl StudioFallbackRefinementTestRuntime {
    fn new(
        kind: StudioRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            provenance: StudioRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
            role,
            calls,
        }
    }
}

#[async_trait]
impl InferenceRuntime for StudioFallbackRefinementTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materialization repairer") {
            "materialize_repair"
        } else if prompt.contains("typed artifact refinement repairer") {
            "refine_repair"
        } else if prompt.contains("typed artifact refiner") {
            "refine"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else if prompt.contains("typed artifact judge") {
            "judge"
        } else {
            "unknown"
        };
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{stage}", self.role));

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "Instacart MCP operators",
                "jobToBeDone": "understand the rollout with interactive evidence",
                "subjectDomain": "Instacart MCP rollout",
                "artifactThesis": "show the rollout through charts, milestones, and click-through details",
                "requiredConcepts": ["Instacart", "MCP", "charts", "product rollout"],
                "requiredInteractions": ["rollover tooltips", "clickable elements", "scrolling through timeline"],
                "visualTone": ["data-driven"],
                "factualAnchors": ["key milestones", "performance metrics"],
                "styleDirectives": ["concise labels", "clear hierarchy"],
                "referenceHints": []
            }),
            "materialize" | "materialize_repair" => {
                let candidate_id = if prompt.contains("\"candidateId\":\"candidate-1\"") {
                    "candidate-1"
                } else {
                    "candidate-2"
                };
                serde_json::json!({
                    "summary": format!("{candidate_id} draft"),
                    "notes": [format!("{candidate_id} draft")],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": format!(
                            "<!doctype html><html><body><main><section><h1>{candidate_id}</h1><p>Inspect the rollout stages and metrics.</p><button type=\"button\" data-view=\"timeline\" aria-controls=\"timeline-panel\" aria-selected=\"true\">Timeline</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics</button></section><section id=\"timeline-panel\" data-view-panel=\"timeline\"><article><h2>Timeline evidence</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"{candidate_id} rollout timeline\"><rect x=\"20\" y=\"48\" width=\"36\" height=\"52\" tabindex=\"0\" data-detail=\"Pilot stores\"></rect><rect x=\"82\" y=\"36\" width=\"36\" height=\"64\" tabindex=\"0\" data-detail=\"Launch readiness\"></rect><rect x=\"144\" y=\"28\" width=\"36\" height=\"72\" tabindex=\"0\" data-detail=\"Owner sign-off\"></rect><text x=\"20\" y=\"114\">Pilot</text><text x=\"82\" y=\"114\">Launch</text><text x=\"144\" y=\"114\">Owners</text></svg></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics evidence</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Order accuracy</td><td>99%</td></tr></table></article></section><aside><h2>Clickable detail panel</h2><p id=\"detail-copy\">Timeline is selected by default for {candidate_id}.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{{panels.forEach((panel)=>{{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;}});document.querySelectorAll('button[data-view]').forEach((control)=>{{control.setAttribute('aria-selected', String(control===button));}});detail.textContent=button.dataset.view + ' selected for {candidate_id}.';}}));document.querySelectorAll('[data-detail]').forEach((mark)=>{{mark.addEventListener('mouseenter',()=>{{detail.textContent=mark.dataset.detail;}});mark.addEventListener('focus',()=>{{detail.textContent=mark.dataset.detail;}});}});</script></main></body></html>"
                        )
                    }]
                })
            }
            "refine" => {
                let refined_candidate_id =
                    if prompt.contains("\"candidateId\":\"candidate-1-refine-1\"") {
                        "candidate-1-refine-1"
                    } else {
                        "candidate-2-refine-1"
                    };
                serde_json::json!({
                    "summary": format!("{refined_candidate_id} refined"),
                    "notes": [format!("{refined_candidate_id} refinement")],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": format!(
                            "<!doctype html><html><body><main><section><h1>{refined_candidate_id}</h1><p>Inspect the rollout stages, performance metrics, and timeline controls.</p><button type=\"button\" data-view=\"timeline\" aria-controls=\"timeline-panel\" aria-selected=\"true\">Timeline</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics</button><button type=\"button\" id=\"timeline-next\">Next milestone</button></section><section id=\"timeline-panel\" data-view-panel=\"timeline\"><article><h2>Timeline evidence</h2><div class=\"timeline-rail\" tabindex=\"0\"><button type=\"button\" data-detail=\"Pilot stores\">Pilot</button><button type=\"button\" data-detail=\"Regional launch\">Regional</button><button type=\"button\" data-detail=\"Owner sign-off\">Owners</button></div></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics evidence</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"{refined_candidate_id} rollout metrics\"><rect x=\"20\" y=\"44\" width=\"40\" height=\"56\" tabindex=\"0\" data-detail=\"Order accuracy 99%\"></rect><rect x=\"90\" y=\"28\" width=\"40\" height=\"72\" tabindex=\"0\" data-detail=\"Support deflection 18%\"></rect><rect x=\"160\" y=\"16\" width=\"40\" height=\"84\" tabindex=\"0\" data-detail=\"Launch velocity 2.3x\"></rect><text x=\"20\" y=\"114\">Accuracy</text><text x=\"90\" y=\"114\">Support</text><text x=\"160\" y=\"114\">Velocity</text></svg></article></section><aside><h2>Clickable detail panel</h2><p id=\"detail-copy\">Pilot is selected by default for {refined_candidate_id}.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{{panels.forEach((panel)=>{{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;}});document.querySelectorAll('button[data-view]').forEach((control)=>{{control.setAttribute('aria-selected', String(control===button));}});detail.textContent=button.dataset.view + ' selected for {refined_candidate_id}.';}}));document.querySelectorAll('[data-detail]').forEach((mark)=>{{mark.addEventListener('mouseenter',()=>{{detail.textContent=mark.dataset.detail;}});mark.addEventListener('focus',()=>{{detail.textContent=mark.dataset.detail;}});mark.addEventListener('click',()=>{{detail.textContent=mark.dataset.detail;}});}});document.getElementById('timeline-next').addEventListener('click',()=>{{detail.textContent='Advanced to the next rollout milestone.';}});</script></main></body></html>"
                        )
                    }]
                })
            }
            "judge" => {
                if self.role == "acceptance" {
                    if prompt.contains("candidate-2-refine-1 refined") {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 5,
                            "conceptCoverage": 5,
                            "interactionRelevance": 5,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 4,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Acceptance cleared the fallback refined candidate."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 3,
                            "conceptCoverage": 3,
                            "interactionRelevance": 2,
                            "layoutCoherence": 3,
                            "visualHierarchy": 3,
                            "completeness": 2,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": false,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "needs denser interaction",
                            "rationale": "Acceptance requires another refinement pass."
                        })
                    }
                } else if prompt.contains("candidate-1 draft") {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 5,
                        "conceptCoverage": 5,
                        "interactionRelevance": 4,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 4,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "Production prefers candidate-1 first."
                    })
                } else {
                    serde_json::json!({
                        "classification": "repairable",
                        "requestFaithfulness": 4,
                        "conceptCoverage": 4,
                        "interactionRelevance": 3,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 3,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": false,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": "needs refinement",
                        "rationale": "Production keeps candidate-2 available for fallback refinement."
                    })
                }
            }
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };
        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[tokio::test]
async fn creative_renderer_refines_fallback_candidate_after_best_branch_stays_repairable() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioFallbackRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            "local producer",
            "qwen2.5:7b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioFallbackRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote acceptance",
            "gpt-4.1",
            "https://api.openai.com/v1/chat/completions",
            "acceptance",
            calls.clone(),
        ));

    let bundle = generate_studio_artifact_bundle_with_runtimes(
        production_runtime,
        acceptance_runtime,
        "Instacart rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect("bundle should generate");

    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert_eq!(
        bundle
            .candidate_summaries
            .iter()
            .find(|candidate| candidate.selected)
            .map(|candidate| candidate.candidate_id.as_str()),
        Some(bundle.winning_candidate_id.as_str())
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:refine")
            .count(),
        2
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:judge")
            .count(),
        2
    );
}

#[tokio::test]
async fn premium_planning_profile_uses_acceptance_runtime_for_brief_and_refine() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioFallbackRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            "local producer",
            "qwen2.5:7b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioFallbackRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote acceptance",
            "gpt-4.1",
            "https://api.openai.com/v1/chat/completions",
            "acceptance",
            calls.clone(),
        ));

    let bundle = generate_studio_artifact_bundle_with_runtimes_and_planning_context(
        production_runtime,
        Some(acceptance_runtime),
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration,
        "Instacart rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
        None,
    )
    .await
    .expect("bundle should generate");

    let runtime_policy = bundle.runtime_policy.expect("runtime policy");
    assert_eq!(
        runtime_policy.profile,
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
    );
    let planning_binding = runtime_policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert_eq!(planning_binding.provenance.label, "remote acceptance");
    assert!(!planning_binding.fallback_applied);
    let repair_binding = runtime_policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::RepairPlanning)
        .expect("repair binding");
    assert_eq!(repair_binding.provenance.label, "remote acceptance");
    assert!(!repair_binding.fallback_applied);
    let generation_binding = runtime_policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::CandidateGeneration)
        .expect("generation binding");
    assert_eq!(generation_binding.provenance.label, "local producer");

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:brief")
            .count(),
        1
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:brief")
            .count(),
        0
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:refine")
            .count(),
        2
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:refine")
            .count(),
        0
    );
}

#[derive(Clone)]
struct StudioSecondRefinementTestRuntime {
    provenance: StudioRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl StudioSecondRefinementTestRuntime {
    fn new(
        kind: StudioRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            provenance: StudioRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
            role,
            calls,
        }
    }
}

#[async_trait]
impl InferenceRuntime for StudioSecondRefinementTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materialization repairer") {
            "materialize_repair"
        } else if prompt.contains("typed artifact refinement repairer") {
            "refine_repair"
        } else if prompt.contains("typed artifact refiner") {
            "refine"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else if prompt.contains("typed artifact judge") {
            "judge"
        } else {
            "unknown"
        };
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:{stage}", self.role));

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "pet care operators",
                "jobToBeDone": "review the rollout evidence",
                "subjectDomain": "dog shampoo rollout",
                "artifactThesis": "show the rollout with charts, channel adoption, and interactive detail",
                "requiredConcepts": ["dog shampoo", "channel adoption", "rollout evidence"],
                "requiredInteractions": ["view switching", "detail comparison"],
                "visualTone": ["clear", "technical"],
                "factualAnchors": ["launch phases", "sales channels"],
                "styleDirectives": ["concise headings"],
                "referenceHints": []
            }),
            "materialize" | "materialize_repair" => {
                let candidate_id = if prompt.contains("\"candidateId\":\"candidate-1\"") {
                    "candidate-1"
                } else {
                    "candidate-2"
                };
                serde_json::json!({
                    "summary": format!("{candidate_id} draft"),
                    "notes": [format!("{candidate_id} initial draft")],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": format!(
                            "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>{candidate_id} summary</p><button type=\"button\" data-view=\"launch\" aria-controls=\"launch-panel\" aria-selected=\"true\">Launch</button><button type=\"button\" data-view=\"adoption\" aria-controls=\"adoption-panel\" aria-selected=\"false\">Adoption</button></section><section id=\"launch-panel\" data-view-panel=\"launch\"><article><h2>Channel adoption</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"{candidate_id} channel adoption\"><rect x=\"20\" y=\"50\" width=\"40\" height=\"50\"></rect><text x=\"20\" y=\"114\">Retail</text></svg></article></section><section><article><h2>Channel scorecard</h2><table><tr><th>Channel</th><th>Lift</th></tr><tr><td>Retail</td><td>24%</td></tr><tr><td>Subscription</td><td>19%</td></tr></table></article></section><section id=\"adoption-panel\" data-view-panel=\"adoption\" hidden><article><h2>Adoption detail</h2><p>Adoption detail remains pre-rendered in this panel.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Initial detail region.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');const controls=document.querySelectorAll('button[data-view]');controls.forEach((button)=>button.addEventListener('click',()=>{{panels.forEach((panel)=>{{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;}});controls.forEach((control)=>{{control.setAttribute('aria-selected', String(control===button));}});detail.textContent=button.dataset.view + ' selected for {candidate_id}.';}}));</script></main></body></html>"
                        )
                    }]
                })
            }
            "refine" | "refine_repair" => {
                if prompt.contains("First refinement") {
                    serde_json::json!({
                        "summary": "Second refinement",
                        "notes": ["second semantic refinement pass"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout by channel</h1><p>Switch between retail and subscription views, then inspect the rollout evidence panel.</p><button type=\"button\" data-view=\"retail\" aria-controls=\"retail-panel\" aria-selected=\"true\">Retail</button><button type=\"button\" data-view=\"subscription\" aria-controls=\"subscription-panel\" aria-selected=\"false\">Subscription</button></section><section id=\"retail-panel\" data-view-panel=\"retail\"><article><h2>Channel adoption</h2><svg viewBox=\"0 0 260 140\" role=\"img\" aria-label=\"Dog shampoo channel adoption\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><rect x=\"94\" y=\"36\" width=\"42\" height=\"80\"></rect><text x=\"24\" y=\"132\">Retail</text><text x=\"94\" y=\"132\">Subscription</text></svg><p>Default view compares retail launch velocity against subscription retention.</p></article><article><h2>Rollout evidence</h2><ul><li tabindex=\"0\" data-detail=\"regional vet launch\">Regional vet launch</li><li tabindex=\"0\" data-detail=\"subscription follow-up\">Subscription follow-up</li></ul></article></section><section><article><h2>Channel comparison</h2><table><tr><th>Channel</th><th>Lift</th></tr><tr><td>Retail</td><td>24%</td></tr><tr><td>Subscription</td><td>19%</td></tr></table></article></section><section id=\"subscription-panel\" data-view-panel=\"subscription\" hidden><article><h2>Subscription evidence</h2><p>Subscription follow-up remains available in this pre-rendered panel.</p></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Retail is the default selected view for launch review.</p></aside><footer><p>Dog shampoo rollout evidence stays request-faithful and interactive.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');const controls=document.querySelectorAll('button[data-view]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});controls.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=`${button.dataset.view} view selected for dog shampoo rollout review.`;}));document.querySelectorAll('li[data-detail]').forEach((item)=>{item.addEventListener('click',()=>{detail.textContent=`Evidence: ${item.dataset.detail}`;});item.addEventListener('focus',()=>{detail.textContent=`Focus: ${item.dataset.detail}`;});});</script></main></body></html>"
                        }]
                    })
                } else {
                    serde_json::json!({
                        "summary": "First refinement",
                        "notes": ["first semantic refinement pass"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Use the segmented controls to inspect launch phases.</p><button type=\"button\" data-view=\"launch\" aria-controls=\"launch-panel\" aria-selected=\"true\">Launch</button><button type=\"button\" data-view=\"adoption\" aria-controls=\"adoption-panel\" aria-selected=\"false\">Adoption</button></section><section id=\"launch-panel\" data-view-panel=\"launch\"><article><h2>Channel adoption</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo launch chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><rect x=\"88\" y=\"38\" width=\"40\" height=\"62\"></rect><text x=\"20\" y=\"114\">Launch</text><text x=\"88\" y=\"114\">Adoption</text></svg></article></section><section><article><h2>Launch scorecard</h2><table><tr><th>Phase</th><th>Status</th></tr><tr><td>Pilot</td><td>Ready</td></tr><tr><td>Adoption</td><td>Tracked</td></tr></table></article></section><section id=\"adoption-panel\" data-view-panel=\"adoption\" hidden><article><h2>Adoption comparison</h2><p>Adoption comparison is ready in this panel.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');const controls=document.querySelectorAll('button[data-view]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});controls.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=`${button.dataset.view} selected.`;}));</script></main></body></html>"
                        }]
                    })
                }
            }
            "judge" => {
                if self.role == "acceptance" {
                    if prompt.contains("Second refinement") {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 5,
                            "conceptCoverage": 5,
                            "interactionRelevance": 5,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 4,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Acceptance cleared the second refinement pass."
                        })
                    } else if prompt.contains("First refinement") {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 4,
                            "conceptCoverage": 4,
                            "interactionRelevance": 4,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "needs denser comparison evidence",
                            "rationale": "Acceptance wants a stronger detail comparison pass."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 3,
                            "conceptCoverage": 3,
                            "interactionRelevance": 2,
                            "layoutCoherence": 3,
                            "visualHierarchy": 3,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "needs stronger interaction depth",
                            "rationale": "Acceptance wants a denser interactive artifact."
                        })
                    }
                } else if prompt.contains("candidate-1 draft") {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 4,
                        "conceptCoverage": 4,
                        "interactionRelevance": 3,
                        "layoutCoherence": 4,
                        "visualHierarchy": 3,
                        "completeness": 3,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "Production prefers candidate-1 before refinement."
                    })
                } else {
                    serde_json::json!({
                        "classification": "repairable",
                        "requestFaithfulness": 3,
                        "conceptCoverage": 3,
                        "interactionRelevance": 3,
                        "layoutCoherence": 3,
                        "visualHierarchy": 3,
                        "completeness": 3,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": "draft is still thin",
                        "rationale": "Production sees a repairable draft."
                    })
                }
            }
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };

        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[tokio::test]
async fn creative_renderer_runs_second_refinement_when_first_pass_improves_but_stays_repairable() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioSecondRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote producer",
            "gpt-4.1-mini",
            "https://api.openai.com/v1/chat/completions",
            "production",
            calls.clone(),
        ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioSecondRefinementTestRuntime::new(
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
            "remote acceptance",
            "gpt-4.1",
            "https://api.openai.com/v1/chat/completions",
            "acceptance",
            calls.clone(),
        ));

    let bundle = generate_studio_artifact_bundle_with_runtimes(
            production_runtime,
            acceptance_runtime,
            "Dog shampoo rollout artifact",
            "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            None,
        )
        .await
        .expect("bundle should generate");

    assert_eq!(bundle.winning_candidate_id, "candidate-1-refine-2");
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_eq!(
        bundle.judge.rationale,
        "Acceptance cleared the second refinement pass."
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:refine")
            .count(),
        2
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:judge")
            .count(),
        0
    );
    let acceptance_judge_count = recorded_calls
        .iter()
        .filter(|call| *call == "acceptance:judge")
        .count();
    assert!((6..=8).contains(&acceptance_judge_count));
}

#[tokio::test]
async fn markdown_bundle_uses_distinct_acceptance_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
        "remote acceptance",
        "gpt-4.1",
        "https://api.openai.com/v1/chat/completions",
        "acceptance",
        calls.clone(),
    ));

    let bundle = generate_studio_artifact_bundle_with_runtimes(
        production_runtime,
        acceptance_runtime,
        "Release checklist",
        "Create a markdown artifact that documents a release checklist",
        &request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown),
        None,
    )
    .await
    .expect("bundle should generate");

    assert_eq!(bundle.acceptance_provenance.label, "remote acceptance");
    assert_eq!(
        bundle.acceptance_provenance.model.as_deref(),
        Some("gpt-4.1")
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert!(recorded_calls.iter().any(|call| call == "production:judge"));
    assert!(recorded_calls.iter().any(|call| call == "acceptance:judge"));
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "production:judge")
            .count(),
        1
    );
    assert_eq!(
        recorded_calls
            .iter()
            .filter(|call| *call == "acceptance:judge")
            .count(),
        1
    );
}

#[test]
fn local_generation_remote_acceptance_policy_falls_back_truthfully_when_acceptance_is_unavailable()
{
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let unavailable_acceptance: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::InferenceUnavailable,
        "acceptance unavailable",
        "unavailable",
        "unavailable://acceptance",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_studio_artifact_runtime_plan(
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        production_runtime,
        Some(unavailable_acceptance),
        StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    assert_eq!(
        runtime_plan.policy.profile,
        StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
    );
    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::AcceptanceJudge)
        .expect("acceptance binding");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("acceptance_runtime_unavailable")
    );
    assert_eq!(acceptance_binding.provenance.label, "local producer");
    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert!(!planning_binding.fallback_applied);
    assert_eq!(planning_binding.provenance.label, "local producer");
}

#[derive(Clone)]
struct StudioGenerationFailureEvidenceTestRuntime {
    provenance: StudioRuntimeProvenance,
}

impl StudioGenerationFailureEvidenceTestRuntime {
    fn new(kind: StudioRuntimeProvenanceKind, label: &str) -> Self {
        Self {
            provenance: StudioRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some("fixture-failure-evidence".to_string()),
                endpoint: Some("fixture://failure-evidence".to_string()),
            },
        }
    }
}

#[async_trait]
impl InferenceRuntime for StudioGenerationFailureEvidenceTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materialization repairer") {
            "repair"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
        } else {
            "unknown"
        };

        let response = match stage {
            "brief" => serde_json::json!({
                "audience": "operators",
                "jobToBeDone": "review the rollout evidence",
                "subjectDomain": "dog shampoo launch",
                "artifactThesis": "show the launch plan clearly",
                "requiredConcepts": ["dog shampoo", "timeline", "owners"],
                "requiredInteractions": ["view switching", "detail comparison"],
                "visualTone": ["clear"],
                "factualAnchors": ["rollout ownership review"],
                "styleDirectives": [],
                "referenceHints": []
            }),
            "materialize" | "repair" => serde_json::json!({
                "summary": "Broken rollout draft",
                "notes": ["candidate intentionally lacks pre-rendered panels"],
                "files": [{
                    "path": "index.html",
                    "mime": "text/html",
                    "role": "primary",
                    "renderable": true,
                    "downloadable": true,
                    "encoding": "utf8",
                    "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Inspect the rollout evidence.</p><button type=\"button\" data-view=\"timeline\">Timeline</button><button type=\"button\" data-view=\"owners\">Owners</button></section><section><article><h2>Timeline evidence</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo rollout timeline\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Plan</text></svg></article></section><aside><h2>Comparison detail</h2><p id=\"detail-copy\">Timeline is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=button.dataset.view + ' selected';}));</script></main></body></html>"
                }]
            }),
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };

        Ok(response.to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[tokio::test]
async fn bundle_failure_returns_candidate_summaries_with_raw_previews() {
    let runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioGenerationFailureEvidenceTestRuntime::new(
            StudioRuntimeProvenanceKind::FixtureRuntime,
            "fixture failure evidence",
        ));

    let error = generate_studio_artifact_bundle_with_runtimes(
        runtime.clone(),
        runtime,
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .await
    .expect_err("all invalid candidates should return typed generation error");

    assert!(error.message.contains("did not produce a valid candidate"));
    assert_eq!(
        error
            .brief
            .as_ref()
            .map(|brief| brief.subject_domain.as_str()),
        Some("dog shampoo launch")
    );
    assert!(error.edit_intent.is_none());
    assert_eq!(error.candidate_summaries.len(), 3);
    assert!(error.candidate_summaries.iter().all(|candidate| candidate
        .failure
        .as_ref()
        .is_some_and(|failure| !failure.is_empty())));
    assert!(error.candidate_summaries.iter().all(|candidate| {
        candidate.judge.classification == StudioArtifactJudgeClassification::Blocked
    }));
}
