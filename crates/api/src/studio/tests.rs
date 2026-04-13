use super::generation::{
    apply_studio_swarm_patch_envelope, build_studio_artifact_direct_author_prompt_for_runtime,
    build_studio_artifact_materialization_prompt_for_runtime,
    evaluate_candidate_render_with_fallback, render_eval_timeout_for_runtime,
    render_evaluation_required, requested_follow_up_pass,
    validate_swarm_generated_artifact_payload, StudioArtifactPatchEnvelope,
    StudioArtifactPatchOperation, StudioArtifactPatchOperationKind,
};
use super::judging::candidate_generation_config;
use super::planning::{
    build_studio_artifact_brief_field_repair_prompt,
    build_studio_artifact_brief_prompt_for_runtime, build_studio_outcome_router_prompt_for_runtime,
    canonicalize_studio_artifact_brief_for_request, validate_studio_artifact_brief_against_request,
};
use super::*;
use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioArtifactDeliverableShape, StudioArtifactPersistenceMode, StudioExecutionStrategy,
    StudioExecutionSubstrate, StudioOutcomeArtifactScope, StudioOutcomeArtifactVerificationRequest,
    StudioPresentationSurface, StudioRuntimeProvenance, StudioRuntimeProvenanceKind,
};
use ioi_types::error::VmError;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::Sender;

mod planning_and_routing;
mod swarm_plans;

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

fn with_modal_first_html_env<T>(f: impl FnOnce() -> T) -> T {
    with_studio_modal_first_html_override(true, f)
}

async fn with_modal_first_html_env_async<T, F>(f: impl FnOnce() -> F) -> T
where
    F: Future<Output = T>,
{
    with_studio_modal_first_html_override_async(true, f).await
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

async fn planned_prepared_context_with_runtime_plan(
    runtime_plan: &StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> StudioArtifactPlanningContext {
    let brief = plan_studio_artifact_brief_with_runtime(
        runtime_plan.planning_runtime.clone(),
        title,
        intent,
        request,
        refinement,
    )
    .await
    .expect("prepared context brief planning should succeed in tests");

    derive_studio_artifact_prepared_context(
        request,
        &brief,
        refinement.and_then(|context| context.blueprint.clone()),
        refinement.and_then(|context| context.artifact_ir.clone()),
        refinement
            .map(|context| context.selected_skills.clone())
            .unwrap_or_default(),
        refinement
            .map(|context| context.retrieved_exemplars.clone())
            .unwrap_or_default(),
    )
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
        query_profile: Some(StudioArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    StudioArtifactContentGoalKind::Explain,
                    "Explain the rollout evidence clearly.",
                ),
                required_content_goal(
                    StudioArtifactContentGoalKind::Compare,
                    "Keep comparison-ready evidence visible.",
                ),
            ],
            interaction_goals: vec![
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::StateSwitch,
                    "Switch between authored evidence states.",
                ),
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::DetailInspect,
                    "Inspect evidence details in a visible response region.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep primary rollout evidence visible on first paint.",
                ),
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::ComparisonSurface,
                    "Keep a comparison evidence surface available on first paint.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Populate the first paint with real evidence.",
                ),
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                ),
            ],
        }),
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
        query_profile: Some(StudioArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    StudioArtifactContentGoalKind::Explain,
                    "Explain the key quantum concepts clearly.",
                ),
                required_content_goal(
                    StudioArtifactContentGoalKind::Compare,
                    "Compare visible quantum states and outcomes.",
                ),
            ],
            interaction_goals: vec![
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::StateAdjust,
                    "Adjust visible state controls.",
                ),
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::DetailInspect,
                    "Inspect visible state details.",
                ),
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::SequenceBrowse,
                    "Progress through staged quantum examples.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep the primary state surface visible.",
                ),
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::SupportingSurface,
                    "Support the explanation with visible labeled evidence.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Populate the first paint with working state evidence.",
                ),
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                ),
            ],
        }),
    }
}

fn sample_quantum_markdown_brief() -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "curious readers".to_string(),
        job_to_be_done: "understand quantum computing through a concise markdown explainer"
            .to_string(),
        subject_domain: "quantum computing fundamentals".to_string(),
        artifact_thesis:
            "Explain qubits, superposition, interference, and hardware limits in a compact document."
                .to_string(),
        required_concepts: vec![
            "qubits".to_string(),
            "superposition".to_string(),
            "interference".to_string(),
            "hardware limits".to_string(),
        ],
        required_interactions: Vec::new(),
        visual_tone: vec!["editorial".to_string(), "clear".to_string()],
        factual_anchors: vec![
            "measurement outcomes".to_string(),
            "error rates".to_string(),
        ],
        style_directives: vec!["concise hierarchy".to_string()],
        reference_hints: vec!["explainer memo".to_string()],
        query_profile: Some(StudioArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    StudioArtifactContentGoalKind::Summary,
                    "Summarize the quantum concepts clearly.",
                ),
                required_content_goal(
                    StudioArtifactContentGoalKind::Explain,
                    "Explain the evidence behind the concepts.",
                ),
            ],
            interaction_goals: Vec::new(),
            evidence_goals: vec![required_evidence_goal(
                StudioArtifactEvidenceGoalKind::SupportingSurface,
                "Support the document with grounded evidence.",
            )],
            presentation_constraints: vec![required_presentation_constraint(
                StudioArtifactPresentationConstraintKind::SemanticStructure,
                "Keep the document semantically structured.",
            )],
        }),
    }
}

fn sample_complex_mission_control_brief() -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "launch operators".to_string(),
        job_to_be_done:
            "coordinate a post-quantum migration through a dense mission-control style artifact"
                .to_string(),
        subject_domain: "post-quantum migration program".to_string(),
        artifact_thesis:
            "Guide operators through rollout phases, risk posture, cutover decisions, and incident response in one interactive artifact."
                .to_string(),
        required_concepts: vec![
            "fleet rollout phases".to_string(),
            "cryptography inventory".to_string(),
            "vendor readiness".to_string(),
            "cutover decision points".to_string(),
            "owner handoffs".to_string(),
            "incident fallback playbook".to_string(),
        ],
        required_interactions: vec![
            "phase switching".to_string(),
            "risk drilldown".to_string(),
            "owner handoff comparison".to_string(),
            "cutover simulation".to_string(),
        ],
        visual_tone: vec![
            "operator-grade".to_string(),
            "dense".to_string(),
            "technical".to_string(),
        ],
        factual_anchors: vec![
            "fleet readiness snapshot".to_string(),
            "handoff ownership".to_string(),
            "rollback thresholds".to_string(),
        ],
        style_directives: vec![
            "dense but readable".to_string(),
            "slate mission control".to_string(),
        ],
        reference_hints: vec![
            "control room dashboard".to_string(),
            "rollout workbook".to_string(),
        ],
        query_profile: Some(StudioArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    StudioArtifactContentGoalKind::Orient,
                    "Orient operators to the migration program immediately.",
                ),
                required_content_goal(
                    StudioArtifactContentGoalKind::Compare,
                    "Compare phases, risks, and owner handoffs.",
                ),
            ],
            interaction_goals: vec![
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::StateSwitch,
                    "Switch between operator views.",
                ),
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::DetailInspect,
                    "Inspect detailed operator evidence inline.",
                ),
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::StateAdjust,
                    "Adjust cutover simulation state.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep mission control evidence visible on first paint.",
                ),
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::ComparisonSurface,
                    "Keep alternate evidence views available on first paint.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Populate the first paint with real operator evidence.",
                ),
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                ),
            ],
        }),
    }
}

fn required_interaction_goal(
    kind: StudioArtifactInteractionGoalKind,
    summary: &str,
) -> StudioArtifactInteractionGoal {
    StudioArtifactInteractionGoal {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

fn required_content_goal(
    kind: StudioArtifactContentGoalKind,
    summary: &str,
) -> StudioArtifactContentGoal {
    StudioArtifactContentGoal {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

fn required_evidence_goal(
    kind: StudioArtifactEvidenceGoalKind,
    summary: &str,
) -> StudioArtifactEvidenceGoal {
    StudioArtifactEvidenceGoal {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

fn required_presentation_constraint(
    kind: StudioArtifactPresentationConstraintKind,
    summary: &str,
) -> StudioArtifactPresentationConstraint {
    StudioArtifactPresentationConstraint {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

#[test]
fn direct_author_html_generation_preserves_raw_document_contract_after_planning_context() {
    #[derive(Debug, Clone)]
    struct DirectAuthorRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
        json_modes: Arc<Mutex<Vec<bool>>>,
        provenance: StudioRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            self.prompts
                .lock()
                .expect("prompt log")
                .push(prompt.clone());
            self.json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            let response = if prompt.contains("typed artifact brief planner") {
                serde_json::to_string(&sample_html_brief())
                    .expect("sample html brief should serialize")
            } else if prompt.contains("direct document author") {
                "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Product rollout</title><style>body{margin:0;background:#171717;color:#f5f5f5;font-family:Georgia,serif;}main{max-width:1040px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#202020;border:1px solid #3a3a3a;border-radius:18px;padding:18px;}button{border:1px solid #666;background:#2a2a2a;color:#f5f5f5;border-radius:999px;padding:8px 14px;}svg{width:100%;height:auto;}</style></head><body><main><section><h1>Product rollout, explained through launch confidence and adoption</h1><p>The page opens with launch confidence, customer adoption, and issue backlog already visible so the first paint is useful before any interaction. Operators can switch between rollout phases and compare what changed in launch readiness, support load, and revenue contribution.</p><div><button type=\"button\" data-view=\"readiness\" aria-selected=\"true\">Readiness</button><button type=\"button\" data-view=\"adoption\" aria-selected=\"false\">Adoption</button></div></section><section data-view-panel=\"readiness\"><h2>Readiness chart</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"Readiness by phase\"><rect x=\"16\" y=\"42\" width=\"42\" height=\"58\"></rect><rect x=\"86\" y=\"24\" width=\"42\" height=\"76\"></rect><rect x=\"156\" y=\"10\" width=\"42\" height=\"90\"></rect><text x=\"16\" y=\"112\">Pilot</text><text x=\"86\" y=\"112\">Regional</text><text x=\"156\" y=\"112\">Global</text></svg><p>Readiness moves from 64% in pilot to 90% at global launch as training, fulfillment, and support tooling converge.</p></section><section data-view-panel=\"adoption\" hidden><h2>Adoption comparison</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"Adoption and support comparison\"><rect x=\"16\" y=\"28\" width=\"54\" height=\"72\"></rect><rect x=\"98\" y=\"42\" width=\"54\" height=\"58\"></rect><rect x=\"180\" y=\"18\" width=\"32\" height=\"82\"></rect><text x=\"16\" y=\"112\">Signups</text><text x=\"98\" y=\"112\">Tickets</text><text x=\"170\" y=\"112\">Revenue</text></svg><p>Adoption accelerates faster than support load, which is why the comparison view keeps both signals visible instead of forcing a single-metric story.</p></section><aside><h2>Why this rollout is working</h2><p id=\"detail-copy\">Readiness is selected by default, showing how the launch moved from pilot confidence to global approval while keeping support load manageable.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='readiness'?'Readiness is selected by default, showing how the launch moved from pilot confidence to global approval while keeping support load manageable.':'Adoption is selected, comparing signups, support tickets, and revenue contribution through the rollout.';}));</script></main></body></html>".to_string()
            } else if prompt.contains("typed artifact judge") {
                serde_json::json!({
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
                    "issueClasses": [],
                    "repairHints": [],
                    "strengths": ["Request-specific first paint"],
                    "blockedReasons": [],
                    "fileFindings": [],
                    "aestheticVerdict": "The page is specific and visually intentional.",
                    "interactionVerdict": "The controls switch between authored evidence views.",
                    "truthfulnessWarnings": [],
                    "recommendedNextPass": "accept",
                    "strongestContradiction": null,
                    "rationale": "The direct-authored artifact is complete and request-faithful."
                })
                .to_string()
            } else {
                return Err(VmError::HostError(format!(
                    "unexpected Studio prompt in direct-author test runtime: {prompt}"
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            self.provenance.clone()
        }
    }

    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorRuntime {
        prompts: prompts.clone(),
        json_modes: json_modes.clone(),
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture direct-author runtime".to_string(),
            model: Some("fixture-direct-author".to_string()),
            endpoint: Some("fixture://direct-author".to_string()),
        },
    });
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let title = "Product rollout explainer";
    let intent = "Create an interactive HTML artifact that explains a product rollout with charts";
    let evaluator = StudioPassingRenderEvaluator;

    let bundle = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
        let runtime_plan = resolve_studio_artifact_runtime_plan(
                &request,
                runtime.clone(),
                None,
                StudioArtifactRuntimePolicyProfile::FullyLocal,
            );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            title,
            intent,
            &request,
            None,
        )
        .await;
        generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
            runtime_plan,
            title,
            intent,
            &request,
            None,
            &planning_context,
            StudioExecutionStrategy::DirectAuthor,
            Some(&evaluator),
            None,
            None,
        )
        .await
    })
        .expect("direct author bundle");

    let prompt_log = prompts.lock().expect("prompt log");
    let direct_author_prompt = prompt_log
        .iter()
        .find(|prompt| prompt.contains("direct document author"))
        .expect("direct author prompt");
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("Raw user request:")));
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("typed artifact brief planner")));
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("Artifact brief JSON:")));
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("Return only one complete self-contained HTML document.")));
    assert!(!prompt_log
        .iter()
        .any(|prompt| prompt.contains("typed artifact edit intent planner")));
    assert!(!direct_author_prompt.contains("Return exactly one JSON object"));
    assert!(json_modes
        .lock()
        .expect("json mode log")
        .iter()
        .any(|json_mode| !json_mode));
    assert_eq!(
        bundle
            .execution_envelope
            .as_ref()
            .and_then(|entry| entry.strategy),
        Some(StudioExecutionStrategy::DirectAuthor)
    );
    assert!(bundle.blueprint.is_some());
    assert!(bundle.artifact_ir.is_some());
    assert!(bundle.selected_skills.is_empty());
    assert_eq!(bundle.winner.files[0].path, "index.html");
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
}

#[tokio::test]
async fn direct_author_streams_token_preview_into_generation_progress() {
    #[derive(Debug, Clone)]
    struct StreamingDirectAuthorRuntime {
        provenance: StudioRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for StreamingDirectAuthorRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if prompt.contains("typed artifact brief planner") {
                return Ok(serde_json::to_string(&sample_quantum_markdown_brief())
                    .expect("sample markdown brief should serialize")
                    .into_bytes());
            }
            if prompt.contains("typed artifact judge") {
                return Ok(serde_json::json!({
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
                    "issueClasses": [],
                    "repairHints": [],
                    "strengths": ["Specific direct-authored markdown"],
                    "blockedReasons": [],
                    "fileFindings": [],
                    "aestheticVerdict": "The document is structured and specific.",
                    "interactionVerdict": "The renderer contract was satisfied.",
                    "truthfulnessWarnings": [],
                    "recommendedNextPass": "accept",
                    "strongestContradiction": null,
                    "rationale": "The direct-authored markdown is complete and ready."
                })
                .to_string()
                .into_bytes());
            }

            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in streaming direct-author test runtime: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
            token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if !prompt.contains("direct document author")
                && !prompt.contains("Return only one complete self-contained index.html.")
            {
                return self
                    .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await;
            }

            let chunks = [
                "# Quantum computers\n\n".to_string(),
                "Qubits keep amplitudes in play while measurement turns those amplitudes into sampled outcomes.\n\n".to_string(),
                "## Why they matter\n\nThey can accelerate some simulation and optimization workloads when error rates are controlled.\n".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }
            Ok(chunks.concat().into_bytes())
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            self.provenance.clone()
        }
    }

    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StreamingDirectAuthorRuntime {
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture streaming direct-author runtime".to_string(),
            model: Some("fixture-streaming-direct-author".to_string()),
            endpoint: Some("fixture://streaming-direct-author".to_string()),
        },
    });
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown);
    let title = "Quantum computers overview";
    let intent = "Create a markdown artifact that explains quantum computers";
    let progress_log = Arc::new(Mutex::new(Vec::<StudioArtifactGenerationProgress>::new()));
    let progress_observer: StudioArtifactGenerationProgressObserver = {
        let progress_log = progress_log.clone();
        Arc::new(move |progress| {
            progress_log.lock().expect("progress log").push(progress);
        })
    };

    let runtime_plan = resolve_studio_artifact_runtime_plan(
        &request,
        runtime.clone(),
        None,
        StudioArtifactRuntimePolicyProfile::FullyLocal,
    );
    let planning_context =
        planned_prepared_context_with_runtime_plan(&runtime_plan, title, intent, &request, None)
            .await;
    let bundle =
        generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
            runtime_plan,
            title,
            intent,
            &request,
            None,
            &planning_context,
            StudioExecutionStrategy::DirectAuthor,
            None,
            Some(progress_observer),
            None,
        )
        .await
        .expect("streaming direct author bundle");

    let progress_log = progress_log.lock().expect("progress log");
    assert!(progress_log.iter().any(|progress| {
        progress
            .current_step
            .contains("Streaming Direct author output")
            && progress
                .execution_envelope
                .as_ref()
                .map(|envelope| {
                    envelope.live_previews.iter().any(|preview| {
                        preview.kind == crate::execution::ExecutionLivePreviewKind::TokenStream
                            && preview.content.contains("Quantum computers")
                    })
                })
                .unwrap_or(false)
    }));
    assert!(bundle
        .execution_envelope
        .as_ref()
        .map(|envelope| envelope.live_previews.iter().any(|preview| {
            preview.kind == crate::execution::ExecutionLivePreviewKind::TokenStream
                && preview.content.contains("Qubits keep amplitudes")
        }))
        .unwrap_or(false));
}

#[tokio::test]
async fn direct_author_continues_incomplete_raw_document_without_terminalizing_preview() {
    #[derive(Debug, Clone)]
    struct InterruptedStreamingDirectAuthorRuntime;

    #[async_trait]
    impl InferenceRuntime for InterruptedStreamingDirectAuthorRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if prompt.contains("Continuation output schema")
                || prompt.contains("typed direct document continuation author")
            {
                return Ok("{\"mode\":\"suffix\",\"content\":\"</style></head><body><main><section><h1>Quantum computers explained</h1><p>Qubits use superposition and interference so some simulation and optimization problems can be attacked differently from classical systems.</p><button type=\\\"button\\\" data-view=\\\"concepts\\\" aria-selected=\\\"true\\\">Concepts</button><button type=\\\"button\\\" data-view=\\\"hardware\\\" aria-selected=\\\"false\\\">Hardware</button></section><section data-view-panel=\\\"concepts\\\"><h2>Concepts</h2><p>Amplitude, interference, and measurement work together to shape the result distribution.</p></section><section data-view-panel=\\\"hardware\\\" hidden><h2>Hardware</h2><p>Error correction and qubit stability are still major constraints.</p></section><aside><p id=\\\"detail-copy\\\">Concepts are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='concepts'?'Concepts are selected by default.':'Hardware limits are selected.';}));</script></main></body></html>\"}".as_bytes().to_vec());
            }
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in interrupted direct-author runtime: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
            token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if !prompt.contains("direct document author")
                && !prompt.contains("Return only one complete self-contained index.html.")
            {
                return self
                    .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await;
            }
            let partial_chunks = [
                "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Quantum computers</title><style>".to_string(),
                "body{margin:0;background:#0f172a;color:#e2e8f0;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;".to_string(),
                "section{background:#111827;border:1px solid #334155;border-radius:18px;padding:20px;}".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &partial_chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }
            Err(VmError::HostError(
                "timed out while emitting stylesheet".to_string(),
            ))
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture interrupted direct-author runtime".to_string(),
                model: Some("fixture-interrupted-direct-author".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let live_previews = Arc::new(Mutex::new(
        Vec::<crate::execution::ExecutionLivePreview>::new(),
    ));
    let live_preview_observer = {
        let live_previews = live_previews.clone();
        Arc::new(move |preview: crate::execution::ExecutionLivePreview| {
            live_previews
                .lock()
                .expect("live preview log")
                .push(preview);
        })
    };

    let payload = super::generation::materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
        Arc::new(InterruptedStreamingDirectAuthorRuntime),
        None,
        "Quantum computers",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        &brief,
        &[],
        None,
        "candidate-1",
        7,
        0.72,
        Some(live_preview_observer),
        None,
    )
    .await
    .expect("interrupted direct-author stream should continue the raw document");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0]
        .body
        .contains("Quantum computers explained"));
    assert!(payload.files[0].body.ends_with("</html>"));

    let preview_log = live_previews.lock().expect("live preview log");
    assert!(preview_log.iter().any(|preview| {
        preview.kind == crate::execution::ExecutionLivePreviewKind::TokenStream
            && preview.status == "interrupted"
            && preview.content.contains("body{margin:0")
            && !preview.is_final
    }));
    let latest_preview = preview_log
        .iter()
        .rev()
        .find(|preview| preview.id == "candidate-1-live-output")
        .expect("recovered preview should be recorded");
    assert_eq!(latest_preview.status, "recovered");
    assert!(latest_preview.is_final);
    assert!(latest_preview
        .content
        .contains("Quantum computers explained"));
}

#[tokio::test]
async fn direct_author_invalid_stream_marks_preview_failed_after_recovery_attempts() {
    #[derive(Debug, Clone)]
    struct CompletedInvalidStreamingDirectAuthorRuntime;

    #[async_trait]
    impl InferenceRuntime for CompletedInvalidStreamingDirectAuthorRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "no repair or continuation output for prompt: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
            token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if !prompt.contains("direct document author")
                && !prompt.contains("Return only one complete self-contained index.html.")
            {
                return self
                    .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await;
            }

            let chunks = [
                "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Quantum Explorer</title><style>".to_string(),
                "body{margin:0;background:#0f172a;color:#e2e8f0;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;}".to_string(),
                "</style></head><body><main class=\"container\"><header><h1>Quantum computers</h1></header>".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }

            Ok(chunks.concat().into_bytes())
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture completed-but-invalid direct-author runtime".to_string(),
                model: Some("fixture-completed-invalid-direct-author".to_string()),
                endpoint: Some("fixture://completed-invalid-direct-author".to_string()),
            }
        }
    }

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let live_previews = Arc::new(Mutex::new(
        Vec::<crate::execution::ExecutionLivePreview>::new(),
    ));
    let live_preview_observer = {
        let live_previews = live_previews.clone();
        Arc::new(move |preview: crate::execution::ExecutionLivePreview| {
            live_previews
                .lock()
                .expect("live preview log")
                .push(preview);
        })
    };

    let error =
        super::generation::materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(CompletedInvalidStreamingDirectAuthorRuntime),
            None,
            "Quantum computers",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            "candidate-1",
            7,
            0.72,
            Some(live_preview_observer),
            None,
        )
        .await
        .expect_err("invalid streamed document should fail after continuation and repair");

    assert!(error.message.contains("continuation attempt"));

    let preview_log = live_previews.lock().expect("live preview log");
    assert!(preview_log.iter().any(|preview| {
        preview.id == "candidate-1-live-output"
            && preview.status == "continuing"
            && !preview.is_final
    }));
    let latest_preview = preview_log
        .iter()
        .rev()
        .find(|preview| preview.id == "candidate-1-live-output")
        .expect("terminal preview should be recorded");
    assert_eq!(
        latest_preview.kind,
        crate::execution::ExecutionLivePreviewKind::TokenStream
    );
    assert_eq!(latest_preview.status, "failed");
    assert!(latest_preview.is_final);
    assert!(latest_preview.content.contains("Quantum computers"));
}

#[tokio::test]
async fn direct_author_interrupted_stream_preserves_whitespace_only_chunks_for_recovery() {
    #[derive(Debug, Clone)]
    struct WhitespaceSensitiveInterruptedRuntime;

    #[async_trait]
    impl InferenceRuntime for WhitespaceSensitiveInterruptedRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if prompt.contains("Continuation output schema")
                || prompt.contains("typed direct document continuation author")
            {
                assert!(
                    prompt.contains("Quantum computers are"),
                    "continuation prompt lost whitespace-only chunks: {prompt}"
                );
                return Ok("{\"mode\":\"suffix\",\"content\":\"</p></section><section><button type=\\\"button\\\" id=\\\"state-toggle\\\" aria-pressed=\\\"false\\\">Toggle measurement</button><p id=\\\"detail-copy\\\">Superposition is visible.</p></section><aside id=\\\"state-panel\\\" hidden><p>Measurement collapses the state into a classical outcome.</p></aside><script>const button=document.getElementById('state-toggle');const detail=document.getElementById('detail-copy');const panel=document.getElementById('state-panel');button.addEventListener('click',()=>{const next=button.getAttribute('aria-pressed')!=='true';button.setAttribute('aria-pressed',String(next));panel.hidden=!next;detail.textContent=next?'Measurement collapses the state into a classical outcome.':'Superposition is visible.';});</script></main></body></html>\"}".as_bytes().to_vec());
            }
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in whitespace-sensitive runtime: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
            token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if !prompt.contains("direct document author")
                && !prompt.contains("Return only one complete self-contained index.html.")
            {
                return self
                    .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await;
            }
            let partial_chunks = [
                "<!doctype html><html lang=\"en\"><body><main><section><p>Quantum".to_string(),
                " ".to_string(),
                "computers".to_string(),
                " ".to_string(),
                "are".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &partial_chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }
            Err(VmError::HostError(
                "timed out after streaming a whitespace-sensitive partial".to_string(),
            ))
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture whitespace-sensitive interrupted runtime".to_string(),
                model: Some("fixture-whitespace-sensitive".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();

    let payload = super::generation::materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
        Arc::new(WhitespaceSensitiveInterruptedRuntime),
        None,
        "Quantum computers",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        &brief,
        &[],
        None,
        "candidate-1",
        11,
        0.72,
        None,
        None,
    )
    .await
    .expect("whitespace-sensitive interrupted stream should recover the full sentence");

    assert!(payload.files[0].body.contains("Quantum computers are"));
    assert!(payload.files[0].body.ends_with("</html>"));
}

#[tokio::test]
async fn direct_author_repairs_structurally_truncated_document_with_terminal_closers() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct StructurallyBrokenDirectAuthorRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for StructurallyBrokenDirectAuthorRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_studio_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("direct document repair author") {
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\">Measurement</button></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in structurally broken runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_studio_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if !prompt.contains("direct document author")
                    && !prompt.contains("Return only one complete self-contained index.html.")
                {
                    return self
                        .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                        .await;
                }
                let broken = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><button type=\"button\" data-view=\"basics\">Basics</button><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></main></body></html>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(broken.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Ok(broken.as_bytes().to_vec())
            }

            async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
                Ok(Vec::new())
            }

            async fn load_model(
                &self,
                _model_hash: [u8; 32],
                _path: &Path,
            ) -> Result<(), VmError> {
                Ok(())
            }

            async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
                Ok(())
            }

            fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
                StudioRuntimeProvenance {
                    kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture structurally broken direct-author runtime".to_string(),
                    model: Some("fixture-structurally-broken".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                }
            }
        }

        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(StructurallyBrokenDirectAuthorRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            "candidate-1",
            19,
            0.72,
            None,
            None,
        )
        .await
        .expect("structurally broken direct-author output should be repaired");

        assert!(payload.files[0].body.contains("Measurement is selected."));
        assert!(payload.files[0].body.ends_with("</html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("direct document repair author")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("continuing an interrupted document")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_local_html_uses_fast_runtime_sanity_without_acceptance_judge() {
    #[derive(Debug, Clone)]
    struct DirectAuthorAcceptanceRuntime {
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        provenance: StudioRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorAcceptanceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief"
            } else if prompt.contains("direct document author")
                || prompt.contains("Return only one complete self-contained index.html.")
            {
                "author"
            } else if prompt.contains("direct document repair author") {
                "repair"
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
                "brief" => serde_json::to_string(&sample_quantum_explainer_brief())
                    .expect("sample html brief should serialize"),
                "author" => "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main><section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div><button type=\"button\" data-view=\"concepts\" aria-selected=\"true\">Core concepts</button><button type=\"button\" data-view=\"hardware\" aria-selected=\"false\">Hardware limits</button></div></section><section data-view-panel=\"concepts\"><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><section data-view-panel=\"hardware\" hidden><h2>Hardware limits</h2><p>Error rates, cooling systems, and qubit connectivity are still major constraints.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='concepts'?'Core concepts are selected by default.':'Hardware limits are selected.';}));</script></main></body></html>".to_string(),
                "repair" => serde_json::json!({
                    "mode": "full_document",
                    "content": "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title></head><body><main><section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p></section></main></body></html>"
                }).to_string(),
                "judge" if self.role == "acceptance" => serde_json::json!({
                    "classification": "repairable",
                    "requestFaithfulness": 4,
                    "conceptCoverage": 4,
                    "interactionRelevance": 3,
                    "layoutCoherence": 3,
                    "visualHierarchy": 3,
                    "completeness": 4,
                    "genericShellDetected": false,
                    "trivialShellDetected": false,
                    "deservesPrimaryArtifactView": true,
                    "patchedExistingArtifact": false,
                    "continuityRevisionUx": 4,
                    "issueClasses": ["weak_visual_hierarchy"],
                    "repairHints": ["Strengthen hierarchy and spacing."],
                    "strengths": ["Request concepts stay visible and specific."],
                    "blockedReasons": [],
                    "fileFindings": [],
                    "aestheticVerdict": "Needs a stronger hierarchy.",
                    "interactionVerdict": "Interaction is coherent but visually soft.",
                    "truthfulnessWarnings": [],
                    "recommendedNextPass": "polish_pass",
                    "strongestContradiction": null,
                    "rationale": "acceptance runtime evaluated the direct-authored draft"
                })
                .to_string(),
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
                    "patchedExistingArtifact": false,
                    "continuityRevisionUx": 4,
                    "issueClasses": [],
                    "repairHints": [],
                    "strengths": ["Producer-side draft looks solid."],
                    "blockedReasons": [],
                    "fileFindings": [],
                    "aestheticVerdict": "Looks good.",
                    "interactionVerdict": "Looks good.",
                    "truthfulnessWarnings": [],
                    "recommendedNextPass": "accept",
                    "strongestContradiction": null,
                    "rationale": "producer runtime judged the draft"
                })
                .to_string(),
                _ => {
                    return Err(VmError::HostError(format!(
                        "unexpected Studio prompt in direct-author acceptance test runtime: {prompt}"
                    )))
                }
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            self.provenance.clone()
        }
    }

    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let evaluator = StudioPassingRenderEvaluator;
        let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorAcceptanceRuntime {
            role: "production",
            calls: calls.clone(),
            provenance: StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture direct-author producer".to_string(),
                model: Some("fixture-qwen-9b".to_string()),
                endpoint: Some("fixture://producer".to_string()),
            },
        });
        let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorAcceptanceRuntime {
            role: "acceptance",
            calls: calls.clone(),
            provenance: StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture direct-author acceptance".to_string(),
                model: Some("fixture-qwen-8b".to_string()),
                endpoint: Some("fixture://acceptance".to_string()),
            },
        });
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let title = "Quantum computing explainer";
        let intent = "Create an interactive HTML artifact that explains quantum computers.";
        let runtime_plan = resolve_studio_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            title,
            intent,
            &request,
            None,
        )
        .await;

        let bundle =
            generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                StudioExecutionStrategy::DirectAuthor,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("direct-author bundle");

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|entry| entry == "production:author"));
        assert!(!recorded_calls.iter().any(|entry| entry == "production:judge"));
        assert!(!recorded_calls.iter().any(|entry| entry == "acceptance:judge"));
        assert!(bundle
            .judge
            .rationale
            .starts_with("Studio replaced slow acceptance with a fast runtime-sanity pass"));
        assert_eq!(
            bundle.judge.classification,
            StudioArtifactJudgeClassification::Pass
        );
        assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Judged);
        assert_eq!(
            bundle.acceptance_provenance.model.as_deref(),
            Some("fixture-qwen-8b")
        );
    })
    .await;
}

#[tokio::test]
async fn direct_author_local_html_repairs_runtime_failure_before_surface() {
    #[derive(Debug, Clone)]
    struct DirectAuthorRuntimeRepairRuntime {
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        provenance: StudioRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorRuntimeRepairRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief"
            } else if prompt.contains("direct document repair author") {
                "repair"
            } else if prompt.contains("direct document author")
                || prompt.contains("Return only one complete self-contained index.html.")
            {
                "author"
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
                "brief" => serde_json::to_string(&sample_quantum_explainer_brief())
                    .expect("sample html brief should serialize"),
                "author" => "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main><section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div id=\"artifact-stage\"><button type=\"button\" data-view=\"concepts\" aria-selected=\"true\">Core concepts</button><button type=\"button\" data-view=\"hardware\" aria-selected=\"false\">Hardware limits</button></div></section><section data-view-panel=\"concepts\"><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><section data-view-panel=\"hardware\" hidden><h2>Hardware limits</h2><p>Error rates, cooling systems, and qubit connectivity are still major constraints.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside><script>const stage=document.getElementById('artifact-stage');stage.forEach(()=>{});</script></main></body></html>".to_string(),
                "repair" => serde_json::json!({
                    "mode": "full_document",
                    "content": "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main data-repaired=\"runtime-error\"><section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div><button type=\"button\" data-view=\"concepts\" aria-selected=\"true\">Core concepts</button><button type=\"button\" data-view=\"hardware\" aria-selected=\"false\">Hardware limits</button></div></section><section data-view-panel=\"concepts\"><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><section data-view-panel=\"hardware\" hidden><h2>Hardware limits</h2><p>Error rates, cooling systems, and qubit connectivity are still major constraints.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='concepts'?'Core concepts are selected by default.':'Hardware limits are selected.';}));</script></main></body></html>"
                }).to_string(),
                "judge" => {
                    return Err(VmError::HostError(
                        "fast local html path should not call the acceptance judge".to_string(),
                    ))
                }
                _ => {
                    return Err(VmError::HostError(format!(
                        "unexpected Studio prompt in direct-author runtime repair test: {prompt}"
                    )))
                }
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            self.provenance.clone()
        }
    }

    #[derive(Default)]
    struct DirectAuthorRuntimeErrorEvaluator;

    #[async_trait]
    impl StudioArtifactRenderEvaluator for DirectAuthorRuntimeErrorEvaluator {
        async fn evaluate_candidate_render(
            &self,
            _request: &StudioOutcomeArtifactRequest,
            _brief: &StudioArtifactBrief,
            _blueprint: Option<&StudioArtifactBlueprint>,
            _artifact_ir: Option<&StudioArtifactIR>,
            _edit_intent: Option<&StudioArtifactEditIntent>,
            candidate: &StudioGeneratedArtifactPayload,
        ) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
            let repaired = candidate
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .map(|file| file.body.contains("data-repaired=\"runtime-error\""))
                .unwrap_or(false);
            if repaired {
                return Ok(Some(studio_test_render_evaluation(
                    20,
                    true,
                    Vec::new(),
                    vec![
                        studio_test_render_capture(
                            StudioArtifactRenderCaptureViewport::Desktop,
                            84,
                            620,
                            4,
                        ),
                        studio_test_render_capture(
                            StudioArtifactRenderCaptureViewport::Mobile,
                            72,
                            540,
                            4,
                        ),
                    ],
                )));
            }

            Ok(Some(StudioArtifactRenderEvaluation {
                supported: true,
                first_paint_captured: true,
                interaction_capture_attempted: true,
                captures: vec![
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Desktop,
                        80,
                        580,
                        4,
                    ),
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Mobile,
                        68,
                        500,
                        4,
                    ),
                ],
                layout_density_score: 3,
                spacing_alignment_score: 3,
                typography_contrast_score: 4,
                visual_hierarchy_score: 3,
                blueprint_consistency_score: 3,
                overall_score: 12,
                findings: vec![StudioArtifactRenderFinding {
                    code: "runtime_boot_clean".to_string(),
                    severity: StudioArtifactRenderFindingSeverity::Blocked,
                    summary: "TypeError: stage.forEach is not a function".to_string(),
                }],
                acceptance_obligations: vec![StudioArtifactAcceptanceObligation {
                    obligation_id: "runtime_boot_clean".to_string(),
                    family: "boot_truth".to_string(),
                    required: true,
                    status: StudioArtifactAcceptanceObligationStatus::Failed,
                    summary:
                        "No runtime witness errors were observed while validating the artifact."
                            .to_string(),
                    detail: Some("TypeError: stage.forEach is not a function".to_string()),
                    witness_ids: vec!["witness-1".to_string()],
                }],
                execution_witnesses: vec![StudioArtifactExecutionWitness {
                    witness_id: "witness-1".to_string(),
                    obligation_id: Some("controls_execute_cleanly".to_string()),
                    action_kind: "click".to_string(),
                    status: StudioArtifactExecutionWitnessStatus::Failed,
                    summary: "'Core concepts' triggered a runtime error.".to_string(),
                    detail: Some("TypeError: stage.forEach is not a function".to_string()),
                    selector: Some("[data-ioi-affordance-id=\"aff-1\"]".to_string()),
                    console_errors: vec!["TypeError: stage.forEach is not a function".to_string()],
                    state_changed: false,
                }],
                summary: "Runtime sanity found a concrete console failure.".to_string(),
                observation: None,
                acceptance_policy: None,
            }))
        }
    }

    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let evaluator = DirectAuthorRuntimeErrorEvaluator;
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(DirectAuthorRuntimeRepairRuntime {
                role: "production",
                calls: calls.clone(),
                provenance: StudioRuntimeProvenance {
                    kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture direct-author producer".to_string(),
                    model: Some("fixture-qwen-9b".to_string()),
                    endpoint: Some("fixture://producer".to_string()),
                },
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(DirectAuthorRuntimeRepairRuntime {
                role: "acceptance",
                calls: calls.clone(),
                provenance: StudioRuntimeProvenance {
                    kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture direct-author acceptance".to_string(),
                    model: Some("fixture-qwen-8b".to_string()),
                    endpoint: Some("fixture://acceptance".to_string()),
                },
            });
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let title = "Quantum computing explainer";
        let intent = "Create an interactive HTML artifact that explains quantum computers.";
        let runtime_plan = resolve_studio_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            title,
            intent,
            &request,
            None,
        )
        .await;

        let bundle =
            generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                StudioExecutionStrategy::DirectAuthor,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("direct-author runtime repair bundle");

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|entry| entry == "production:author"));
        assert!(recorded_calls.iter().any(|entry| entry.ends_with(":repair")));
        assert!(!recorded_calls.iter().any(|entry| entry == "acceptance:judge"));
        assert_eq!(
            bundle.judge.classification,
            StudioArtifactJudgeClassification::Pass
        );
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html"
                && file.body.contains("data-repaired=\"runtime-error\"")
        }));
    })
    .await;
}

#[test]
fn local_direct_author_prompt_omits_materialization_json_scaffolding() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let selected_skills = vec![StudioArtifactSelectedSkill {
        skill_hash: "skill-hash".to_string(),
        name: "frontend-skill".to_string(),
        description: "Create distinctive production-grade frontend interfaces.".to_string(),
        lifecycle_state: "promoted".to_string(),
        source_type: "filesystem".to_string(),
        reliability_bps: 9800,
        semantic_score_bps: 9100,
        adjusted_score_bps: 9450,
        relative_path: Some("skills/frontend-skill/SKILL.md".to_string()),
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![StudioArtifactSkillNeedKind::VisualArtDirection],
        match_rationale:
            "Matched the request because the artifact needs strong editorial frontend direction."
                .to_string(),
        guidance_markdown: Some(
            "Before coding, understand the context and commit to a bold aesthetic direction."
                .to_string(),
        ),
    }];

    let payload = build_studio_artifact_direct_author_prompt_for_runtime(
        "Quantum explainer",
        "Create an interactive HTML artifact that explains quantum computers.",
        &request,
        &brief,
        &selected_skills,
        None,
        "candidate-1",
        7,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        true,
    )
    .expect("direct author prompt");

    let prompt_text = serde_json::to_string(&payload).expect("prompt json");

    assert!(prompt_text
        .contains("Create an interactive HTML artifact that explains quantum computers."));
    assert!(prompt_text.contains("Prepared artifact brief:"));
    assert!(prompt_text.contains("Selected skill guidance:"));
    assert!(prompt_text.contains("frontend-skill"));
    assert!(prompt_text.contains("Return only one complete self-contained index.html."));
    assert!(prompt_text.contains("Keep inline CSS concise"));
    assert!(prompt_text.contains("End with a fully closed </main></body></html>."));
    assert!(!prompt_text.contains("Artifact request focus JSON:"));
    assert!(!prompt_text.contains("Current artifact context JSON:"));
    assert!(!prompt_text.contains("Candidate metadata:"));
}

#[test]
fn direct_author_markdown_generation_uses_raw_document_contract() {
    #[derive(Debug, Clone)]
    struct DirectAuthorMarkdownRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
        json_modes: Arc<Mutex<Vec<bool>>>,
        provenance: StudioRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorMarkdownRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            self.prompts
                .lock()
                .expect("prompt log")
                .push(prompt.clone());
            self.json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            let response = if prompt.contains("typed artifact brief planner") {
                serde_json::to_string(&sample_quantum_markdown_brief())
                    .expect("sample markdown brief should serialize")
            } else if prompt.contains("direct document author") {
                "# Quantum computers\n\n## Why they matter\nQuantum computers use superposition and interference to explore specific classes of problems differently from classical machines.\n\n## Core ideas\n- Qubits carry amplitudes instead of one fixed bit value.\n- Gates rotate state so interference can amplify useful outcomes.\n- Measurement collapses the state into a sampled result.\n\n## Practical caution\nUseful quantum workflows still depend on careful error handling, hardware constraints, and problem selection."
                    .to_string()
            } else if prompt.contains("typed artifact judge") {
                serde_json::json!({
                    "classification": "pass",
                    "requestFaithfulness": 5,
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
                    "issueClasses": [],
                    "repairHints": [],
                    "strengths": ["Request-specific markdown document"],
                    "blockedReasons": [],
                    "fileFindings": [],
                    "aestheticVerdict": "The markdown document is specific and complete.",
                    "interactionVerdict": "Direct authoring was appropriate for a single document.",
                    "truthfulnessWarnings": [],
                    "recommendedNextPass": "accept",
                    "strongestContradiction": null,
                    "rationale": "The markdown artifact directly answers the request."
                })
                .to_string()
            } else {
                return Err(VmError::HostError(format!(
                    "unexpected Studio prompt in markdown direct-author test runtime: {prompt}"
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            self.provenance.clone()
        }
    }

    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorMarkdownRuntime {
        prompts: prompts.clone(),
        json_modes: json_modes.clone(),
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture markdown direct-author runtime".to_string(),
            model: Some("fixture-direct-author-markdown".to_string()),
            endpoint: Some("fixture://direct-author-markdown".to_string()),
        },
    });
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown);
    let title = "Quantum computers brief";
    let intent = "Create a markdown artifact that explains quantum computers";

    let bundle = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let runtime_plan = resolve_studio_artifact_runtime_plan(
                &request,
                runtime.clone(),
                None,
                StudioArtifactRuntimePolicyProfile::FullyLocal,
            );
            let planning_context = planned_prepared_context_with_runtime_plan(
                &runtime_plan,
                title,
                intent,
                &request,
                None,
            )
            .await;
            generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                StudioExecutionStrategy::DirectAuthor,
                None,
                None,
                None,
            )
            .await
        })
        .expect("markdown direct author bundle");

    let prompt_log = prompts.lock().expect("prompt log");
    let direct_author_prompt = prompt_log
        .iter()
        .find(|prompt| prompt.contains("direct document author"))
        .expect("direct author prompt");
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("Raw user request:")));
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("Return only one complete markdown document.")));
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("typed artifact brief planner")));
    assert!(!direct_author_prompt.contains("Return exactly one JSON object"));
    assert!(json_modes
        .lock()
        .expect("json mode log")
        .iter()
        .any(|json_mode| !json_mode));
    assert_eq!(bundle.winner.files[0].path, "artifact.md");
    assert_eq!(bundle.winner.files[0].mime, "text/markdown");
    assert!(bundle.winner.files[0]
        .body
        .starts_with("# Quantum computers"));
    assert_eq!(
        bundle
            .execution_envelope
            .as_ref()
            .and_then(|entry| entry.strategy),
        Some(StudioExecutionStrategy::DirectAuthor)
    );
}

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
            let prompt = decode_studio_test_prompt(input_context);
            let response = if prompt.contains("typed artifact brief planner") {
                serde_json::to_string(&sample_quantum_markdown_brief())
                    .expect("sample markdown brief should serialize")
            } else if prompt.contains("direct document author") {
                "# Quantum computers\n\nQuantum computing uses qubits, interference, and measurement to solve certain classes of problems differently from classical machines.\n\n## Core concepts\n- Superposition keeps multiple amplitudes in play.\n- Entanglement links qubit states.\n- Measurement samples a concrete result."
                    .to_string()
            } else if prompt.contains("typed artifact judge") {
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::FixtureRuntime,
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
            let prompt = decode_studio_test_prompt(input_context);
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::FixtureRuntime,
                label: "slow acceptance fixture".to_string(),
                model: Some("fixture-acceptance".to_string()),
                endpoint: Some("fixture://acceptance".to_string()),
            }
        }
    }

    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown);
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(FastProductionRuntime);
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowAcceptanceRuntime);
    let title = "Quantum computers brief";
    let intent = "Create a markdown artifact that explains quantum computers";
    let evaluator = StudioPassingRenderEvaluator;

    let bundle = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let runtime_plan = resolve_studio_artifact_runtime_plan(
                &request,
                production_runtime.clone(),
                Some(acceptance_runtime.clone()),
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
            );
            let planning_context = planned_prepared_context_with_runtime_plan(
                &runtime_plan,
                title,
                intent,
                &request,
                None,
            )
            .await;
            generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                StudioExecutionStrategy::DirectAuthor,
                Some(&evaluator),
                None,
                None,
            )
            .await
        })
        .expect("direct author fast surface should return a judged bundle");

    assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Judged);
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert!(bundle
        .judge
        .rationale
        .contains("without waiting on the slow acceptance gate"));
    assert_eq!(bundle.winner.files[0].path, "artifact.md");
    assert!(bundle.winning_candidate_id.is_some());
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

#[test]
fn requested_follow_up_pass_prefers_structural_repair_for_repairable_accept_mismatch() {
    let mut judge = studio_test_judge(
        StudioArtifactJudgeClassification::Repairable,
        false,
        5,
        5,
        4,
        4,
        5,
        4,
    );
    judge.recommended_next_pass = Some("accept".to_string());

    assert_eq!(requested_follow_up_pass(&judge), Some("structural_repair"));
}

#[test]
fn requested_follow_up_pass_prefers_polish_for_warning_only_render_eval_repairs() {
    let mut judge = studio_test_judge(
        StudioArtifactJudgeClassification::Repairable,
        false,
        5,
        5,
        5,
        4,
        5,
        4,
    );
    judge.issue_classes = vec!["render_eval".to_string()];
    judge.recommended_next_pass = Some("accept".to_string());

    assert_eq!(requested_follow_up_pass(&judge), Some("polish_pass"));
}

#[test]
fn requested_follow_up_pass_stops_for_clean_acceptance_clear() {
    let mut judge = studio_test_judge(
        StudioArtifactJudgeClassification::Pass,
        true,
        5,
        5,
        5,
        5,
        5,
        5,
    );
    judge.recommended_next_pass = Some("accept".to_string());

    assert_eq!(requested_follow_up_pass(&judge), None);
}

#[test]
fn requested_follow_up_pass_keeps_repairing_nontrivial_blocks() {
    let mut judge = studio_test_judge(
        StudioArtifactJudgeClassification::Blocked,
        false,
        4,
        5,
        2,
        2,
        2,
        3,
    );
    judge.repair_hints = vec![
        "Increase text contrast.".to_string(),
        "Strengthen visible interaction change.".to_string(),
    ];

    assert_eq!(requested_follow_up_pass(&judge), Some("structural_repair"));
}

#[test]
fn modal_first_refinement_directives_do_not_force_shared_detail_panels() {
    with_modal_first_html_env(|| {
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let judge = studio_test_judge(
            StudioArtifactJudgeClassification::Repairable,
            false,
            4,
            5,
            2,
            3,
            3,
            3,
        );

        let directives =
            super::studio_artifact_candidate_refinement_directives(&request, &brief, &judge);

        assert!(!directives
            .contains("Use a named control bar plus a shared detail or comparison panel"));
        assert!(directives.contains("detached shared-detail panel is optional"));
        assert!(directives.contains("chosen interaction grammar"));
    });
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
        acceptance_obligations: Vec::new(),
        execution_witnesses: Vec::new(),
        summary: "Render evaluation completed.".to_string(),
        observation: None,
        acceptance_policy: None,
    }
}

#[derive(Default)]
struct StudioPassingRenderEvaluator;

#[async_trait]
impl StudioArtifactRenderEvaluator for StudioPassingRenderEvaluator {
    async fn evaluate_candidate_render(
        &self,
        _request: &StudioOutcomeArtifactRequest,
        _brief: &StudioArtifactBrief,
        _blueprint: Option<&StudioArtifactBlueprint>,
        _artifact_ir: Option<&StudioArtifactIR>,
        _edit_intent: Option<&StudioArtifactEditIntent>,
        _candidate: &StudioGeneratedArtifactPayload,
    ) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
        Ok(Some(studio_test_render_evaluation(
            18,
            true,
            Vec::new(),
            vec![
                studio_test_render_capture(
                    StudioArtifactRenderCaptureViewport::Desktop,
                    88,
                    720,
                    4,
                ),
                studio_test_render_capture(StudioArtifactRenderCaptureViewport::Mobile, 72, 610, 4),
            ],
        )))
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
fn render_eval_merge_overrides_accept_to_polish_for_warning_only_regressions() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let mut judge = studio_test_judge(
        StudioArtifactJudgeClassification::Pass,
        true,
        5,
        5,
        5,
        4,
        5,
        4,
    );
    judge.recommended_next_pass = Some("accept".to_string());
    let render_evaluation = studio_test_render_evaluation(
        17,
        true,
        vec![StudioArtifactRenderFinding {
            code: "alignment_unstable".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Warning,
            summary: "Captured viewports show weak alignment or inconsistent spacing cadence."
                .to_string(),
        }],
        vec![
            studio_test_render_capture(StudioArtifactRenderCaptureViewport::Desktop, 12, 1629, 5),
            studio_test_render_capture(StudioArtifactRenderCaptureViewport::Mobile, 7, 1076, 3),
        ],
    );

    let merged = merge_studio_artifact_render_evaluation_into_judge(
        &request,
        judge,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert_eq!(merged.recommended_next_pass.as_deref(), Some("polish_pass"));
    assert_eq!(
        merged.strongest_contradiction.as_deref(),
        Some("Captured viewports show weak alignment or inconsistent spacing cadence.")
    );
}

#[test]
fn render_eval_merge_ignores_unsupported_markdown_failures() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown);
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
    let render_evaluation = StudioArtifactRenderEvaluation {
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
        findings: vec![StudioArtifactRenderFinding {
            code: "render_eval_failure".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
                summary: "Render evaluation failed before Studio could verify the surfaced first paint: Driver internal error: JS decode failed: No value found".to_string(),
        }],
        acceptance_obligations: Vec::new(),
        execution_witnesses: Vec::new(),
        summary: "Render evaluation failed before Studio could verify the surfaced first paint: Driver internal error: JS decode failed: No value found".to_string(),
        observation: None,
        acceptance_policy: None,
    };

    let merged = merge_studio_artifact_render_evaluation_into_judge(
        &request,
        judge.clone(),
        Some(&render_evaluation),
    );

    assert_eq!(merged.classification, judge.classification);
    assert_eq!(
        merged.deserves_primary_artifact_view,
        judge.deserves_primary_artifact_view
    );
    assert!(!merged
        .issue_classes
        .iter()
        .any(|value| value == "render_eval"));
}

#[test]
fn render_evaluation_required_skips_default_markdown_requests() {
    let mut request = request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown);
    request.verification.require_render = false;

    assert!(!render_evaluation_required(&request));
}

#[test]
fn render_evaluation_required_preserves_html_first_paint_checks() {
    let mut request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    request.verification.require_render = false;

    assert!(render_evaluation_required(&request));
}

#[test]
fn render_eval_merge_blocks_pass_when_required_execution_obligations_fail() {
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
    let render_evaluation = StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: true,
        captures: vec![
            studio_test_render_capture(StudioArtifactRenderCaptureViewport::Desktop, 24, 220, 4),
            studio_test_render_capture(StudioArtifactRenderCaptureViewport::Mobile, 22, 196, 4),
        ],
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 4,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 4,
        overall_score: 20,
        findings: Vec::new(),
        acceptance_obligations: vec![StudioArtifactAcceptanceObligation {
            obligation_id: "controls_execute_cleanly".to_string(),
            family: "interaction_truth".to_string(),
            required: true,
            status: StudioArtifactAcceptanceObligationStatus::Failed,
            summary: "Surfaced controls executed without runtime errors or no-op behavior."
                .to_string(),
            detail: Some("successfulWitnesses=1 failedWitnesses=3".to_string()),
            witness_ids: vec!["witness-1".to_string()],
        }],
        execution_witnesses: vec![StudioArtifactExecutionWitness {
            witness_id: "witness-1".to_string(),
            obligation_id: Some("controls_execute_cleanly".to_string()),
            action_kind: "click".to_string(),
            status: StudioArtifactExecutionWitnessStatus::Failed,
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

    let merged = merge_studio_artifact_render_evaluation_into_judge(
        &request,
        judge,
        Some(&render_evaluation),
    );

    assert_eq!(
        merged.classification,
        StudioArtifactJudgeClassification::Repairable
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
struct StudioSlowRenderEvaluator;

#[async_trait]
impl StudioArtifactRenderEvaluator for StudioSlowRenderEvaluator {
    async fn evaluate_candidate_render(
        &self,
        _request: &StudioOutcomeArtifactRequest,
        _brief: &StudioArtifactBrief,
        _blueprint: Option<&StudioArtifactBlueprint>,
        _artifact_ir: Option<&StudioArtifactIR>,
        _edit_intent: Option<&StudioArtifactEditIntent>,
        _candidate: &StudioGeneratedArtifactPayload,
    ) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok(Some(studio_test_render_evaluation(
            20,
            true,
            Vec::new(),
            vec![studio_test_render_capture(
                StudioArtifactRenderCaptureViewport::Desktop,
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
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        render_eval_timeout_for_runtime(
            StudioRendererKind::Markdown,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        render_eval_timeout_for_runtime(
            StudioRendererKind::BundleManifest,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        None
    );
}

#[tokio::test]
async fn render_eval_wrapper_passes_through_non_local_results() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Interactive rollout artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>AI tools</h1></section><section><button type=\"button\">Compare</button></section><section><p>Evidence</p></section></main></body></html>".to_string(),
        }],
    };
    let evaluator = StudioSlowRenderEvaluator;

    let evaluation = evaluate_candidate_render_with_fallback(
        Some(&evaluator),
        &request,
        &brief,
        None,
        None,
        None,
        &candidate,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
    .await
    .expect("render evaluation result");

    assert!(evaluation.supported);
    assert!(evaluation.first_paint_captured);
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
        query_profile: None,
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
        query_profile: None,
    };

    let error = validate_studio_artifact_brief_against_request(&brief, &request, None)
        .expect_err("ungrounded interaction metaphors should be rejected");
    assert!(error.contains("grounded in request concepts"));
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
        query_profile: None,
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
            query_profile: None,
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
            query_profile: None,
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
            query_profile: None,
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
fn studio_artifact_production_sources_do_not_special_case_quantum_fixture() {
    for source in [
        include_str!("planning.rs"),
        include_str!("generation/mod.rs"),
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
fn local_html_artifact_brief_prompt_is_compact_for_runtime() {
    let remote_prompt = build_studio_artifact_brief_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
    )
    .expect("remote brief prompt");
    let local_prompt = build_studio_artifact_brief_prompt_for_runtime(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    )
    .expect("local brief prompt");

    let remote_prompt_bytes = serde_json::to_vec(&remote_prompt).expect("remote prompt bytes");
    let local_prompt_bytes = serde_json::to_vec(&local_prompt).expect("local prompt bytes");
    let local_prompt_text = decode_studio_test_prompt(&local_prompt_bytes);

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
    let prompt = build_studio_artifact_brief_field_repair_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        None,
        "{\"audience\":\"\"}",
        "{\"subjectDomain\":\"\"}",
        "Studio artifact brief fields must not be empty.",
    )
    .expect("field repair prompt");
    let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
    let prompt_text = decode_studio_test_prompt(&prompt_bytes);

    assert!(prompt_text.contains("Planner output preview"));
    assert!(prompt_text.contains("Repair output preview"));
    assert!(prompt_text.contains("Studio artifact brief fields must not be empty."));
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
        query_profile: None,
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
        query_profile: None,
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
        query_profile: None,
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
fn rollover_failure_directives_require_focusable_detail_marks() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = studio_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe artifacts that wire focus-based detail behavior must make their data-detail marks keyboard-focusable.",
    );

    assert!(directives.contains("keep the current <main>"));
    assert!(directives.contains("querySelectorAll('[data-detail]')"));
    assert!(directives.contains("tabindex=\"0\""));
    assert!(directives.contains("[data-view-panel]"));
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
        query_profile: None,
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
        query_profile: None,
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
        query_profile: None,
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
fn modal_first_html_local_runtime_candidate_generation_uses_single_candidate() {
    with_modal_first_html_env(|| {
        let (count, temperature, strategy) = candidate_generation_config(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        );
        assert_eq!(count, 1);
        assert!(temperature >= 0.68);
        assert_eq!(strategy, "request-grounded_html");
    });
}

#[test]
fn modal_first_html_local_runtime_materialization_token_budget_expands_completion_room() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::generation::materialization_max_tokens_for_runtime(
                StudioRendererKind::HtmlIframe,
                StudioRuntimeProvenanceKind::RealLocalRuntime,
            ),
            4200
        );
    });
}

#[test]
fn local_html_direct_author_budget_matches_local_materialization_budget() {
    super::with_studio_modal_first_html_override(false, || {
        assert_eq!(
            super::generation::materialization_max_tokens_for_execution_strategy(
                StudioRendererKind::HtmlIframe,
                StudioExecutionStrategy::DirectAuthor,
                StudioRuntimeProvenanceKind::RealLocalRuntime,
            ),
            super::generation::materialization_max_tokens_for_runtime(
                StudioRendererKind::HtmlIframe,
                StudioRuntimeProvenanceKind::RealLocalRuntime,
            ),
        );
    });
}

#[test]
fn modal_first_html_direct_author_budget_expands_completion_room() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::generation::materialization_max_tokens_for_execution_strategy(
                StudioRendererKind::HtmlIframe,
                StudioExecutionStrategy::DirectAuthor,
                StudioRuntimeProvenanceKind::RealLocalRuntime,
            ),
            4200
        );
    });
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
fn modal_first_html_local_runtime_refinement_budget_allows_one_pass() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::judging::semantic_refinement_pass_limit(
                StudioRendererKind::HtmlIframe,
                StudioRuntimeProvenanceKind::RealLocalRuntime,
            ),
            1
        );
    });
}

#[test]
fn modal_first_quantum_html_budget_stays_user_viable() {
    with_modal_first_html_env(|| {
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
            StudioArtifactRuntimePolicyProfile::FullyLocal,
            false,
        );

        assert_eq!(budget.initial_candidate_count, 1);
        assert_eq!(budget.max_candidate_count, 1);
        assert_eq!(budget.shortlist_limit, 1);
        assert_eq!(budget.max_semantic_refinement_passes, 1);
        assert!(budget
            .signals
            .contains(&StudioAdaptiveSearchSignal::LocalGenerationConstraint));
    });
}

#[test]
fn modal_first_quantum_html_budget_reopens_for_judge_backed_runtime_profile() {
    with_modal_first_html_env(|| {
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
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
            false,
        );

        assert_eq!(budget.initial_candidate_count, 1);
        assert!(budget.max_candidate_count >= 3);
        assert!(budget.shortlist_limit >= 3);
        assert_eq!(budget.max_semantic_refinement_passes, 3);
        assert!(budget
            .signals
            .contains(&StudioAdaptiveSearchSignal::LocalGenerationConstraint));
    });
}

#[test]
fn modal_first_local_html_prompt_pushes_authored_interactive_explainers() {
    with_modal_first_html_env(|| {
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();

        let prompt = build_studio_artifact_materialization_prompt_for_runtime(
            "Quantum computing explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-1",
            42,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        )
        .expect("modal-first local prompt");

        let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
        let prompt_text = decode_studio_test_prompt(&prompt_bytes);

        assert!(prompt_text.contains(
            "prefer a living model, scenario walkthrough, inspectable diagram, or guided comparison"
        ));
        assert!(prompt_text
            .contains("one isolated button or slider does not satisfy an interactive artifact"));
        assert!(prompt_text.contains("avoid default browser-white document styling"));
    });
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
fn parse_and_validate_recovers_raw_html_payloads_and_normalizes_custom_fonts() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = "<!doctype html><html><head><style>:root{--display-font:'Newsreader',serif;}body{font-family:'Newsreader',serif;background:#f8fafc;color:#0f172a;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #cbd5e1;border-radius:12px;}button{font-family:'Instrument Sans',sans-serif;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics</h2><p>Metrics evidence stays pre-rendered.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>";

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("raw html payloads should be recoverable for html iframe artifacts");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("normalized from raw html document output")));
    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(!html.contains("font-family:'newsreader'"));
    assert!(!html.contains("font-family:'instrument sans'"));
    assert!(html.contains("ui-serif, serif"));
    assert!(html.contains("system-ui, sans-serif"));
}

#[test]
fn parse_and_validate_recovers_raw_markdown_payloads() {
    let request = request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown);
    let raw = "```markdown\n# Quantum computers\n\n## Core idea\nQuantum computers use qubits, interference, and measurement to solve specific classes of problems differently from classical systems.\n\n## What changes in practice\nTeams still need algorithm fit, hardware realism, and error mitigation.\n```";

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("raw markdown payloads should be recoverable for direct document artifacts");

    assert_eq!(payload.files[0].path, "artifact.md");
    assert_eq!(payload.files[0].mime, "text/markdown");
    assert!(payload.files[0].body.starts_with("# Quantum computers"));
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("normalized from raw markdown document output")));
}

#[test]
fn parse_and_validate_recovers_raw_svg_payloads() {
    let request = request_for(StudioArtifactClass::Visual, StudioRendererKind::Svg);
    let raw = "Here is the document:\n<svg viewBox=\"0 0 240 140\" xmlns=\"http://www.w3.org/2000/svg\"><title>Quantum comparison</title><desc>Compares classical and quantum states.</desc><rect x=\"16\" y=\"58\" width=\"42\" height=\"54\" /><rect x=\"84\" y=\"34\" width=\"42\" height=\"78\" /><rect x=\"152\" y=\"20\" width=\"42\" height=\"92\" /><text x=\"16\" y=\"130\">Bit</text><text x=\"84\" y=\"130\">Qubit</text><text x=\"152\" y=\"130\">Measure</text></svg>\nThanks.";

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("raw svg payloads should be recoverable for direct document artifacts");

    assert_eq!(payload.files[0].path, "artifact.svg");
    assert_eq!(payload.files[0].mime, "image/svg+xml");
    assert!(payload.files[0].body.starts_with("<svg"));
    assert!(payload.files[0].body.ends_with("</svg>"));
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("normalized from raw svg document output")));
}

#[test]
fn modal_first_html_requires_real_interaction_instead_of_injected_disclosure() {
    with_modal_first_html_env(|| {
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let raw = serde_json::json!({
            "summary": "Quantum computing explainer",
            "notes": ["model emitted a static page shell"],
            "files": [{
                "path": "quantum-explainer.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><header><h1>Quantum computing explained</h1><p>Understand superposition, entanglement, and measurement through concise sections.</p></header><section><h2>Superposition</h2><p>Qubits carry probability amplitudes before observation.</p></section><section><h2>Entanglement</h2><p>Entangled systems share state relationships across distance.</p></section><section><h2>Measurement</h2><p>Measurement collapses the quantum state into a classical outcome.</p></section></body></html>"
            }]
        })
        .to_string();

        let error = parse_and_validate_generated_artifact_payload(&raw, &request).expect_err(
            "modal-first html should require authored interaction instead of injecting one",
        );

        assert!(error.contains("must contain real interactive controls or handlers"));
    });
}

#[test]
fn modal_first_html_validation_rejects_truncated_documents() {
    with_modal_first_html_env(|| {
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let raw = "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button></section><section><article><h2>Quantum circuit</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Quantum circuit\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Gate</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Superposition is selected by default.</p></aside><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.getElementById('detail-copy').textContent=button.dataset.view;}));</script><div class=\"";

        let error = parse_and_validate_generated_artifact_payload(raw, &request)
            .expect_err("truncated modal-first html should be rejected before promotion");

        assert!(error.contains("fully closed </body></html> document"));
    });
}

#[test]
fn modal_first_html_validation_rejects_structurally_truncated_documents_even_with_terminal_closers()
{
    with_modal_first_html_env(|| {
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let raw = "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button><section><article><h2>Quantum circuit</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Quantum circuit\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Gate</text></svg></article></section></main></body></html>";

        let error = parse_and_validate_generated_artifact_payload(raw, &request).expect_err(
            "terminally closed but structurally truncated modal-first html should be rejected",
        );

        assert!(error
            .contains("must not close the document while non-void HTML elements remain unclosed"));
    });
}

#[test]
fn modal_first_html_normalization_closes_missing_terminal_suffix() {
    with_modal_first_html_env(|| {
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let raw = "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button></section><section><article><h2>Quantum circuit</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Quantum circuit\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Gate</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Superposition is selected by default.</p></aside><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.getElementById('detail-copy').textContent=button.dataset.view;}));</script>";

        let payload = parse_and_validate_generated_artifact_payload(raw, &request)
            .expect("modal-first normalization should close a missing terminal html suffix");

        let html = payload.files[0].body.to_ascii_lowercase();
        assert!(html.ends_with("</main></body></html>"));
        validate_generated_artifact_payload(&payload, &request)
            .expect("the normalized html suffix should validate");
    });
}

#[test]
fn parse_and_validate_rejects_structurally_truncated_svg_even_with_terminal_closer() {
    let request = request_for(StudioArtifactClass::Visual, StudioRendererKind::Svg);
    let raw = "<svg viewBox=\"0 0 240 140\" xmlns=\"http://www.w3.org/2000/svg\"><g><rect x=\"16\" y=\"58\" width=\"42\" height=\"54\" /></svg>";

    let error = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect_err("terminally closed but structurally truncated svg should be rejected");

    assert!(error.contains("must not close the document while SVG elements remain unclosed"));
}

#[test]
fn parse_and_validate_extracts_html_from_mixed_json_and_html_output() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = concat!(
        "{\"summary\":\"Interactive HTML artifact\",\"notes\":[\"model spilled both formats\"],",
        "\"files\":[{\"path\":\"artifact.html\",\"mime\":\"text/html\",\"role\":\"primary\",",
        "\"renderable\":true,\"downloadable\":false,\"encoding\":\"utf8\",\"body\":\"truncated\"}]}",
        "\n<!doctype html><html><body><main><section><h1>Quantum computers explained</h1>",
        "<p>Inspect qubits, superposition, and entanglement through authored states.</p>",
        "<button type=\"button\" data-view=\"qubits\" aria-controls=\"qubits-panel\">Qubits</button>",
        "<button type=\"button\" data-view=\"entanglement\" aria-controls=\"entanglement-panel\">Entanglement</button>",
        "</section><section id=\"qubits-panel\" data-view-panel=\"qubits\"><article><h2>Qubits</h2>",
        "<p>Qubits encode amplitudes instead of a fixed binary state.</p></article></section>",
        "<section id=\"entanglement-panel\" data-view-panel=\"entanglement\" hidden><article><h2>Entanglement</h2>",
        "<p>Entangled pairs preserve correlated outcomes across distance.</p></article></section>",
        "<aside><h2>Detail</h2><p id=\"detail-copy\">Qubits are selected by default.</p></aside>",
        "<script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script>",
        "</main></body></html>\ntrailing prose that should be discarded"
    );

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("mixed json/html output should salvage the authored html document");

    assert_eq!(payload.files[0].path, "artifact.html");
    assert!(payload.files[0].body.starts_with("<!doctype html>"));
    assert!(payload.files[0]
        .body
        .contains("Quantum computers explained"));
    assert!(!payload.files[0].body.contains("\"summary\":"));
    assert!(!payload.files[0]
        .body
        .contains("trailing prose that should be discarded"));
}

#[test]
fn parse_and_validate_accepts_file_content_aliases_for_download_cards() {
    let request = request_for(
        StudioArtifactClass::DownloadableFile,
        StudioRendererKind::DownloadCard,
    );
    let raw = serde_json::json!({
        "summary": "Download bundle",
        "notes": ["local-runtime alias payload"],
        "files": [{
            "path": "README.md",
            "mime": "text/markdown",
            "role": "supporting",
            "renderable": false,
            "downloadable": true,
            "encoding": "utf8",
            "content": "# Bundle\n\nUse the CSV export for launch review."
        }, {
            "path": "exports/launch-metrics.csv",
            "mime": "text/csv",
            "role": "export",
            "renderable": false,
            "downloadable": true,
            "encoding": "utf8",
            "text": "lane,metric,value\npilot,coverage,72\nlaunch,readiness,81\n"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("content aliases should normalize into generated file bodies");

    assert_eq!(payload.files.len(), 2);
    assert_eq!(
        payload.files[0].body,
        "# Bundle\n\nUse the CSV export for launch review."
    );
    assert_eq!(
        payload.files[1].body,
        "lane,metric,value\npilot,coverage,72\nlaunch,readiness,81\n"
    );
}

#[test]
fn parse_and_validate_recovers_download_card_missing_readme_and_placeholder_csv() {
    let request = request_for(
        StudioArtifactClass::DownloadableFile,
        StudioRendererKind::DownloadCard,
    );
    let raw = serde_json::json!({
        "summary": "A downloadable artifact bundle with a CSV and README",
        "notes": [
            "The artifact includes a non-empty README.md file explaining the bundle contents.",
            "The CSV export has at least two data rows with request-grounded values."
        ],
        "files": [{
            "path": "README.md",
            "mime": "text/markdown",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": null
        }, {
            "path": "data.csv",
            "mime": "text/csv",
            "role": "export",
            "renderable": false,
            "downloadable": true,
            "body": "CSV export with at least two data rows"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("download card salvage should recover missing README and CSV bodies");

    assert_eq!(payload.files.len(), 2);
    assert!(payload.files.iter().all(|file| !file.renderable));
    let readme = payload
        .files
        .iter()
        .find(|file| file.path == "README.md")
        .expect("README file");
    let csv = payload
        .files
        .iter()
        .find(|file| file.path == "data.csv")
        .expect("CSV file");
    assert!(readme.body.contains("## Files"));
    assert!(readme.body.contains("## CSV columns"));
    assert!(csv.body.starts_with("record,detail"));
    assert!(csv.body.lines().count() >= 4);
}

#[test]
fn accepts_html_payloads_with_negated_placeholder_wording_and_no_comments() {
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
                body: "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>No placeholders or TODOs appear in this launch brief; the page starts with real copy and evidence.</p><div class=\"control-bar\"><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"signals\" aria-controls=\"signals-panel\">Signals</button></div></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Adoption view</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Adoption by workflow\"><rect x=\"20\" y=\"44\" width=\"40\" height=\"56\" data-detail=\"Drafting copilots lead adoption\" tabindex=\"0\"></rect><rect x=\"88\" y=\"30\" width=\"40\" height=\"70\" data-detail=\"Research copilots show the strongest trust lift\" tabindex=\"0\"></rect><text x=\"20\" y=\"114\">Drafting</text><text x=\"88\" y=\"114\">Research</text></svg></article></section><section id=\"signals-panel\" data-view-panel=\"signals\" hidden><article><h2>Signal rail</h2><ul><li>Fact-check coverage rose across launch week.</li><li>Editorial confidence improved after revisions.</li><li>Operator guidance stayed visible on first paint.</li></ul></article></section><aside id=\"detail-panel\"><h2>Shared detail</h2><p id=\"detail-copy\">Drafting copilots lead adoption by default.</p></aside><footer><p>Use the control bar to compare the launch evidence and update the shared detail panel.</p></footer></main><script>const buttons=Array.from(document.querySelectorAll('[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const marks=Array.from(document.querySelectorAll('[data-detail]'));buttons.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{const active=panel.dataset.viewPanel===button.dataset.view;panel.hidden=!active;});}));marks.forEach((mark)=>{const syncDetail=()=>{detail.textContent=mark.dataset.detail||'';};mark.addEventListener('mouseenter',syncDetail);mark.addEventListener('focus',syncDetail);});</script></body></html>".to_string(),
            }],
        };

    validate_generated_artifact_payload(
        &payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
    )
    .expect("negated placeholder wording without comments should stay valid");
}

#[test]
fn parse_and_validate_preserves_authored_controls_without_injecting_disclosure() {
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout artifact",
            "notes": ["authored inline response interaction"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><button id=\"proof-button\" type=\"button\">Show proof</button></section><article><h2>Channel evidence</h2><ul><li>Retail adoption 48%</li><li>Subscription adoption 36%</li></ul></article><aside aria-live=\"polite\"><p id=\"proof-copy\">Retail adoption is leading the launch.</p></aside><footer><p>Operators can inspect the rollout plan inline.</p></footer><script>const proof=document.getElementById('proof-copy');document.getElementById('proof-button').addEventListener('click',()=>{proof.textContent='Subscription adoption accelerated during week two.';});</script></main></body></html>"
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
    .expect("authored inline response HTML should remain valid without disclosure injection");

    let html = &payload.files[0].body;
    assert!(!html.to_ascii_lowercase().contains("alert("));
    assert!(html.contains("<button"));
    assert!(!html.contains("data-studio-interaction=\"true\""));
}

#[test]
fn parse_and_validate_rejects_static_interactive_html_without_real_controls() {
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
    );

    let error = payload.expect_err(
        "static interactive HTML should be rejected instead of gaining a synthetic disclosure",
    );
    assert!(error.contains("must contain real interactive controls or handlers"));
}

#[test]
fn validate_generated_html_accepts_data_view_controls_mapped_to_panel_ids() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "AI tools editors".to_string(),
        job_to_be_done: "review the launch evidence".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show the launch evidence clearly".to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "interactive HTML".to_string(),
        ],
        required_interactions: vec![
            "click to explore AI tools".to_string(),
            "hover to inspect editorial highlights".to_string(),
        ],
        visual_tone: vec!["modern".to_string()],
        factual_anchors: vec!["AI tools editorial launch page".to_string()],
        style_directives: vec!["responsive design".to_string()],
        reference_hints: vec!["HTML iframe integration".to_string()],
        query_profile: Some(StudioArtifactQueryProfile {
            content_goals: Vec::new(),
            interaction_goals: vec![
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::StateSwitch,
                    "Switch between authored evidence views.",
                ),
                required_interaction_goal(
                    StudioArtifactInteractionGoalKind::DetailInspect,
                    "Inspect focused editorial highlights in a visible response region.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::PrimarySurface,
                    "Show the primary AI tools evidence view.",
                ),
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::ComparisonSurface,
                    "Provide a comparison evidence view for launch planning.",
                ),
                required_evidence_goal(
                    StudioArtifactEvidenceGoalKind::DetailSurface,
                    "Keep a detail surface visible during interaction.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::SemanticStructure,
                    "Use semantic sections for first-paint structure.",
                ),
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Keep authored evidence visible on first paint.",
                ),
                required_presentation_constraint(
                    StudioArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a populated response region visible on first paint.",
                ),
            ],
        }),
    };
    let raw = serde_json::json!({
        "summary": "AI tools editorial launch",
        "notes": ["data-view buttons map directly to panel ids"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Switch between the evidence views.</p><button data-view=\"tools\">AI Tools</button><button data-view=\"comparison\">Tool Comparison</button></section><section id=\"tools\"><article><h2>AI tools</h2><ul><li tabindex=\"0\" data-detail=\"Content generator adoption grew 22% week over week.\">Content generator adoption grew 22% week over week.</li><li tabindex=\"0\" data-detail=\"Grammar checker retention held at 91% across pilot accounts.\">Grammar checker retention held at 91% across pilot accounts.</li><li tabindex=\"0\" data-detail=\"Fact checker review time dropped to 6 minutes per story.\">Fact checker review time dropped to 6 minutes per story.</li></ul></article></section><section id=\"comparison\" hidden><article><h2>Comparison</h2><dl><dt>Editors</dt><dd>Saved 14 minutes per draft on average.</dd><dt>Publishers</dt><dd>Improved throughput by 11% across launch week.</dd><dt>Reviewers</dt><dd>Reduced factual follow-up loops by 3 per story.</dd></dl></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">AI tools is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('#tools, #comparison');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.dataset.view;});detail.textContent=button.textContent;}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("data-view controls should normalize into mapped panels");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("data-view to id panel mapping should satisfy visible mapped panel validation");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-view=\"tools\""));
    assert!(html.contains("id=\"tools\""));
    assert!(html.contains("id=\"detail-copy\""));
}

#[test]
fn ensure_minimum_html_sectioning_elements_groups_consecutive_controls_and_marks() {
    let html = "<!doctype html><html><body><main><header><h1>AI Tools Editorial Launch</h1><p>Explore the future of AI tools with interactive features and demos.</p></header><button data-view=\"overview\">Overview</button><button data-view=\"features\">Features</button><button data-view=\"demos\">Demos</button><div class=\"evidence\" data-view-panel=\"overview\"><h3>Overview</h3><p>Overview evidence stays visible on first paint.</p></div><div class=\"evidence\" data-view-panel=\"features\" hidden><h3>Features</h3><ul><li>Real-time content generation</li><li>Collaborative editing tools</li></ul></div><h3>Demos</h3><p>Hover or click the following to preview tool demos:</p><div class=\"data-detail\" data-detail=\"demo1\">Demo 1: Content Generation</div><div class=\"data-detail\" data-detail=\"demo2\">Demo 2: Analytics Dashboard</div><div class=\"data-detail\" data-detail=\"demo3\">Demo 3: Collaborative Editing</div><div class=\"shared-detail\"><h4>Shared Detail</h4><p>Default detail copy stays visible.</p></div></main></body></html>";

    let normalized = ensure_minimum_html_sectioning_elements(html);
    let lower = normalized.to_ascii_lowercase();

    assert!(count_html_sectioning_elements(&lower) >= 3);
    assert!(!lower.contains(
        "</button></section><section data-studio-normalized=\"true\"><button data-view=\"features\""
    ));
    assert!(!lower.contains(
        "</p></section><section data-studio-normalized=\"true\"><div class=\"data-detail\" data-detail=\"demo1\">"
    ));
}

#[test]
fn renderer_contract_allows_near_pass_html_after_normalization_repairs() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "AI tools editors and publishers".to_string(),
        job_to_be_done: "launch an AI tools editorial with an interactive HTML artifact"
            .to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "an interactive HTML artifact that showcases AI tools for editorial use"
            .to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "interactive HTML".to_string(),
        ],
        required_interactions: vec![
            "click to explore AI tools".to_string(),
            "hover to view tool features".to_string(),
        ],
        visual_tone: vec![
            "modern".to_string(),
            "clean".to_string(),
            "professional".to_string(),
        ],
        factual_anchors: vec!["AI tools editorial launch page".to_string()],
        style_directives: vec![
            "responsive design".to_string(),
            "user-friendly interface".to_string(),
        ],
        reference_hints: vec!["HTML iframe integration".to_string()],
        query_profile: None,
    };
    let payload = parse_and_validate_generated_artifact_payload(
        include_str!("test_fixtures/qwen3_editorial_trace8_near_pass.html"),
        &request,
    )
    .expect("fixture should parse and normalize");

    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("fixture should stay above the first-paint contract");

    let judge = StudioArtifactJudgeResult {
        classification: StudioArtifactJudgeClassification::Pass,
        request_faithfulness: 5,
        concept_coverage: 5,
        interaction_relevance: 4,
        layout_coherence: 4,
        visual_hierarchy: 4,
        completeness: 4,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: true,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes: vec!["first-paint evidence density could be higher".to_string()],
        repair_hints: vec!["add more populated evidence surfaces".to_string()],
        strengths: vec![
            "interactive control bar with active state styling".to_string(),
            "responsive design".to_string(),
        ],
        blocked_reasons: Vec::new(),
        file_findings: Vec::new(),
        aesthetic_verdict: "Clean and modern visual tone.".to_string(),
        interaction_verdict: "Interaction contract is satisfied.".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("accept".to_string()),
        strongest_contradiction: None,
        rationale: "Complies with the interaction contract and stays request-faithful.".to_string(),
    };

    let result = enforce_renderer_judge_contract(&request, &brief, &payload, judge);

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert!(!result.trivial_shell_detected);
    assert!(result.blocked_reasons.is_empty());
    assert_eq!(result.strongest_contradiction, None);
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
            query_profile: None,
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
fn normalize_generated_artifact_payload_unwraps_nested_html_json_envelopes() {
    let nested_payload = serde_json::json!({
        "summary": "Nested HTML payload",
        "notes": ["wrapped once"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Explore the launch.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\" aria-selected=\"true\">Overview</button><button type=\"button\" data-view=\"features\" aria-controls=\"features-panel\" aria-selected=\"false\">Features</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Overview evidence is visible on first paint.</p></article></section><section id=\"features-panel\" data-view-panel=\"features\" hidden><article><h2>Features</h2><p>Feature evidence remains pre-rendered.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside></main><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-view-panel]').forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});document.getElementById('detail-copy').textContent=`${button.dataset.view} selected`; }));</script></body></html>"
        }]
    })
    .to_string();
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
            body: nested_payload,
        }],
    };
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );

    normalize_generated_artifact_payload(&mut payload, &request);

    let body = payload.files[0].body.trim();
    assert!(body.to_ascii_lowercase().starts_with("<!doctype html>"));
    assert!(!body.starts_with('{'));
    assert!(!body.contains("\"files\""));
    assert!(body.contains("data-view-panel"));
    assert!(validate_generated_artifact_payload(&payload, &request).is_ok());
}

#[test]
fn normalize_generated_artifact_payload_decodes_json_escaped_html_bodies() {
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
            body: "<!doctype html>\\n<html lang=\\\"en\\\"><body><main><section><h1>Quantum states</h1><p>Inspect superposition without leaving the scene.</p></section><section><button type=\\\"button\\\" data-view=\\\"overview\\\" aria-controls=\\\"overview-panel\\\">Overview</button><button type=\\\"button\\\" data-view=\\\"interference\\\" aria-controls=\\\"interference-panel\\\">Interference</button></section><section id=\\\"overview-panel\\\" data-view-panel=\\\"overview\\\"><p>Default overview state.</p></section><section id=\\\"interference-panel\\\" data-view-panel=\\\"interference\\\" hidden><p>Interference details.</p></section></main><script>document.querySelectorAll('[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-view-panel]').forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});}));</script></body></html>".to_string(),
        }],
    };
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );

    normalize_generated_artifact_payload(&mut payload, &request);

    let body = payload.files[0].body.as_str();
    assert!(body.to_ascii_lowercase().starts_with("<!doctype html>"));
    assert!(!body.contains("\\n"));
    assert!(!body.contains("\\\""));
    assert!(body.contains("<main>"));
    assert!(validate_generated_artifact_payload(&payload, &request).is_ok());
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

#[test]
fn local_generation_remote_acceptance_prefers_local_specialist_for_markdown_generation_and_acceptance(
) {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_studio_artifact_runtime_plan(
        &request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown),
        production_runtime,
        Some(acceptance_runtime),
        StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert_eq!(planning_binding.provenance.label, "local specialist");
    assert!(!planning_binding.fallback_applied);

    let generation_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::CandidateGeneration)
        .expect("generation binding");
    assert_eq!(generation_binding.provenance.label, "local specialist");
    assert!(!generation_binding.fallback_applied);

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::AcceptanceJudge)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("compact_local_specialist_acceptance")
    );
}

#[test]
fn local_generation_remote_acceptance_prefers_local_specialist_for_download_bundle_acceptance() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_studio_artifact_runtime_plan(
        &request_for(
            StudioArtifactClass::DownloadableFile,
            StudioRendererKind::DownloadCard,
        ),
        production_runtime,
        Some(acceptance_runtime),
        StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::AcceptanceJudge)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("compact_local_specialist_acceptance")
    );
}

#[test]
fn local_generation_remote_acceptance_keeps_html_generation_on_primary_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_studio_artifact_runtime_plan(
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        production_runtime,
        Some(acceptance_runtime),
        StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let generation_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::CandidateGeneration)
        .expect("generation binding");
    assert_eq!(generation_binding.provenance.label, "local producer");
    assert!(!generation_binding.fallback_applied);

    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert_eq!(planning_binding.provenance.label, "local producer");
    assert!(!planning_binding.fallback_applied);

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::AcceptanceJudge)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(!acceptance_binding.fallback_applied);

    let repair_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == StudioArtifactRuntimeStep::RepairPlanning)
        .expect("repair binding");
    assert_eq!(repair_binding.provenance.label, "local specialist");
    assert!(!repair_binding.fallback_applied);
}

#[test]
fn modal_first_local_generation_remote_acceptance_keeps_html_generation_on_primary_runtime() {
    with_modal_first_html_env(|| {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            "local producer",
            "qwen2.5:14b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
        let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            "local specialist",
            "qwen3.5:9b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "acceptance",
            calls,
        ));

        let runtime_plan = resolve_studio_artifact_runtime_plan(
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
        );

        let planning_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == StudioArtifactRuntimeStep::BlueprintPlanning)
            .expect("planning binding");
        assert_eq!(planning_binding.provenance.label, "local producer");
        assert!(!planning_binding.fallback_applied);

        let generation_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == StudioArtifactRuntimeStep::CandidateGeneration)
            .expect("generation binding");
        assert_eq!(generation_binding.provenance.label, "local producer");
        assert!(!generation_binding.fallback_applied);

        let acceptance_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == StudioArtifactRuntimeStep::AcceptanceJudge)
            .expect("acceptance binding");
        assert_eq!(acceptance_binding.provenance.label, "local specialist");
        assert!(!acceptance_binding.fallback_applied);

        let repair_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == StudioArtifactRuntimeStep::RepairPlanning)
            .expect("repair binding");
        assert_eq!(repair_binding.provenance.label, "local specialist");
        assert!(!repair_binding.fallback_applied);
    });
}

#[test]
fn local_html_materialization_repair_prefers_local_specialist_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let repair_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "repair",
        calls,
    ));

    let selected_runtime = super::generation::materialization_repair_runtime_for_request(
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &production_runtime,
        Some(&repair_runtime),
    );

    assert_eq!(
        selected_runtime.studio_runtime_provenance().label,
        "local specialist"
    );
}

#[tokio::test]
async fn local_html_swarm_strategy_repairs_and_passes_quantum_artifact_regression() {
    #[derive(Clone)]
    struct QuantumSwarmRegressionRuntime {
        provenance: StudioRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for QuantumSwarmRegressionRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief"
            } else if prompt.contains("typed swarm Skeleton worker") {
                "skeleton"
            } else if prompt.contains("typed swarm SectionContent worker") {
                "section"
            } else if prompt.contains("typed swarm StyleSystem worker") {
                "style"
            } else if prompt.contains("typed swarm Interaction worker") {
                "interaction"
            } else if prompt.contains("typed swarm Repair worker") {
                "repair"
            } else if prompt.contains("typed swarm Integrator worker") {
                "integrator"
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
                "brief" => {
                    serde_json::to_value(sample_quantum_explainer_brief()).expect("quantum brief")
                }
                "skeleton" => serde_json::json!({
                    "summary": "Quantum computers interactive draft",
                    "notes": ["Created the bounded quantum explainer skeleton."],
                    "operations": [{
                        "kind": "create_file",
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><meta charset=\"utf-8\"><title>Quantum computers interactive explainer</title></head><body><main><section><h1>Quantum computers, step by step</h1><p>Compare classical bits with quantum states, then inspect how measurement changes the outcome.</p><div class=\"mode-switch\"><button type=\"button\" data-mode=\"classical\" aria-selected=\"true\">Classical Bit</button><button type=\"button\" data-mode=\"quantum\" aria-selected=\"false\">Quantum State</button></div></section><section><article><h2>State comparison</h2><p id=\"mode-summary\">Classical bits stay in one definite state at a time.</p></article></section><aside><h2>Inspector</h2><p id=\"detail-copy\">Select a mode to inspect the difference.</p></aside></main></body></html>"
                    }]
                }),
                "section" => serde_json::json!({
                    "summary": "Extended the bounded quantum section.",
                    "notes": ["Added a scoped comparison section patch."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<section class=\"comparison-band\"><article><h2>Probability intuition</h2><p>Quantum systems distribute likelihood across outcomes before measurement.</p></article></section>"
                    }]
                }),
                "style" => serde_json::json!({
                    "summary": "Applied the slate quantum style system.",
                    "notes": ["Added restrained slate styling for the explainer."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<style>:root{color-scheme:dark;--bg:#13171d;--panel:#1b222c;--panel-border:#2b3644;--text:#e6ebf2;--muted:#97a5b8;--accent:#7dd3fc;}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);}main{display:grid;gap:18px;padding:24px;max-width:960px;margin:0 auto;}section,aside{background:var(--panel);border:1px solid var(--panel-border);border-radius:18px;padding:18px;}button{border:1px solid #36506a;background:#1d2a38;color:var(--text);border-radius:999px;padding:10px 14px;cursor:pointer;}button[aria-selected=\"true\"]{border-color:var(--accent);box-shadow:0 0 0 1px rgba(125,211,252,.35) inset;}p{color:var(--muted);}h1,h2{margin:0 0 10px;}svg{width:100%;height:auto;display:block;}</style>"
                    }]
                }),
                "interaction" => serde_json::json!({
                    "summary": "Wired the bounded quantum interaction loop.",
                    "notes": ["Added button-driven explanation updates."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<script>const summary=document.getElementById('mode-summary');const detail=document.getElementById('detail-copy');const controls=document.querySelectorAll('[data-mode]');controls.forEach((button)=>button.addEventListener('click',()=>{controls.forEach((control)=>control.setAttribute('aria-selected', String(control===button)));if(button.dataset.mode==='quantum'){summary.textContent='Quantum states can spread amplitude across multiple outcomes before measurement.';detail.textContent='Quantum state selected. Inspect how probabilities differ from a classical bit.';}else{summary.textContent='Classical bits stay in one definite state at a time.';detail.textContent='Classical mode selected. A bit resolves to one state immediately.';}}));</script>"
                    }]
                }),
                "repair" => serde_json::json!({
                    "summary": "Repair completed with a stronger quantum comparison.",
                    "notes": ["Added the missing qubit-focused comparison module."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<section data-verified-repair=\"quantum-state-compare\"><article><h2>Measurement comparison</h2><p>Quantum Qubit views show a weighted set of possible outcomes before measurement collapses the state.</p><div class=\"repair-switch\"><button type=\"button\">Classical Bit</button><button type=\"button\">Quantum Qubit</button></div><svg viewBox=\"0 0 320 160\" role=\"img\" aria-label=\"Classical versus quantum measurement distribution\"><rect x=\"34\" y=\"42\" width=\"54\" height=\"88\"></rect><rect x=\"132\" y=\"64\" width=\"54\" height=\"66\"></rect><rect x=\"230\" y=\"28\" width=\"54\" height=\"102\"></rect><text x=\"28\" y=\"148\">0</text><text x=\"126\" y=\"148\">0 / 1</text><text x=\"224\" y=\"148\">1</text></svg></article></section>"
                    }]
                }),
                "integrator" => serde_json::json!({
                    "summary": "No extra integrator pass was required.",
                    "notes": ["The local HTML swarm keeps the integrator in reserve."],
                    "operations": []
                }),
                "judge" => {
                    if prompt.contains("Repair completed with a stronger quantum comparison.")
                        || prompt.contains("qubit-focused comparison module")
                        || (prompt.contains("Measurement comparison")
                            && prompt.contains("Quantum Qubit"))
                    {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 5,
                            "conceptCoverage": 5,
                            "interactionRelevance": 5,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 5,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Acceptance cleared the repaired quantum explainer."
                        })
                    } else {
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
                            "strongestContradiction": "The explainer still needs a visible qubit measurement comparison.",
                            "rationale": "Acceptance wants a stronger qubit-focused comparison before primary view."
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

    #[derive(Default)]
    struct QuantumSwarmRegressionRenderEvaluator;

    #[async_trait]
    impl StudioArtifactRenderEvaluator for QuantumSwarmRegressionRenderEvaluator {
        async fn evaluate_candidate_render(
            &self,
            _request: &StudioOutcomeArtifactRequest,
            _brief: &StudioArtifactBrief,
            _blueprint: Option<&StudioArtifactBlueprint>,
            _artifact_ir: Option<&StudioArtifactIR>,
            _edit_intent: Option<&StudioArtifactEditIntent>,
            candidate: &StudioGeneratedArtifactPayload,
        ) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
            let repaired = candidate
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .map(|file| {
                    file.body
                        .contains("data-verified-repair=\"quantum-state-compare\"")
                })
                .unwrap_or(false);

            Ok(Some(studio_test_render_evaluation(
                if repaired { 24 } else { 17 },
                true,
                if repaired {
                    Vec::new()
                } else {
                    vec![StudioArtifactRenderFinding {
                        code: "comparison_depth_thin".to_string(),
                        severity: StudioArtifactRenderFindingSeverity::Warning,
                        summary: "The first render still needs a stronger qubit comparison module."
                            .to_string(),
                    }]
                },
                vec![
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Desktop,
                        if repaired { 46 } else { 28 },
                        if repaired { 540 } else { 320 },
                        if repaired { 7 } else { 4 },
                    ),
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Mobile,
                        if repaired { 42 } else { 24 },
                        if repaired { 482 } else { 274 },
                        if repaired { 7 } else { 4 },
                    ),
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Interaction,
                        if repaired { 45 } else { 22 },
                        if repaired { 498 } else { 248 },
                        if repaired { 8 } else { 4 },
                    ),
                ],
            )))
        }
    }

    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(QuantumSwarmRegressionRuntime {
                provenance: StudioRuntimeProvenance {
                    kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                },
                role: "production",
                calls: calls.clone(),
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(QuantumSwarmRegressionRuntime {
                provenance: StudioRuntimeProvenance {
                    kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some(
                        "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance"
                            .to_string(),
                    ),
                },
                role: "acceptance",
                calls: calls.clone(),
            });
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let runtime_plan = resolve_studio_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::FullyLocal,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            "Quantum computers interactive explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            None,
        )
        .await;
        let evaluator = QuantumSwarmRegressionRenderEvaluator;

        let bundle =
            generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                "Quantum computers interactive explainer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                None,
                &planning_context,
                StudioExecutionStrategy::AdaptiveWorkGraph,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("quantum swarm bundle should generate");

        assert!(bundle.candidate_summaries.is_empty());
        assert_eq!(
            bundle
                .swarm_plan
                .as_ref()
                .map(|plan| plan.execution_domain.as_str()),
            Some("studio_artifact")
        );
        assert_eq!(
            bundle
                .swarm_execution
                .as_ref()
                .map(|execution| execution.verification_status.as_str()),
            Some("pass")
        );
        assert_eq!(
            bundle
                .swarm_execution
                .as_ref()
                .map(|execution| execution.current_stage.as_str()),
            Some("ready")
        );
        assert_eq!(
            bundle.judge.classification,
            StudioArtifactJudgeClassification::Pass
        );
        assert!(bundle
            .swarm_worker_receipts
            .iter()
            .any(|receipt| receipt.role == StudioArtifactWorkerRole::Repair
                && receipt.status == StudioArtifactWorkItemStatus::Succeeded));
        assert!(bundle
            .swarm_plan
            .as_ref()
            .is_some_and(|plan| plan
                .work_items
                .iter()
                .any(|item| item.id == "repair-pass-1"
                    && item.spawned_from_id.as_deref() == Some("repair"))));
        assert!(bundle
            .swarm_change_receipts
            .iter()
            .any(|receipt| receipt.work_item_id == "repair-pass-1" && receipt.operation_count > 0));
        assert!(bundle
            .swarm_merge_receipts
            .iter()
            .any(|receipt| receipt.work_item_id == "repair-pass-1"));
        assert!(bundle
            .swarm_verification_receipts
            .iter()
            .any(|receipt| receipt.kind == "acceptance_judge"));
        assert!(bundle
            .execution_envelope
            .as_ref()
            .is_some_and(|envelope| envelope
                .graph_mutation_receipts
                .iter()
                .any(|receipt| receipt.mutation_kind == "subtask_spawned")));
        assert!(bundle
            .execution_envelope
            .as_ref()
            .is_some_and(|envelope| envelope
                .dispatch_batches
                .iter()
                .any(|batch| {
                    batch.status != "blocked"
                        && batch
                            .work_item_ids
                            .iter()
                            .filter(|id| id.starts_with("section-"))
                            .count()
                            >= 2
                })));
        assert!(bundle
            .render_evaluation
            .as_ref()
            .is_some_and(|evaluation| evaluation.captures.iter().any(|capture| {
                capture.viewport == StudioArtifactRenderCaptureViewport::Interaction
                    && capture.interactive_element_count >= 8
            })));
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html"
                && file.body.contains("data-verified-repair=\"quantum-state-compare\"")
                && file.body.contains("Quantum Qubit")
        }));

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|call| call == "production:brief"));
        assert!(recorded_calls.iter().any(|call| call == "production:skeleton"));
        assert!(recorded_calls.iter().any(|call| call == "production:style"));
        assert!(recorded_calls.iter().any(|call| call == "production:interaction"));
        assert!(recorded_calls.iter().any(|call| call == "production:repair"));
        assert!(!recorded_calls
            .iter()
            .any(|call| call.starts_with("acceptance:")));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":judge"))
                .count(),
            0
        );
    })
    .await;
}

#[tokio::test]
async fn local_html_swarm_strategy_breaks_complex_mission_control_query_into_iterative_waves() {
    #[derive(Clone)]
    struct ComplexMissionControlRuntime {
        provenance: StudioRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        section_regions: Vec<String>,
        repair_region: String,
    }

    fn section_region_from_prompt(prompt: &str, section_regions: &[String]) -> Option<String> {
        let candidate = [
            "\"targetRegion\":\"",
            "\"targetRegion\": \"",
            "targetRegion\":\"",
            "targetRegion\": \"",
        ]
        .into_iter()
        .find_map(|needle| {
            let start = prompt.find(needle)? + needle.len();
            let rest = &prompt[start..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        });

        candidate.filter(|region| section_regions.iter().any(|entry| entry == region))
    }

    #[async_trait]
    impl InferenceRuntime for ComplexMissionControlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief".to_string()
            } else if prompt.contains("typed swarm Skeleton worker") {
                "skeleton".to_string()
            } else if prompt.contains("typed swarm SectionContent worker") {
                let region = section_region_from_prompt(&prompt, &self.section_regions)
                    .unwrap_or_else(|| "section:unknown".to_string());
                format!("section:{region}")
            } else if prompt.contains("typed swarm StyleSystem worker") {
                "style".to_string()
            } else if prompt.contains("typed swarm Interaction worker") {
                "interaction".to_string()
            } else if prompt.contains("typed swarm Repair worker") {
                "repair".to_string()
            } else if prompt.contains("typed swarm Integrator worker") {
                "integrator".to_string()
            } else if prompt.contains("typed artifact judge") {
                "judge".to_string()
            } else {
                "unknown".to_string()
            };

            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("{}:{stage}", self.role));

            let response = if stage == "brief" {
                serde_json::to_value(sample_complex_mission_control_brief()).expect("complex brief")
            } else if stage == "skeleton" {
                serde_json::json!({
                    "summary": "Mission control workbook shell",
                    "notes": ["Created the canonical mission-control HTML shell."],
                    "operations": [{
                        "kind": "create_file",
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><meta charset=\"utf-8\"><title>Post-quantum migration mission control</title></head><body><main><header><h1>Post-quantum migration mission control</h1><p>Track rollout phases, inspect risk posture, compare owner handoffs, and test cutover readiness from one control room artifact.</p><div class=\"mode-switch\"><button type=\"button\" data-panel=\"phases\" aria-selected=\"true\">Phases</button><button type=\"button\" data-panel=\"risk\" aria-selected=\"false\">Risk</button><button type=\"button\" data-panel=\"handoffs\" aria-selected=\"false\">Handoffs</button></div></header><aside class=\"detail-rail\"><h2>Operator detail</h2><p id=\"detail-copy\">Phases panel is selected with fleet rollout evidence visible on first paint.</p></aside></main></body></html>"
                    }]
                })
            } else if let Some(region) = stage.strip_prefix("section:") {
                let section_markup = if region == self.section_regions[0] {
                    "<section data-panel=\"phases\" class=\"mission-panel\"><article><h2>Fleet rollout phases</h2><p>Wave 1 upgrades signing infrastructure, Wave 2 rotates edge services, and Wave 3 retires the legacy fallback lane after verification clears.</p><ol><li><strong>Pilot:</strong> five canary regions with manual approval.</li><li><strong>Expansion:</strong> regional fleet rollout with live latency watch.</li><li><strong>Retire:</strong> remove the legacy signing path after rollback confidence stays green.</li></ol><div class=\"evidence-strip\"><button type=\"button\" data-detail=\"Pilot phase focuses on low-blast-radius rollout across five regions.\">Pilot focus</button><button type=\"button\" data-detail=\"Expansion phase compares readiness, latency, and rollback tolerance.\">Expansion focus</button></div></article></section>"
                } else if region == self.section_regions[1] {
                    "<section data-panel=\"risk\" class=\"mission-panel\"><article><h2>Cryptography risk drilldown</h2><p>Inspect signing libraries, vendor readiness, and support exposure before each cutover decision.</p><table><tr><th>Surface</th><th>Status</th><th>Risk</th></tr><tr><td>Identity signing</td><td>Library patched</td><td>Low</td></tr><tr><td>Mobile SDK</td><td>Vendor awaiting rollout</td><td>Medium</td></tr><tr><td>Support scripts</td><td>Legacy fallback active</td><td>High</td></tr></table><div class=\"risk-toggles\"><button type=\"button\" data-risk=\"identity\">Identity</button><button type=\"button\" data-risk=\"mobile\">Mobile</button><button type=\"button\" data-risk=\"support\">Support</button></div></article></section>"
                } else {
                    "<section data-panel=\"handoffs\" class=\"mission-panel\"><article><h2>Owner handoffs and cutover simulation</h2><p>Compare who owns preflight, cutover, and rollback, then simulate whether the current readiness state permits launch.</p><div class=\"ownership-grid\"><div><h3>Infrastructure</h3><p>Owns certificate rotation, cutover execution, and rollback thresholds.</p></div><div><h3>Product</h3><p>Owns rollout messaging, customer sequencing, and regional launch approval.</p></div><div><h3>Support</h3><p>Owns incident intake, escalation templates, and customer-safe fallback guidance.</p></div></div><div class=\"simulator\"><button type=\"button\" data-sim=\"hold\">Hold rollout</button><button type=\"button\" data-sim=\"launch\">Launch rollout</button></div><p id=\"sim-status\">Simulation idle. Review ownership signals before launch.</p></article></section>"
                };

                serde_json::json!({
                    "summary": format!("Filled {region} with request-grounded mission-control content."),
                    "notes": [format!("Patched scoped region {region}.")],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": region,
                        "body": section_markup
                    }]
                })
            } else if stage == "style" {
                serde_json::json!({
                    "summary": "Applied the mission-control style system.",
                    "notes": ["Added the shared slate hierarchy and compact chrome."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": "style-system",
                        "body": "<style>:root{color-scheme:dark;--bg:#11161c;--panel:#1a212b;--panel-alt:#151b24;--border:#2c3948;--text:#e8eef6;--muted:#94a3b8;--accent:#7dd3fc;--warn:#f59e0b;}*{box-sizing:border-box;}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);}main{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:18px;padding:22px;max-width:1200px;margin:0 auto;}header,section,aside{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:18px;}header{grid-column:1 / span 2;display:grid;gap:14px;}h1,h2,h3,p,ol{margin:0;}p,li,td,th{color:var(--muted);line-height:1.5;}table{width:100%;border-collapse:collapse;margin-top:12px;}th,td{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;}button{border:1px solid #31506d;background:#182635;color:var(--text);border-radius:999px;padding:9px 13px;font:inherit;cursor:pointer;}button[aria-selected=\"true\"],button[data-active=\"true\"]{border-color:var(--accent);box-shadow:0 0 0 1px rgba(125,211,252,.34) inset;}header .mode-switch,.evidence-strip,.risk-toggles,.simulator{display:flex;gap:10px;flex-wrap:wrap;}.mission-panel{display:grid;gap:14px;}.ownership-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;}.ownership-grid>div{background:var(--panel-alt);border:1px solid var(--border);border-radius:14px;padding:12px;}.detail-rail{position:sticky;top:18px;height:max-content;}#sim-status{padding:12px 14px;border-radius:14px;background:rgba(125,211,252,.08);border:1px solid rgba(125,211,252,.22);color:var(--text);}strong{color:var(--text);}</style>"
                    }]
                })
            } else if stage == "interaction" {
                serde_json::json!({
                    "summary": "Wired the mission-control interaction grammar.",
                    "notes": ["Bound the control bar, detail rail, risk drilldown, and cutover simulator."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": "interaction",
                        "body": "<script>const detail=document.getElementById('detail-copy');const panels=[...document.querySelectorAll('.mission-panel')];const tabButtons=[...document.querySelectorAll('button[data-panel]')];tabButtons.forEach((button)=>button.addEventListener('click',()=>{const target=button.dataset.panel;tabButtons.forEach((control)=>control.setAttribute('aria-selected',String(control===button)));panels.forEach((panel)=>panel.dataset.active=String(panel.dataset.panel===target));detail.textContent=target==='phases'?'Phases panel selected. Inspect the rollout wave timing and the readiness evidence strip.':target==='risk'?'Risk panel selected. Compare surface readiness and vendor exposure before cutover.':'Handoffs panel selected. Compare owners and simulate whether launch can proceed.';}));document.querySelectorAll('[data-detail]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=button.dataset.detail;}));document.querySelectorAll('[data-risk]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-risk]').forEach((control)=>control.dataset.active=String(control===button));detail.textContent=button.dataset.risk==='identity'?'Identity path is patched and ready for early rollout.':button.dataset.risk==='mobile'?'Mobile path is blocked on vendor rollout timing.':'Support path still depends on the legacy fallback lane.';}));const simStatus=document.getElementById('sim-status');document.querySelectorAll('[data-sim]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-sim]').forEach((control)=>control.dataset.active=String(control===button));if(button.dataset.sim==='launch'){simStatus.textContent='Launch simulation: proceed only if vendor readiness and rollback staffing both stay green.';detail.textContent='Launch simulation selected. Confirm support staffing and vendor readiness before go-live.';}else{simStatus.textContent='Hold simulation: keep the rollout paused until support scripts leave the legacy lane.';detail.textContent='Hold simulation selected. Remediate the support fallback dependency before launch.';}}));</script>"
                    }]
                })
            } else if stage == "repair" {
                serde_json::json!({
                    "summary": "Added the missing rollback playbook detail.",
                    "notes": ["Repair added the cited fallback playbook depth."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": self.repair_region,
                        "body": "<section data-panel=\"handoffs\" class=\"mission-panel\" data-repaired=\"rollback-playbook\"><article><h2>Owner handoffs and cutover simulation</h2><p>Compare who owns preflight, cutover, and rollback, then simulate whether the current readiness state permits launch.</p><div class=\"ownership-grid\"><div><h3>Infrastructure</h3><p>Owns certificate rotation, cutover execution, and rollback thresholds.</p></div><div><h3>Product</h3><p>Owns rollout messaging, customer sequencing, and regional launch approval.</p></div><div><h3>Support</h3><p>Owns incident intake, escalation templates, and customer-safe fallback guidance.</p></div></div><section class=\"rollback-playbook\"><h3>Rollback playbook</h3><p>If vendor readiness drops or support fallback remains red, freeze launch, return traffic to the legacy signer, and page the owning leads in the order shown above.</p></section><div class=\"simulator\"><button type=\"button\" data-sim=\"hold\">Hold rollout</button><button type=\"button\" data-sim=\"launch\">Launch rollout</button></div><p id=\"sim-status\">Simulation idle. Review ownership signals before launch.</p></article></section>"
                    }]
                })
            } else if stage == "integrator" {
                serde_json::json!({
                    "summary": "Integrator stayed in reserve.",
                    "notes": ["Local HTML path keeps the integrator as a reserve seam."],
                    "operations": []
                })
            } else if stage == "judge" {
                let repaired_already = self
                    .calls
                    .lock()
                    .expect("calls lock")
                    .iter()
                    .any(|call| call == "production:repair")
                    || prompt.contains("data-repaired=\"rollback-playbook\"")
                    || prompt.contains("Rollback playbook");
                if repaired_already {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 5,
                        "conceptCoverage": 5,
                        "interactionRelevance": 5,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 5,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "The repaired mission-control artifact now covers rollout, risk, ownership, and rollback decisions with visible interactions."
                    })
                } else {
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
                        "strongestContradiction": "The artifact still needs an explicit rollback playbook inside the owner handoff surface.",
                        "rationale": "The control room is strong, but the launch decision loop is incomplete without a visible rollback playbook."
                    })
                }
            } else {
                return Err(VmError::HostError("unexpected Studio prompt".to_string()));
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

    #[derive(Default)]
    struct ComplexMissionControlRenderEvaluator;

    #[async_trait]
    impl StudioArtifactRenderEvaluator for ComplexMissionControlRenderEvaluator {
        async fn evaluate_candidate_render(
            &self,
            _request: &StudioOutcomeArtifactRequest,
            _brief: &StudioArtifactBrief,
            _blueprint: Option<&StudioArtifactBlueprint>,
            _artifact_ir: Option<&StudioArtifactIR>,
            _edit_intent: Option<&StudioArtifactEditIntent>,
            candidate: &StudioGeneratedArtifactPayload,
        ) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
            let repaired = candidate
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .map(|file| file.body.contains("data-repaired=\"rollback-playbook\""))
                .unwrap_or(false);

            Ok(Some(studio_test_render_evaluation(
                if repaired { 32 } else { 24 },
                true,
                if repaired {
                    Vec::new()
                } else {
                    vec![StudioArtifactRenderFinding {
                        code: "rollback_playbook_missing".to_string(),
                        severity: StudioArtifactRenderFindingSeverity::Warning,
                        summary: "The first render still needs an explicit rollback playbook in the handoff surface.".to_string(),
                    }]
                },
                vec![
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Desktop,
                        if repaired { 58 } else { 42 },
                        if repaired { 910 } else { 680 },
                        if repaired { 12 } else { 8 },
                    ),
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Mobile,
                        if repaired { 51 } else { 36 },
                        if repaired { 840 } else { 590 },
                        if repaired { 11 } else { 7 },
                    ),
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Interaction,
                        if repaired { 56 } else { 40 },
                        if repaired { 876 } else { 622 },
                        if repaired { 13 } else { 8 },
                    ),
                ],
            )))
        }
    }

    with_modal_first_html_env_async(|| async {
        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let brief = sample_complex_mission_control_brief();
        let blueprint = derive_studio_artifact_blueprint(&request, &brief);
        let swarm_plan = super::generation::build_studio_artifact_swarm_plan(
            &request,
            Some(&blueprint),
            &brief,
            StudioExecutionStrategy::AdaptiveWorkGraph,
        );
        let section_regions = swarm_plan
            .work_items
            .iter()
            .filter(|item| item.role == StudioArtifactWorkerRole::SectionContent)
            .flat_map(|item| item.write_regions.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            section_regions.len(),
            3,
            "complex HTML briefs should coalesce into three bounded section workers"
        );
        let repair_region = section_regions
            .last()
            .cloned()
            .expect("repair region should exist");

        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(ComplexMissionControlRuntime {
                provenance: StudioRuntimeProvenance {
                    kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                },
                role: "production",
                calls: calls.clone(),
                section_regions: section_regions.clone(),
                repair_region: repair_region.clone(),
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(ComplexMissionControlRuntime {
                provenance: StudioRuntimeProvenance {
                    kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some(
                        "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance"
                            .to_string(),
                    ),
                },
                role: "acceptance",
                calls: calls.clone(),
                section_regions: section_regions.clone(),
                repair_region: repair_region.clone(),
            });
        let runtime_plan = resolve_studio_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::FullyLocal,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            "Post-quantum migration mission control",
            "Create an interactive HTML mission control artifact for a post-quantum migration program that lets operators compare rollout phases, inspect cryptography risk, simulate cutover decisions, and review owner handoffs with a visible rollback playbook.",
            &request,
            None,
        )
        .await;
        let evaluator = ComplexMissionControlRenderEvaluator;

        let bundle =
            generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                "Post-quantum migration mission control",
                "Create an interactive HTML mission control artifact for a post-quantum migration program that lets operators compare rollout phases, inspect cryptography risk, simulate cutover decisions, and review owner handoffs with a visible rollback playbook.",
                &request,
                None,
                &planning_context,
                StudioExecutionStrategy::AdaptiveWorkGraph,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("complex mission-control swarm bundle should generate");

        assert!(bundle.candidate_summaries.is_empty());
        assert_eq!(
            bundle.judge.classification,
            StudioArtifactJudgeClassification::Pass
        );

        let envelope = bundle
            .execution_envelope
            .as_ref()
            .expect("execution envelope");
        assert_eq!(
            envelope.execution_summary.as_ref().map(|summary| summary.current_stage.as_str()),
            Some("ready")
        );
        assert_eq!(
            envelope.execution_summary.as_ref().map(|summary| summary.verification_status.as_str()),
            Some("pass")
        );
        assert!(
            envelope.dispatch_batches.len() >= 5,
            "complex local HTML should require several iterative dispatch waves"
        );
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().filter(|id| id.starts_with("section-")).count() == 2
                && !batch.deferred_work_item_ids.is_empty()
        }));
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().filter(|id| id.starts_with("section-")).count() == 1
                && batch.deferred_work_item_ids.is_empty()
        }));
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().any(|id| id == "style-system")
                && batch.work_item_ids.iter().any(|id| id == "interaction")
        }));
        assert!(envelope
            .graph_mutation_receipts
            .iter()
            .any(|receipt| receipt.mutation_kind == "subtask_spawned"));
        assert!(envelope
            .repair_receipts
            .iter()
            .any(|receipt| receipt.status == "pass"
                && receipt
                    .work_item_ids
                    .iter()
                    .any(|id| id == "repair-pass-1")));
        assert!(
            envelope
                .budget_summary
                .as_ref()
                .and_then(|summary| summary.token_budget)
                .unwrap_or_default()
                > 0
        );
        assert!(
            envelope
                .budget_summary
                .as_ref()
                .and_then(|summary| summary.dispatched_worker_count)
                .unwrap_or_default()
                >= 7
        );

        let section_receipts = bundle
            .swarm_worker_receipts
            .iter()
            .filter(|receipt| receipt.role == StudioArtifactWorkerRole::SectionContent)
            .collect::<Vec<_>>();
        assert_eq!(section_receipts.len(), 3);
        assert!(section_receipts.iter().all(|receipt| {
            receipt.status == StudioArtifactWorkItemStatus::Succeeded
                && receipt.write_regions.len() == 1
        }));
        assert!(bundle
            .swarm_change_receipts
            .iter()
            .filter(|receipt| receipt.work_item_id.starts_with("section-"))
            .all(|receipt| receipt.operation_count == 1 && receipt.touched_regions.len() == 1));
        assert!(bundle
            .swarm_verification_receipts
            .iter()
            .any(|receipt| receipt.kind == "acceptance_judge"));
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html"
                && file.body.contains("Fleet rollout phases")
                && file.body.contains("Cryptography risk drilldown")
                && file.body.contains("Owner handoffs and cutover simulation")
                && file.body.contains("Rollback playbook")
                && file.body.contains("data-repaired=\"rollback-playbook\"")
        }));
        assert!(bundle
            .render_evaluation
            .as_ref()
            .is_some_and(|evaluation| evaluation.captures.iter().any(|capture| {
                capture.viewport == StudioArtifactRenderCaptureViewport::Interaction
                    && capture.interactive_element_count >= 13
            })));

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|call| call == "production:brief"));
        assert!(recorded_calls.iter().any(|call| call == "production:skeleton"));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.starts_with("production:section:section:"))
                .count(),
            3
        );
        assert!(recorded_calls.iter().any(|call| call == "production:style"));
        assert!(recorded_calls.iter().any(|call| call == "production:interaction"));
        assert!(recorded_calls.iter().any(|call| call == "production:repair"));
        assert!(!recorded_calls
            .iter()
            .any(|call| call.starts_with("acceptance:")));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":judge"))
                .count(),
            0
        );
    })
    .await;
}

#[test]
fn html_swarm_semantic_conflict_rejects_cross_boundary_patch() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let mut payload = StudioGeneratedArtifactPayload {
        summary: "Seed".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><!-- STUDIO_REGION_START:section:intro --><section>Old body</section><!-- STUDIO_REGION_END:section:intro --></body></html>".to_string(),
        }],
    };
    let work_item = StudioArtifactWorkItem {
        id: "section-1".to_string(),
        title: "Section 1".to_string(),
        role: StudioArtifactWorkerRole::SectionContent,
        summary: "Own the intro section.".to_string(),
        spawned_from_id: None,
        read_paths: vec!["index.html".to_string()],
        write_paths: vec!["index.html".to_string()],
        write_regions: vec!["section:intro".to_string()],
        lease_requirements: vec![
            shared_read_lease_for_path("index.html"),
            exclusive_write_lease_for_region("section:intro"),
        ],
        acceptance_criteria: vec!["Stay inside the intro region.".to_string()],
        dependency_ids: vec!["skeleton".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(SwarmVerificationPolicy::Normal),
        retry_budget: Some(0),
        status: StudioArtifactWorkItemStatus::Pending,
    };
    let envelope = StudioArtifactPatchEnvelope {
        summary: Some("Bad section patch".to_string()),
        notes: Vec::new(),
        operations: vec![StudioArtifactPatchOperation {
            kind: StudioArtifactPatchOperationKind::ReplaceFile,
            path: "index.html".to_string(),
            region_id: None,
            mime: None,
            role: None,
            renderable: None,
            downloadable: None,
            encoding: None,
            body: Some(
                "<script>document.body.dataset.bad='true';</script><section>Wrong boundary</section>"
                    .to_string(),
            ),
        }],
    };

    let (patch_receipt, merge_receipt) =
        apply_studio_swarm_patch_envelope(&request, &mut payload, &work_item, &envelope)
            .expect("semantic conflict should surface as a bounded rejection");

    assert_eq!(patch_receipt.status, StudioArtifactWorkItemStatus::Rejected);
    assert_eq!(merge_receipt.status, StudioArtifactWorkItemStatus::Rejected);
    assert!(patch_receipt
        .failure
        .as_deref()
        .is_some_and(|failure| failure.contains("semantic ownership boundary")));
    assert!(merge_receipt
        .rejected_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("semantic ownership boundary")));
    assert!(payload.files[0].body.contains("Old body"));
}

#[test]
fn validate_swarm_generated_artifact_payload_repairs_default_primary_renderable_flag() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = StudioGeneratedArtifactPayload {
        summary: "Interactive HTML artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: false,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><body><main><header><h1>Renderable shell</h1><div class=\"controls\"><button type=\"button\" data-view=\"risk\" aria-pressed=\"true\">Risk</button><button type=\"button\" data-view=\"rollback\" aria-pressed=\"false\">Rollback</button></div></header><section id=\"risk-panel\"><h2>Risk detail</h2><p id=\"detail-copy\">Inspect cryptography risk before cutover.</p></section><section id=\"rollback-panel\" hidden><h2>Rollback</h2><p>Rollback playbook is ready if launch conditions fail.</p></section><section><h2>Operator summary</h2><p>Compare phases, inspect risk, and confirm rollback readiness.</p></section></main><script>document.querySelectorAll('[data-view]').forEach((button)=>button.addEventListener('click',()=>{const isRisk=button.dataset.view==='risk';document.getElementById('risk-panel').hidden=!isRisk;document.getElementById('rollback-panel').hidden=isRisk;document.getElementById('detail-copy').textContent=isRisk?'Inspect cryptography risk before cutover.':'Rollback playbook is visible.';document.querySelectorAll('[data-view]').forEach((candidate)=>candidate.setAttribute('aria-pressed', String(candidate===button)));}));</script></body></html>".to_string(),
        }],
    };

    let repaired = validate_swarm_generated_artifact_payload(&payload, &request)
        .expect("default HTML primary file should be normalized before validation");

    let primary = repaired
        .files
        .iter()
        .find(|file| file.path == "index.html")
        .expect("normalized primary file");
    assert_eq!(primary.role, StudioArtifactFileRole::Primary);
    assert!(primary.renderable);
    assert!(!primary.downloadable);
    assert_eq!(
        primary.encoding,
        Some(StudioGeneratedArtifactEncoding::Utf8)
    );
}
