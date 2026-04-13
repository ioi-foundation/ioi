use super::generation::{
    apply_studio_swarm_patch_envelope,
    build_studio_artifact_candidate_refinement_prompt_for_runtime,
    build_studio_artifact_direct_author_prompt_for_runtime,
    build_studio_artifact_materialization_prompt_for_runtime,
    build_studio_artifact_materialization_repair_prompt_for_runtime,
    evaluate_candidate_render_with_fallback, refine_studio_artifact_candidate_with_runtime,
    render_eval_timeout_for_runtime, render_evaluation_required, requested_follow_up_pass,
    validate_swarm_generated_artifact_payload, StudioArtifactPatchEnvelope,
    StudioArtifactPatchOperation, StudioArtifactPatchOperationKind,
};
use super::judging::build_studio_artifact_judge_prompt_for_runtime;
use super::judging::candidate_generation_config;
use super::planning::{
    brief_planner_max_tokens_for_runtime, build_studio_artifact_brief_field_repair_prompt,
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
use std::sync::{Arc, Mutex, OnceLock};
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
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock");
    let previous_local_gpu = std::env::var("AUTOPILOT_LOCAL_GPU_DEV").ok();
    let previous_modal_first = std::env::var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML").ok();

    unsafe {
        std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", "1");
        std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", "1");
    }

    let result = f();

    unsafe {
        match previous_local_gpu {
            Some(value) => std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", value),
            None => std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV"),
        }
        match previous_modal_first {
            Some(value) => std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", value),
            None => std::env::remove_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML"),
        }
    }

    drop(guard);
    result
}

async fn with_modal_first_html_env_async<T, F>(f: impl FnOnce() -> F) -> T
where
    F: Future<Output = T>,
{
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock");
    let previous_local_gpu = std::env::var("AUTOPILOT_LOCAL_GPU_DEV").ok();
    let previous_modal_first = std::env::var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML").ok();

    unsafe {
        std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", "1");
        std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", "1");
    }

    let result = f().await;

    unsafe {
        match previous_local_gpu {
            Some(value) => std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", value),
            None => std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV"),
        }
        match previous_modal_first {
            Some(value) => std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", value),
            None => std::env::remove_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML"),
        }
    }

    drop(guard);
    result
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

fn prepared_context_for_request(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> StudioArtifactPlanningContext {
    derive_studio_artifact_prepared_context(request, brief, None, None, Vec::new(), Vec::new())
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
async fn direct_author_continues_incomplete_raw_document_before_repairing() {
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
    }));
}

#[tokio::test]
async fn direct_author_successful_but_invalid_stream_terminalizes_preview_before_failure() {
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
    let latest_preview = preview_log
        .iter()
        .rev()
        .find(|preview| preview.id == "candidate-1-live-output")
        .expect("terminal preview should be recorded");
    assert_eq!(
        latest_preview.kind,
        crate::execution::ExecutionLivePreviewKind::TokenStream
    );
    assert_eq!(latest_preview.status, "completed");
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
async fn direct_author_runs_acceptance_before_using_draft_pending_state() {
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
        assert!(recorded_calls.iter().any(|entry| entry == "acceptance:judge"));
        assert!(bundle
            .judge
            .rationale
            .starts_with("acceptance runtime evaluated the direct-authored draft"));
        assert_ne!(
            bundle.judge.strongest_contradiction.as_deref(),
            Some("Acceptance judging is still pending for this draft.")
        );
        assert_ne!(
            bundle.judge.recommended_next_pass.as_deref(),
            Some("acceptance_retry")
        );
        assert_eq!(
            bundle.acceptance_provenance.model.as_deref(),
            Some("fixture-qwen-8b")
        );
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
fn direct_author_acceptance_timeout_surfaces_draft_instead_of_failing() {
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
            if !prompt.contains("typed artifact judge") {
                return Err(VmError::HostError(format!(
                    "unexpected acceptance prompt in direct-author timeout test: {prompt}"
                )));
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
            Ok(serde_json::json!({
                "classification": "pass",
                "requestFaithfulness": 5,
                "conceptCoverage": 5,
                "interactionRelevance": 4,
                "layoutCoherence": 5,
                "visualHierarchy": 5,
                "completeness": 5,
                "genericShellDetected": false,
                "trivialShellDetected": false,
                "deservesPrimaryArtifactView": true,
                "patchedExistingArtifact": null,
                "continuityRevisionUx": null,
                "issueClasses": [],
                "repairHints": [],
                "strengths": ["Would have passed if allowed to finish"],
                "blockedReasons": [],
                "fileFindings": [],
                "aestheticVerdict": "Strong markdown artifact.",
                "interactionVerdict": "Good fit for direct authoring.",
                "truthfulnessWarnings": [],
                "recommendedNextPass": "accept",
                "strongestContradiction": null,
                "rationale": "The acceptance judge would have cleared this artifact."
            })
            .to_string()
            .into_bytes())
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

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock");
    let previous_timeout = std::env::var("AUTOPILOT_STUDIO_ACCEPTANCE_TIMEOUT_MS").ok();
    unsafe {
        std::env::set_var("AUTOPILOT_STUDIO_ACCEPTANCE_TIMEOUT_MS", "10");
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
        .expect("direct author timeout should return a draft bundle");

    unsafe {
        match previous_timeout {
            Some(value) => std::env::set_var("AUTOPILOT_STUDIO_ACCEPTANCE_TIMEOUT_MS", value),
            None => std::env::remove_var("AUTOPILOT_STUDIO_ACCEPTANCE_TIMEOUT_MS"),
        }
    }

    assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Draft);
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Repairable
    );
    assert!(bundle
        .judge
        .strongest_contradiction
        .as_deref()
        .is_some_and(|value| value.contains("Acceptance judging timed out after 10ms.")));
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
fn local_html_materialization_prompt_is_compact_for_runtime() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "tech enthusiasts and industry professionals".to_string(),
        job_to_be_done: "explore and learn about new AI tools for editorial purposes".to_string(),
        subject_domain: "AI tools in content creation and management".to_string(),
        artifact_thesis: "Create a launch-ready editorial HTML artifact for AI tools.".to_string(),
        required_concepts: vec![
            "AI tool demonstrations".to_string(),
            "editorial workflow optimization".to_string(),
            "content generation examples".to_string(),
            "launch positioning".to_string(),
        ],
        required_interactions: vec![
            "toggle between tool categories".to_string(),
            "click to inspect editorial use cases".to_string(),
            "hover to compare launch signals".to_string(),
        ],
        visual_tone: vec!["modern".to_string(), "editorial".to_string()],
        factual_anchors: vec![
            "recent studies on AI-assisted content workflows".to_string(),
            "launch positioning cues".to_string(),
        ],
        style_directives: vec![
            "clear hierarchy".to_string(),
            "bold editorial framing".to_string(),
        ],
        reference_hints: vec!["https://example.com/editorial-ai".to_string()],
    };

    let remote_prompt = build_studio_artifact_materialization_prompt(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        42,
    )
    .expect("remote prompt");
    let local_prompt = build_studio_artifact_materialization_prompt_for_runtime(
        "AI tools editorial launch page",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
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
    .expect("local prompt");

    let remote_prompt_bytes = serde_json::to_vec(&remote_prompt).expect("remote prompt bytes");
    let local_prompt_bytes = serde_json::to_vec(&local_prompt).expect("local prompt bytes");
    let local_prompt_text = decode_studio_test_prompt(&local_prompt_bytes);

    assert!(local_prompt_bytes.len() < remote_prompt_bytes.len());
    assert!(local_prompt_text.contains("Artifact request focus JSON"));
    assert!(local_prompt_text.contains("Artifact brief focus JSON"));
    assert!(local_prompt_text.contains("Scaffold execution digest"));
    assert!(local_prompt_text.contains("Renderer-native authoring guidance"));
    assert!(local_prompt_text.contains("keyboard-focusable"));
    assert!(local_prompt_text.contains("mapped-panel scaffold"));
    assert!(local_prompt_text.contains("querySelectorAll('[data-view-panel]')"));
    assert!(
        local_prompt_text.contains("do not point every control only to the shared detail region")
    );
    assert!(local_prompt_text
        .contains("populate its default state directly in the HTML before any script runs"));
    assert!(!local_prompt_text.contains("Artifact blueprint JSON"));
    assert!(!local_prompt_text.contains("Artifact IR JSON"));
    assert!(!local_prompt_text.contains("Selected skill guidance JSON"));
    assert!(!local_prompt_text.contains("Retrieved exemplar JSON"));
    assert!(!local_prompt_text.contains("Studio HTML scaffold contract JSON"));
    assert!(!local_prompt_text.contains("A valid two-view first paint can pair"));
    assert!(!local_prompt_text.contains("Use pre-rendered mapped panels such as"));
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
    assert!(materializer_text
        .contains("must not emit the literal words placeholder, placeholders, TODO, or TBD"));
    assert!(materializer_text.contains("candidate seed to vary composition"));
    assert!(materializer_text.contains("abstract geometry alone does not count"));
    assert!(materializer_text.contains("shared detail, comparison, or explanation region"));
    assert!(materializer_text
        .contains("must not include HTML comments, placeholder comments, TODO markers"));
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
    let judge_prompt_bytes = serde_json::to_vec(&judge_prompt).expect("judge prompt bytes");
    let judge_text = decode_studio_test_prompt(&judge_prompt_bytes);
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
    assert!(materializer_text.contains("Studio promoted design skill spine JSON"));
    assert!(materializer_text.contains("Studio HTML scaffold contract JSON"));
    assert!(materializer_text.contains("Studio HTML component pack contracts JSON"));
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
    assert!(refinement_materializer_text.contains("Studio promoted design skill spine JSON"));
    assert!(refinement_materializer_text.contains("Studio HTML scaffold contract JSON"));
    assert!(refinement_materializer_text.contains("Studio HTML component pack contracts JSON"));
    assert!(refinement_materializer_text.contains("Refinement output contract"));
    assert!(refinement_materializer_text.contains(
        "do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object"
    ));

    let mut render_evaluation = studio_test_render_evaluation(
        16,
        true,
        Vec::new(),
        vec![studio_test_render_capture(
            StudioArtifactRenderCaptureViewport::Desktop,
            56,
            520,
            4,
        )],
    );
    render_evaluation.acceptance_obligations = vec![StudioArtifactAcceptanceObligation {
        obligation_id: "controls_discovered".to_string(),
        family: "controls_discovered".to_string(),
        required: true,
        status: StudioArtifactAcceptanceObligationStatus::Passed,
        summary: "Actionable controls were discovered on first paint.".to_string(),
        detail: None,
        witness_ids: vec!["witness-1".to_string()],
    }];
    render_evaluation.execution_witnesses = vec![StudioArtifactExecutionWitness {
        witness_id: "witness-1".to_string(),
        obligation_id: Some("interaction_witnessed".to_string()),
        action_kind: "click".to_string(),
        status: StudioArtifactExecutionWitnessStatus::Failed,
        summary: "Clicking the chart toggles did not update the visible evidence panel."
            .to_string(),
        detail: Some(
            "The mapped evidence surface stayed visually unchanged after the attempted toggle."
                .to_string(),
        ),
        selector: Some("button[data-view=\"comparison\"]".to_string()),
        console_errors: Vec::new(),
        state_changed: false,
    }];
    render_evaluation.summary =
        "One required interaction still fails to produce a visible state change.".to_string();

    let refinement_prompt = build_studio_artifact_candidate_refinement_prompt(
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request,
        &brief,
        None,
        None,
        &candidate,
        Some(&render_evaluation),
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
    assert!(refinement_text.contains("Studio promoted design skill spine JSON"));
    assert!(refinement_text.contains("Studio HTML scaffold contract JSON"));
    assert!(refinement_text.contains("Studio HTML component pack contracts JSON"));
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
    assert!(refinement_text.contains("Render evaluation JSON"));
    assert!(refinement_text.contains("controls_discovered"));
    assert!(refinement_text.contains("did not update the visible evidence panel"));
    assert!(refinement_text.contains("Refinement output contract"));
    assert!(refinement_text.contains(
        "do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object"
    ));

    let local_refinement_prompt = build_studio_artifact_candidate_refinement_prompt_for_runtime(
        "Dog shampoo rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
        &request,
        &brief,
        None,
        None,
        &[],
        &[],
        None,
        None,
        &candidate,
        Some(&render_evaluation),
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
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    )
    .expect("local refinement prompt");
    let local_refinement_bytes =
        serde_json::to_vec(&local_refinement_prompt).expect("local refinement bytes");
    let local_refinement_text = decode_studio_test_prompt(&local_refinement_bytes);

    let refinement_prompt_bytes = serde_json::to_vec(&refinement_prompt).expect("refinement bytes");
    assert!(local_refinement_bytes.len() < refinement_prompt_bytes.len());
    assert!(local_refinement_bytes.len() < 16_000);
    assert!(local_refinement_text.contains("Artifact request focus JSON"));
    assert!(local_refinement_text.contains("Artifact brief focus JSON"));
    assert!(local_refinement_text.contains("Current candidate focus JSON"));
    assert!(local_refinement_text.contains("Acceptance judgment focus JSON"));
    assert!(local_refinement_text.contains("Render evaluation focus JSON"));
    assert!(local_refinement_text.contains("Scaffold execution digest"));
    assert!(!local_refinement_text.contains("Artifact blueprint JSON"));
    assert!(!local_refinement_text.contains("Artifact IR JSON"));
    assert!(!local_refinement_text.contains("Selected skill guidance JSON"));
    assert!(!local_refinement_text.contains("Retrieved exemplar JSON"));
    assert!(!local_refinement_text.contains("Promoted design skill spine JSON"));
    assert!(!local_refinement_text.contains("HTML scaffold contract JSON"));
    assert!(!local_refinement_text.contains("Component pack contract JSON"));
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
fn local_html_materialization_repair_prompt_uses_compact_focus_contract() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();
    let raw_output = serde_json::json!({
        "summary": "AI tools editorial launch evidence",
        "notes": ["candidate near miss"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI Tools Editorial Launch</h1><p>Inspect the launch evidence.</p><button type=\"button\" data-view=\"tools\">Tools</button><button type=\"button\" data-view=\"signals\">Signals</button></section><section id=\"tools-panel\"><article><h2>Tool adoption</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Tool adoption\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\" data-detail=\"Drafting copilots lead adoption\" tabindex=\"0\"></rect><text x=\"20\" y=\"114\">Drafting</text></svg></article></section><section id=\"signals-panel\" hidden><article><h2>Editorial confidence</h2><ul><li>Fact-check coverage</li><li>Revision throughput</li><li>Voice consistency</li></ul></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Drafting copilots lead adoption by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();
    let failure = "HTML iframe briefs with clickable view switching must map each control to a pre-rendered panel with a literal data-view-panel attribute on the panel wrapper.";

    let remote_prompt = build_studio_artifact_materialization_repair_prompt(
        "AI tools editorial launch",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request,
        &brief,
        None,
        None,
        "candidate-4",
        77,
        &raw_output,
        failure,
    )
    .expect("remote repair prompt");
    let local_prompt = build_studio_artifact_materialization_repair_prompt_for_runtime(
        "AI tools editorial launch",
        "Create an interactive HTML artifact for an AI tools editorial launch page",
        &request,
        &brief,
        None,
        None,
        &[],
        &[],
        None,
        None,
        "candidate-4",
        77,
        &raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    )
    .expect("local repair prompt");

    let remote_text = serde_json::to_string(&remote_prompt).expect("remote repair prompt text");
    let local_text = serde_json::to_string(&local_prompt).expect("local repair prompt text");

    assert!(local_text.contains("Artifact request focus JSON"));
    assert!(local_text.contains("Artifact brief focus JSON"));
    assert!(local_text.contains("Interaction contract JSON"));
    assert!(local_text.contains("Previous candidate focus JSON"));
    assert!(local_text.contains("bodyPreview") || local_text.contains("rawOutputPreview"));
    assert!(local_text.contains("instead of restarting from a fresh shell"));
    assert!(local_text.contains("keyboard-focusable"));
    assert!(local_text.contains("do not leave it empty until interaction"));
    assert!(local_text
        .contains("Do not emit the literal words placeholder, placeholders, TODO, or TBD"));
    assert!(!local_text.contains("Artifact blueprint JSON"));
    assert!(!local_text.contains("Artifact IR JSON"));
    assert!(!local_text.contains("Selected skill guidance JSON"));
    assert!(local_text.len() < remote_text.len());
    assert!(local_text.len() < 10_000);
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
fn normalization_derives_view_tokens_from_plain_button_labels() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "AI tools editors".to_string(),
        job_to_be_done: "compare launch views".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show the launch evidence clearly".to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "tool comparison".to_string(),
            "launch metrics".to_string(),
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
        "summary": "AI tools launch artifact",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Compare the launch snapshot and tool metrics without leaving the artifact.</p><button type=\"button\">Launch Snapshot</button><button type=\"button\">Tool Metrics</button></section><section><article><h2>Launch Snapshot</h2><p>Editorial launch readiness stays visible here with one clear first-paint summary.</p></article></section><section><article><h2>Tool Metrics</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Coverage</td><td>82%</td></tr></table></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch Snapshot is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("plain button labels should become explicit view targets");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("derived button targets should satisfy explicit mapping");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-view=\"launch-snapshot\""));
    assert!(html.contains("data-view=\"tool-metrics\""));
    assert!(html.contains("data-view-panel=\"launch-snapshot\""));
    assert!(html.contains("data-view-panel=\"tool-metrics\""));
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
        "HTML iframe artifacts that wire focus-based detail behavior must make their data-detail marks keyboard-focusable.",
    );

    assert!(directives.contains("keep the current <main>"));
    assert!(directives.contains("querySelectorAll('[data-detail]')"));
    assert!(directives.contains("tabindex=\"0\""));
    assert!(directives.contains("[data-view-panel]"));
    assert!(directives.contains("detailCopy.textContent = mark.dataset.detail"));
}

#[test]
fn parse_and_validate_repairs_missing_panel_ids_referenced_by_scripts() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
        "summary": "Quantum computing explainer",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Quantum computing explainer</h1><button type=\"button\" data-view=\"superposition\" aria-controls=\"superposition-panel\" aria-selected=\"true\">Superposition</button><button type=\"button\" data-view=\"entanglement\" aria-controls=\"entanglement-panel\" aria-selected=\"false\">Entanglement</button></section><section data-view-panel=\"superposition\"><article><h2>Superposition view</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Superposition evidence\"><rect x=\"20\" y=\"40\" width=\"42\" height=\"60\" data-detail=\"Qubit amplitudes overlap\" tabindex=\"0\"></rect><text x=\"20\" y=\"114\">Overlap</text></svg></article></section><section data-view-panel=\"entanglement\" hidden><article><h2>Entanglement view</h2><p>Entanglement evidence stays pre-rendered here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Superposition is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const activePanel=document.getElementById('superposition-panel');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});const panel=document.getElementById(button.getAttribute('aria-controls'));if(panel){detail.textContent=panel.querySelector('h2')?.textContent||button.textContent||'';}}));if(activePanel){detail.textContent=activePanel.querySelector('h2')?.textContent||detail.textContent;}</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should add matching panel ids for referenced controls");
    let html = payload.files[0].body.to_ascii_lowercase();

    assert!(html.contains("id=\"superposition-panel\""));
    assert!(html.contains("id=\"entanglement-panel\""));
    assert!(!html_references_missing_dom_ids(&html));
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
fn html_local_runtime_candidate_generation_starts_with_two_candidates() {
    let (count, temperature, strategy) = candidate_generation_config(
        StudioRendererKind::HtmlIframe,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    assert_eq!(count, 2);
    assert!(temperature > 0.5);
    assert_eq!(strategy, "request-grounded_html");
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
fn local_html_generation_temperature_is_clamped_by_runtime_shape() {
    let (_, configured_temperature, _) = candidate_generation_config(
        StudioRendererKind::HtmlIframe,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );

    let local_html_temperature = super::generation::effective_candidate_generation_temperature(
        StudioRendererKind::HtmlIframe,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        configured_temperature,
    );
    let remote_html_temperature = super::generation::effective_candidate_generation_temperature(
        StudioRendererKind::HtmlIframe,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
        configured_temperature,
    );

    assert!((local_html_temperature - 0.32).abs() < f32::EPSILON);
    assert!((remote_html_temperature - configured_temperature).abs() < f32::EPSILON);
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
fn html_local_runtime_materialization_token_budget_preserves_completion_room() {
    assert_eq!(
        super::generation::materialization_max_tokens_for_runtime(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        2200
    );
    assert_eq!(
        super::generation::materialization_max_tokens_for_runtime(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
        ),
        2800
    );
}

#[tokio::test]
async fn modal_first_local_html_can_open_draft_before_acceptance() {
    #[derive(Clone)]
    struct DraftFirstHtmlRuntime {
        provenance: StudioRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for DraftFirstHtmlRuntime {
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
                    "jobToBeDone": "understand how quantum computers differ from classical systems",
                    "subjectDomain": "quantum computing",
                    "artifactThesis": "Explain the mental model with one request-grounded interactive artifact.",
                    "requiredConcepts": ["superposition", "measurement", "qubit"],
                    "requiredInteractions": [
                        "switch between classical and quantum views to compare how the explanation changes",
                        "inspect qubit callouts to reveal deeper context inline"
                    ],
                    "visualTone": ["technical editorial"],
                    "factualAnchors": ["measurement collapse"],
                    "styleDirectives": ["restrained dark scientific layout"],
                    "referenceHints": ["use browser-native controls only"]
                }),
                "materialize" => serde_json::json!({
                    "summary": "Quantum explainer draft",
                    "notes": ["Created a request-grounded HTML draft suitable for first paint."],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><meta charset=\"utf-8\"><title>Quantum computers interactive explainer</title><style>:root{color-scheme:dark;--bg:#10151b;--panel:#18202a;--border:#2a3644;--text:#ebf1f7;--muted:#9aabbe;--accent:#7dd3fc;}*{box-sizing:border-box;}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);}main{max-width:960px;margin:0 auto;padding:28px;display:grid;gap:18px;}section{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:18px;}button{border:1px solid #31506d;background:#182635;color:var(--text);border-radius:999px;padding:9px 14px;font:inherit;cursor:pointer;}button[aria-selected=\"true\"]{border-color:var(--accent);box-shadow:0 0 0 1px rgba(125,211,252,.34) inset;}p{color:var(--muted);line-height:1.55;}</style></head><body><main><section><h1>Quantum computers, visually</h1><p>Compare a classical bit with a qubit, then inspect how measurement changes what you can know.</p><div><button type=\"button\" data-mode=\"classical\" aria-selected=\"true\">Classical bit</button><button type=\"button\" data-mode=\"quantum\" aria-selected=\"false\">Quantum qubit</button></div></section><section><h2>State comparison</h2><p id=\"mode-summary\">A classical bit is either 0 or 1 before you read it.</p><p id=\"detail-copy\">Select a mode to reveal how quantum state and measurement differ.</p></section></main><script>const summary=document.getElementById('mode-summary');const detail=document.getElementById('detail-copy');const controls=document.querySelectorAll('[data-mode]');controls.forEach((button)=>button.addEventListener('click',()=>{controls.forEach((control)=>control.setAttribute('aria-selected', String(control===button)));if(button.dataset.mode==='quantum'){summary.textContent='A qubit can encode amplitude across multiple outcomes before measurement collapses the state.';detail.textContent='Quantum mode selected. Measurement turns a spread of possibilities into one observed result.';}else{summary.textContent='A classical bit is either 0 or 1 before you read it.';detail.textContent='Classical mode selected. The state is definite before observation.';}}));</script></body></html>"
                    }]
                }),
                "judge" => serde_json::json!({
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
                    "rationale": "The local HTML draft is request-grounded and strong enough to open while acceptance remains pending."
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

    #[derive(Default)]
    struct DraftFirstHtmlRenderEvaluator;

    #[async_trait]
    impl StudioArtifactRenderEvaluator for DraftFirstHtmlRenderEvaluator {
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
                        48,
                        460,
                        4,
                    ),
                    studio_test_render_capture(
                        StudioArtifactRenderCaptureViewport::Mobile,
                        44,
                        408,
                        4,
                    ),
                ],
            )))
        }
    }

    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(DraftFirstHtmlRuntime {
            provenance: StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            },
            role: "production",
            calls: calls.clone(),
        });
        let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(DraftFirstHtmlRuntime {
            provenance: StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some(
                    "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
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
        let evaluator = DraftFirstHtmlRenderEvaluator;

        let bundle =
            generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                "Quantum computers interactive explainer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                None,
                &planning_context,
                StudioExecutionStrategy::SinglePass,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("modal-first local html bundle should generate");

        let call_log = calls.lock().expect("calls lock").clone();
        assert!(call_log.iter().any(|entry| entry == "production:brief"));
        assert!(call_log
            .iter()
            .any(|entry| entry == "production:materialize"));
        assert!(call_log.iter().any(|entry| entry == "production:judge"));
        assert!(!call_log.iter().any(|entry| entry.starts_with("acceptance:")));
        assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Draft);
        assert_eq!(
            bundle.judge.classification,
            StudioArtifactJudgeClassification::Repairable
        );
        assert_eq!(bundle.winning_candidate_id.as_deref(), Some("candidate-1"));
        assert!(bundle
            .winning_candidate_rationale
            .as_deref()
            .is_some_and(|rationale| rationale.contains("Production surfaced a request-faithful local draft")));
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html" && file.body.contains("Quantum computers, visually")
        }));
    })
    .await;
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
fn html_local_runtime_refinement_budget_allows_two_passes() {
    assert_eq!(
        super::judging::semantic_refinement_pass_limit(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        ),
        2
    );
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
        StudioArtifactRuntimePolicyProfile::FullyLocal,
        false,
    );

    assert_eq!(budget.initial_candidate_count, 2);
    assert_eq!(budget.max_candidate_count, 3);
    assert!(budget.shortlist_limit >= 2);
    assert!(budget.max_semantic_refinement_passes >= 2);
    assert!(budget.max_semantic_refinement_passes <= 2);
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::BriefInteractionLoad));
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::BriefConceptLoad));
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::LocalGenerationConstraint));
    assert!(!budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::RendererComplexity));
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
fn moderate_local_html_budget_stays_tightly_bounded_before_refinement() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "developers interested in AI tools".to_string(),
        job_to_be_done: "explore new AI tools through an interactive editorial launch page"
            .to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "Launch page for an editorial on AI tools.".to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "interactive elements".to_string(),
        ],
        required_interactions: vec![
            "scroll through sections of the editorial".to_string(),
            "click on links to related articles or resources".to_string(),
        ],
        visual_tone: vec![],
        factual_anchors: vec![
            "latest advancements in AI technology".to_string(),
            "related articles and resources".to_string(),
        ],
        style_directives: vec![],
        reference_hints: vec![],
    };
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

    assert_eq!(budget.initial_candidate_count, 2);
    assert_eq!(budget.max_candidate_count, 2);
    assert_eq!(budget.shortlist_limit, 1);
    assert!(budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::LocalGenerationConstraint));
    assert!(!budget
        .signals
        .contains(&StudioAdaptiveSearchSignal::RendererComplexity));
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
        StudioArtifactRuntimePolicyProfile::FullyLocal,
        false,
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
fn parse_and_validate_repairs_json_wrapped_html_missing_main_region() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
        "summary": "Quantum computing explainer",
        "notes": ["model emitted the typed wrapper"],
        "files": [{
            "path": "artifact.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;}section{padding:1rem;}</style></head><body><header><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement without leaving the page.</p></header><section><h2>Qubits</h2><p>Qubits can represent blended amplitudes before measurement.</p></section><section><h2>Entanglement</h2><p>Entangled qubits share state information across distance.</p></section><section><h2>Measurement</h2><p>Measurement collapses amplitudes into observed outcomes.</p></section></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should synthesize a valid main region for wrapped html");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("<main"));
    assert!(html.contains("</main>"));
    assert!(html.matches("<section").count() >= 3);
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
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Compare launch readiness, channel adoption, and formula proof points.</p><button type=\"button\" id=\"retail\">Retail</button><button type=\"button\" id=\"subscription\">Subscription</button></section><section><article class=\"chart\"><h2>Channel adoption</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo adoption chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><rect x=\"88\" y=\"34\" width=\"40\" height=\"66\"></rect><text x=\"20\" y=\"114\">Retail</text><text x=\"88\" y=\"114\">Subscription</text></svg><p>Retail stays selected by default.</p></article></section><aside id=\"detail-panel\"><h2>Comparison detail</h2></aside></main><script>const detail=document.getElementById('detail-panel');document.getElementById('retail').addEventListener('click',()=>{detail.dataset.view='retail';});document.getElementById('subscription').addEventListener('click',()=>{detail.dataset.view='subscription';});</script></body></html>".to_string(),
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
fn parse_and_validate_preserves_authored_controls_without_injecting_disclosure() {
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
fn parse_and_validate_adds_tabindex_to_focus_driven_rollover_marks() {
    let raw = serde_json::json!({
            "summary": "AI tools editorial launch",
            "notes": ["focus handlers without tabindex"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Switch between readiness and metrics views, then inspect detail marks.</p><button type=\"button\" data-view=\"readiness\" aria-controls=\"readiness-panel\">Readiness</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"readiness-panel\" data-view-panel=\"readiness\"><article><h2>Readiness evidence</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Readiness evidence\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\" data-detail=\"Pilot approvals\"></rect><rect x=\"84\" y=\"36\" width=\"40\" height=\"64\" data-detail=\"Support readiness\"></rect><text x=\"20\" y=\"114\">Pilot</text><text x=\"84\" y=\"114\">Support</text></svg></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics evidence</h2><p>Metrics evidence stays pre-rendered here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Readiness is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("focus-driven rollover marks should gain tabindex");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-detail=\"pilot approvals\" tabindex=\"0\""));
    assert!(html.contains("data-detail=\"support readiness\" tabindex=\"0\""));
    assert!(html.contains("data-detail=\"pilot approvals\""));
    assert!(html.contains("role=\"button\""));
    assert!(html.contains("aria-label=\"pilot approvals\""));
}

#[test]
fn parse_and_validate_groups_loose_rollover_cards_into_highlight_section() {
    let raw = serde_json::json!({
            "summary": "AI tools editorial launch",
            "notes": ["loose rollover cards without a grouped evidence rail"],
            "files": [{
                "path": "launch-page.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><header><h1>AI tools editorial launch</h1><p>Inspect the launch evidence.</p></header><main><div class=\"control-bar\"><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"signals\" aria-controls=\"signals-panel\">Signals</button></div><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Overview evidence stays visible on first paint.</p></article></section><section id=\"signals-panel\" data-view-panel=\"signals\" hidden><article><h2>Signals</h2><p>Signals evidence remains pre-rendered here.</p></article></section><aside><h2>Shared detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside><div class=\"data-detail\" data-detail=\"Launch readiness\">Launch readiness</div><div class=\"data-detail\" data-detail=\"Audience adoption\">Audience adoption</div><div class=\"data-detail\" data-detail=\"Workflow lift\">Workflow lift</div><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('.data-detail').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-view-panel]').forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});detail.textContent=button.textContent + ' selected.';}));</script></main></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("loose rollover cards should be grouped into a visible highlight rail");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-rollover-chip-rail=\"true\""));
    assert!(html.contains("<div class=\"studio-rollover-chip-rail\">"));
    assert!(html.contains("evidence highlights"));
    assert!(html.contains("data-detail=\"launch readiness\""));
    assert!(html.contains("role=\"button\""));
}

#[test]
fn parse_and_validate_polishes_view_controls_for_render_eval() {
    let raw = serde_json::json!({
            "summary": "AI tools editorial launch",
            "notes": ["view controls missing accessibility polish"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><head><style>.control-bar{display:flex;justify-content:center;gap:20px;margin:20px 0}.evidence-surface{padding:20px;margin:20px;background:#fff;border:1px solid #ccc}.evidence-surface h3{text-align:center}</style></head><body><header><h1>AI tools editorial launch</h1><p>Inspect the launch evidence.</p></header><main><section><div class=\"control-bar\"><button data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></div></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article class=\"evidence-surface\"><h3>Overview</h3><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Overview chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\" data-detail=\"Launch readiness\"></rect><text x=\"20\" y=\"114\">Launch</text></svg></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article class=\"evidence-surface\"><h3>Metrics</h3><p>Metrics remain visible in this pre-rendered panel.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside></main><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.textContent;}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("view controls should gain accessibility polish and a primary render action");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-interaction-polish=\"true\""));
    assert!(html.contains("data-view=\"overview\" aria-controls=\"overview-panel\" type=\"button\" aria-label=\"overview\" aria-selected=\"true\""));
    assert!(html.contains("data-view=\"metrics\" aria-controls=\"metrics-panel\" type=\"button\" aria-label=\"metrics\" aria-selected=\"false\" data-studio-render-primary-action=\"true\""));
    assert!(html.contains("button[data-view][aria-selected=\"true\"]"));
    assert!(html.contains("[data-view-panel]:focus-within"));
}

#[test]
fn parse_and_validate_repairs_panel_only_click_handlers_and_thin_first_paint() {
    let raw = serde_json::json!({
            "summary": "Quantum computers explained",
            "notes": ["panel click handlers instead of control handlers"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computers Explained</title><style>body { margin: 0; font-family: system-ui, sans-serif; background: #0f172a; color: #e5e7eb; } main { max-width: 960px; margin: 0 auto; padding: 24px; } .control-bar button { display: inline-block; margin-right: 8px; background-color: #1f232b; color: white; border: none; padding: 6px 12px; cursor: pointer; } .detail-panel { display: block; margin-top: 16px; }</style></head><body><main><header><h1>Quantum Computers Explained</h1><p>Explore the fundamental concepts and practical implications of quantum computing in an engaging, interactive manner.</p></header><div class=\"control-bar\"><button data-view=\"qubits\" aria-controls=\"qubits-panel\">Qubits</button><button data-view=\"superposition\" aria-controls=\"superposition-panel\">Superposition</button></div><section id=\"qubits-panel\" data-view-panel=\"qubits\" hidden><h2>Quantum Computers Use Quantum Bits (Qubits)</h2><p>Unlike classical bits which can be either 0 or 1, qubits can exist in multiple states simultaneously.</p></section><section id=\"superposition-panel\" data-view-panel=\"superposition\"><h2>Superposition and Quantum States</h2><p>In superposition, a qubit can be in multiple states simultaneously.</p></section><aside class=\"detail-panel\" id=\"shared-detail-panel\"><p id=\"detail-copy\">Qubits is selected by default.</p><p>This area will update based on the selected view panel.</p></aside></main><script>const panels = document.querySelectorAll('[data-view-panel]');panels.forEach(panel => {panel.addEventListener('click', () => {const activePanel = document.querySelector('.active-panel');if (activePanel) {activePanel.classList.remove('active-panel');}panel.classList.add('active-panel');document.getElementById('shared-detail-panel').textContent = `Selected view: ${panel.getAttribute('data-view-panel')}`;});});</script></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("broken control wiring should be repaired into a render-evaluable artifact");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-view-switch-repair=\"true\""));
    assert!(html.contains("button[data-view], [role=\"tab\"][data-view]"));
    assert!(html.contains("summarizepanel"));
    assert!(!html.contains("nav[aria-label=...,"));
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
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Switch between the evidence views.</p><button data-view=\"tools\">AI Tools</button><button data-view=\"comparison\">Tool Comparison</button></section><section id=\"tools\"><article><h2>AI tools</h2><ul><li>Content generator</li><li>Grammar checker</li><li>Fact checker</li></ul></article></section><section id=\"comparison\" hidden><article><h2>Comparison</h2><p>Compare editors, publishers, and reviewers in one pre-rendered panel.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">AI tools is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('#tools, #comparison');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.dataset.view;});detail.textContent=button.textContent;}));</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("data-view controls should normalize into mapped panels");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("data-view to id panel mapping should satisfy visible mapped panel validation");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html_has_visible_populated_mapped_view_panel(&html));
    assert!(html.contains("data-view=\"tools\""));
    assert!(html.contains("id=\"tools\""));
}

#[test]
fn parse_and_validate_adds_rollover_detail_payloads_to_list_items() {
    let raw = serde_json::json!({
            "summary": "AI tools editorial launch",
            "notes": ["list-based evidence without data-detail"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Inspect the launch evidence.</p><button data-view=\"tools\">AI Tools</button><button data-view=\"comparison\">Comparison</button></section><section id=\"tools\" data-view-panel=\"tools\"><article><h2>AI tools</h2><ul><li>Content generator</li><li>Grammar checker</li><li>Fact checker</li></ul></article></section><section id=\"comparison\" data-view-panel=\"comparison\" hidden><article><h2>Comparison</h2><ul><li>Editors</li><li>Publishers</li><li>Reviewers</li></ul></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">AI tools is selected by default.</p></aside></main></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("list-based evidence should gain rollover detail payloads");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("<li data-detail=") || html.contains("<li tabindex=\"0\" data-detail="));
    assert!(count_html_rollover_detail_marks(&html) >= 3);
    assert!(html.contains("data-studio-rollover-repair=\"true\""));
}

#[test]
fn parse_and_validate_populates_empty_mapped_view_panels() {
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
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": ["empty mapped panels"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Switch between launch and sales evidence.</p></section><nav aria-label=\"Artifact views\"><button type=\"button\" data-view=\"launch\" aria-controls=\"launch-panel\" aria-selected=\"true\">Launch</button><button type=\"button\" data-view=\"sales\" aria-controls=\"sales-panel\">Sales</button></nav><section id=\"launch-panel\" data-view-panel=\"launch\"></section><section id=\"sales-panel\" data-view-panel=\"sales\" hidden></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch selected by default.</p></aside><footer><p>Compare rollout evidence without leaving the artifact.</p></footer><script>const controls=document.querySelectorAll('button[data-view]');const panels=document.querySelectorAll('[data-view-panel]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');panel.setAttribute('aria-hidden',String(panel.hidden));});document.getElementById('detail-copy').textContent=button.textContent;}));</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("empty mapped panels should gain fallback content during normalization");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("normalized mapped panels should satisfy first-paint content requirements");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-empty-panel-repair=\"true\""));
    assert!(html.contains("launch stays available as a pre-rendered editorial launch view"));
    assert!(html.contains("sales stays available as a pre-rendered editorial launch view"));
}

#[test]
fn parse_and_validate_backfills_empty_existing_shared_detail_regions() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
        "summary": "AI tools editorial launch",
        "notes": ["empty shared detail panel"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Switch between launch views and inspect the detail panel.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"signals\" aria-controls=\"signals-panel\">Signals</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Overview evidence is visible on first paint.</p></article></section><section id=\"signals-panel\" data-view-panel=\"signals\" hidden><article><h2>Signals</h2><p>Signals remain pre-rendered for comparison.</p></article></section><aside id=\"detail-panel\"><h2>Comparison detail</h2></aside><script>const panels=document.querySelectorAll('[data-view-panel]');const detail=document.getElementById('detail-panel');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});detail.dataset.view=button.dataset.view;}));</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("empty shared detail regions should be backfilled during normalization");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("id=\"detail-copy\""));
    assert!(html.contains("overview is selected by default."));
    assert!(!html_contains_empty_detail_regions(&html));
    assert_eq!(count_populated_html_detail_regions(&html), 1);
}

#[test]
fn parse_and_validate_reuses_existing_shared_detail_region_for_detail_copy_target() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
        "summary": "AI tools editorial launch",
        "notes": ["existing shared detail region lacks detail-copy target"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Explore the tool launch and inspect the shared detail region.</p><button type=\"button\" data-view=\"tools\" aria-controls=\"tools-panel\">Tools</button><button type=\"button\" data-view=\"demos\" aria-controls=\"demos-panel\">Demos</button></section><section id=\"tools-panel\" data-view-panel=\"tools\"><article><h2>Featured AI tools</h2><p>Tool coverage stays visible on first paint.</p></article></section><section id=\"demos-panel\" data-view-panel=\"demos\" hidden><article><h2>Live demos</h2><p>Demo coverage remains pre-rendered here.</p></article></section><section><div class=\"shared-detail\"><h2>Selected tool details</h2><div id=\"detail-content\"><p>Default content for the shared detail region.</p></div></div></section><script>const panels=document.querySelectorAll('[data-view-panel]');const detailContent=document.getElementById('detail-content');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});detailContent.textContent=button.dataset.view;}));</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("existing shared detail region should gain a detail-copy target in place");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("id=\"detail-copy\""));
    assert!(!html_contains_empty_detail_regions(&html));
    assert_eq!(count_populated_html_detail_regions(&html), 1);
    assert!(!html.contains(
        "<aside data-studio-normalized=\"true\" data-studio-shared-detail=\"true\"><h2>detail</h2>"
    ));
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
fn repair_shim_marker_count_tracks_unique_repair_families() {
    let html = "<!doctype html><html><body data-studio-normalized=\"true\"><main data-studio-normalized=\"true\"><section data-studio-normalized=\"true\"></section><script data-studio-view-switch-repair=\"true\"></script><aside data-studio-shared-detail=\"true\"></aside><section data-studio-rollover-chip-rail=\"true\"></section></main></body></html>";
    assert_eq!(
        count_html_repair_shim_markers(&html.to_ascii_lowercase()),
        3
    );
}

#[test]
fn repair_shim_marker_count_ignores_populated_rollover_chip_rail() {
    let html = "<!doctype html><html><body><main><script data-studio-view-switch-repair=\"true\"></script><aside data-studio-shared-detail=\"true\"><p id=\"detail-copy\">Overview is selected.</p></aside><section data-studio-rollover-chip-rail=\"true\"><button type=\"button\" data-detail=\"launch readiness\">Launch readiness</button><button type=\"button\" data-detail=\"tool features\">Tool features</button><button type=\"button\" data-detail=\"editorial comparison\">Editorial comparison</button></section></main></body></html>";
    assert_eq!(
        count_html_repair_shim_markers(&html.to_ascii_lowercase()),
        2
    );
}

#[test]
fn renderer_contract_allows_near_pass_html_when_unique_repairs_stay_below_threshold() {
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
    };
    let payload = parse_and_validate_generated_artifact_payload(
        include_str!("test_fixtures/qwen3_editorial_trace8_near_pass.html"),
        &request,
    )
    .expect("fixture should parse and normalize");

    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("fixture should stay above the first-paint contract");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert_eq!(count_html_repair_shim_markers(&html), 3);

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
fn enrich_generated_html_payload_adds_rollover_chips_to_editorial_trace_shape() {
    let mut payload = StudioGeneratedArtifactPayload {
        summary: "Prepared editorial launch artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><header><h1>AI Tools Editorial Launch</h1></header><main><section class=\"hero\"><h1>Interactive HTML Artifact</h1><p>Showcasing AI tools for editorial use.</p></section><section class=\"control-bar\"><button data-view=\"tools\">AI Tools</button><button data-view=\"features\">Tool Features</button></section><section class=\"evidence\" data-view-panel=\"tools\"><h2>AI Tools for Editorial Use</h2><p>These AI tools streamline editorial workflows.</p><svg viewBox=\"0 0 200 100\"><rect x=\"0\" y=\"0\" width=\"200\" height=\"100\" fill=\"#e0e0e0\"></rect><text x=\"10\" y=\"20\">Tool 1</text><text x=\"10\" y=\"40\">Tool 2</text><text x=\"10\" y=\"60\">Tool 3</text></svg></section><section class=\"evidence\" data-view-panel=\"features\"><h2>Tool Features</h2><p>Feature comparisons stay pre-rendered here.</p><svg viewBox=\"0 0 200 100\"><rect x=\"0\" y=\"0\" width=\"200\" height=\"100\" fill=\"#e0e0e0\"></rect><text x=\"10\" y=\"20\">Feature 1</text><text x=\"10\" y=\"40\">Feature 2</text><text x=\"10\" y=\"60\">Feature 3</text></svg></section><section class=\"shared-detail\"><h2>Shared Detail Panel</h2><p id=\"detail-copy\">This panel displays details about the currently selected view.</p></section></main></body></html>".to_string(),
        }],
    };
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
    };

    enrich_generated_artifact_payload(
        &mut payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &brief,
    );

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-rollover-chip-rail=\"true\""));
    assert!(count_html_rollover_detail_marks(&html) >= 3);
}

#[test]
fn enrich_generated_html_payload_backfills_existing_chip_rail_without_detail_marks() {
    let mut payload = StudioGeneratedArtifactPayload {
        summary: "Prepared editorial launch artifact".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "artifact.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Inspect the launch evidence.</p><button data-view=\"overview\">Overview</button><button data-view=\"comparison\">Comparison</button></section><section data-view-panel=\"overview\"><article><h2>Overview</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Launch chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><text x=\"20\" y=\"114\">Launch</text></svg></article></section><section data-view-panel=\"comparison\" hidden><article><h2>Comparison</h2><p>Comparison evidence remains visible here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside><section data-studio-normalized=\"true\" data-studio-rollover-chip-rail=\"true\"><h2>Evidence highlights</h2><div class=\"studio-rollover-chip-rail\"><button type=\"button\" class=\"studio-rollover-chip\">Overview</button><button type=\"button\" class=\"studio-rollover-chip\">Comparison</button></div><p>Select, hover, or focus a highlight to inspect the shared detail panel.</p></section></main></body></html>".to_string(),
        }],
    };
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
    };

    enrich_generated_artifact_payload(
        &mut payload,
        &request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        ),
        &brief,
    );

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-rollover-chip-rail=\"true\""));
    assert!(count_html_rollover_detail_marks(&html) >= 3);
}

#[test]
fn parse_and_validate_adds_tabindex_to_svg_text_rollover_marks() {
    let raw = serde_json::json!({
            "summary": "AI tools editorial launch",
            "notes": ["svg text nodes carry rollover detail labels"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Inspect the launch evidence.</p><button data-view=\"tools\">AI Tools</button><button data-view=\"features\">Tool Features</button></section><section data-view-panel=\"tools\"><article><h2>AI tools</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"AI tools chart\"><text x=\"20\" y=\"24\" data-detail=\"tool one\">Tool 1</text><text x=\"20\" y=\"52\" data-detail=\"tool two\">Tool 2</text><text x=\"20\" y=\"80\" data-detail=\"tool three\">Tool 3</text></svg></article></section><section data-view-panel=\"features\" hidden><article><h2>Features</h2><p>Feature evidence remains visible here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Tool one is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("svg text rollover marks should gain tabindex");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-detail=\"tool one\" tabindex=\"0\""));
    assert!(html.contains("data-detail=\"tool two\" tabindex=\"0\""));
    assert!(html.contains("data-detail=\"tool three\" tabindex=\"0\""));
    assert!(!html_has_unfocusable_rollover_marks(&html));
}

#[test]
fn parse_and_validate_adds_tabindex_when_rollover_contract_is_injected() {
    let raw = serde_json::json!({
            "summary": "AI tools editorial launch",
            "notes": ["rollover contract should add focusability in markup"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Inspect the launch evidence.</p><button data-view=\"tools\">AI Tools</button><button data-view=\"comparison\">Comparison</button></section><section data-view-panel=\"tools\"><article><h2>AI tools</h2><div data-detail=\"tool one\">Tool 1</div><div data-detail=\"tool two\">Tool 2</div><div data-detail=\"tool three\">Tool 3</div></article></section><section data-view-panel=\"comparison\" hidden><article><h2>Comparison</h2><p>Comparison evidence remains visible here.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Tool one is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
            }]
        })
        .to_string();

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("rollover contract injection should also make marks focusable in markup");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-studio-rollover-repair=\"true\""));
    assert!(html.contains("data-detail=\"tool one\" tabindex=\"0\""));
    assert!(html.contains("data-detail=\"tool two\" tabindex=\"0\""));
    assert!(html.contains("data-detail=\"tool three\" tabindex=\"0\""));
    assert!(!html_has_unfocusable_rollover_marks(&html));
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
struct StudioWarmupRecordingRuntime {
    provenance: StudioRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl StudioWarmupRecordingRuntime {
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
impl InferenceRuntime for StudioWarmupRecordingRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("direct document author") {
            "materialize"
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
                "jobToBeDone": "explore the launch page",
                "subjectDomain": "AI tools editorial launch page",
                "artifactThesis": "Showcase AI tools with editorial comparisons and live callouts.",
                "requiredConcepts": ["AI tools", "editorial workflow optimization", "content generation examples"],
                "requiredInteractions": ["switch launch sections", "compare editorial callouts"],
                "visualTone": ["modern", "editorial"],
                "factualAnchors": ["launch issue highlights"],
                "styleDirectives": ["Use clear hierarchy"],
                "referenceHints": []
            })
            .to_string(),
            "materialize" => "<!doctype html><html><body><main><section><h1>AI tools launch</h1><div><button type=\"button\" data-view=\"overview\" aria-controls=\"panel-overview\" aria-selected=\"true\">Overview</button><button type=\"button\" data-view=\"compare\" aria-controls=\"panel-compare\" aria-selected=\"false\">Compare</button></div></section><aside><p id=\"detail-copy\">Overview is selected by default.</p></aside><section id=\"panel-overview\" data-view-panel=\"overview\" data-active=\"true\"><h2>Overview</h2><p>AI tools and editorial workflow optimization.</p></section><section id=\"panel-compare\" data-view-panel=\"compare\" data-active=\"false\" hidden><h2>Compare</h2><p>Compare editorial callouts and content generation examples.</p></section><script>const controls = Array.from(document.querySelectorAll('button[data-view]')); const panels = Array.from(document.querySelectorAll('[data-view-panel]')); const detail = document.getElementById('detail-copy'); controls.forEach((button) => { button.addEventListener('click', () => { const view = button.dataset.view; panels.forEach((panel) => { const active = panel.dataset.viewPanel === view; panel.hidden = !active; panel.dataset.active = active ? 'true' : 'false'; }); controls.forEach((control) => control.setAttribute('aria-selected', control === button ? 'true' : 'false')); detail.textContent = `${button.textContent} is selected.`; }); });</script></main></body></html>".to_string(),
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
            })
            .to_string(),
            _ => return Err(VmError::HostError("unexpected Studio prompt".to_string())),
        };
        Ok(response.into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{}:load_model", self.role));
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
struct FailingStudioOutcomeRuntime;

#[async_trait]
impl InferenceRuntime for FailingStudioOutcomeRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError(
            "explicit single-document routes should not invoke the LLM router".to_string(),
        ))
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
            label: "fixture://failing-studio-outcome".to_string(),
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
struct StudioDownloadAliasTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioDownloadAliasTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        if !prompt.contains("typed artifact materializer") {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        }

        self.calls
            .lock()
            .expect("calls lock")
            .push("materialize".to_string());

        Ok(serde_json::json!({
            "summary": "Downloadable launch bundle",
            "notes": ["local-runtime alias payload"],
            "files": [{
                "path": "README.md",
                "mime": "text/markdown",
                "role": "supporting",
                "renderable": false,
                "downloadable": true,
                "encoding": "utf8",
                "content": "# Launch bundle\n\nReview `exports/launch-metrics.csv` before the meeting."
            }, {
                "path": "exports/launch-metrics.csv",
                "mime": "text/csv",
                "role": "export",
                "renderable": false,
                "downloadable": true,
                "encoding": "utf8",
                "text": "lane,metric,value\npilot,coverage,72\nlaunch,readiness,81\nretention,continuity,66\n"
            }]
        })
        .to_string()
        .into_bytes())
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
            label: "fixture://studio-download-alias".to_string(),
            model: Some("fixture-download-alias".to_string()),
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
                    "requiredInteractions": ["switch launch sections", "compare editorial callouts"],
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
struct StudioBriefDeterministicSalvageTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefDeterministicSalvageTestRuntime {
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
                    "audience": "",
                    "jobToBeDone": "Create a markdown artifact that documents a release checklist",
                    "subjectDomain": "",
                    "artifactThesis": "A release checklist document",
                    "requiredConcepts": ["release", "checklist", "markdown"],
                    "requiredInteractions": [],
                    "visualTone": [],
                    "factualAnchors": [],
                    "styleDirectives": [],
                    "referenceHints": []
                }),
            )
        } else if prompt.contains("typed artifact brief repairer") {
            (
                "brief-repair",
                serde_json::json!({
                    "audience": "",
                    "jobToBeDone": "Create a markdown artifact that documents a release checklist",
                    "subjectDomain": "",
                    "artifactThesis": "A release checklist document",
                    "requiredConcepts": ["release", "checklist", "markdown"],
                    "requiredInteractions": [],
                    "visualTone": [],
                    "factualAnchors": [],
                    "styleDirectives": [],
                    "referenceHints": []
                }),
            )
        } else {
            (
                "brief",
                serde_json::json!({
                    "audience": "",
                    "jobToBeDone": "Create a markdown artifact that documents a release checklist",
                    "subjectDomain": "",
                    "artifactThesis": "A release checklist document",
                    "requiredConcepts": ["release", "checklist", "markdown"],
                    "requiredInteractions": [],
                    "visualTone": [],
                    "factualAnchors": [],
                    "styleDirectives": [],
                    "referenceHints": []
                }),
            )
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
            label: "fixture://studio-brief-deterministic-salvage".to_string(),
            model: Some("fixture-brief-deterministic-salvage".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioBriefSubjectFallbackTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefSubjectFallbackTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let stage = if prompt.contains("typed artifact brief field repairer") {
            "brief-field-repair"
        } else if prompt.contains("typed artifact brief repairer") {
            "brief-repair"
        } else {
            "brief"
        };
        let response = serde_json::json!({
            "audience": "users",
            "jobToBeDone": "Create a downloadable artifact bundle with a CSV and README",
            "subjectDomain": "",
            "artifactThesis": "A downloadable artifact bundle with a CSV and README",
            "requiredConcepts": ["CSV", "README"],
            "requiredInteractions": [],
            "visualTone": [],
            "factualAnchors": [],
            "styleDirectives": [],
            "referenceHints": []
        });

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
            label: "fixture://studio-brief-subject-fallback".to_string(),
            model: Some("fixture-brief-subject-fallback".to_string()),
            endpoint: None,
        }
    }
}

#[derive(Clone)]
struct StudioBriefPromptCaptureTestRuntime {
    calls: Arc<Mutex<Vec<(String, u32)>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefPromptCaptureTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_studio_test_prompt(input_context);
        self.calls
            .lock()
            .expect("calls lock")
            .push((prompt, options.max_tokens));
        Ok(serde_json::json!({
            "audience": "AI editorial readers",
            "jobToBeDone": "understand the launch story through inspectable sections",
            "subjectDomain": "AI tools editorial launch page",
            "artifactThesis": "Present an editorial launch page for AI tools with visible evidence-rich interaction points.",
            "requiredConcepts": ["AI tools", "editorial launch", "launch page"],
            "requiredInteractions": ["switch launch sections", "compare editorial callouts"],
            "visualTone": ["editorial"],
            "factualAnchors": ["launch themes and editorial callouts"],
            "styleDirectives": ["clear hierarchy"],
            "referenceHints": ["launch page narrative structure"]
        })
        .to_string()
        .into_bytes())
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
            label: "ollama-openai".to_string(),
            model: Some("qwen2.5:14b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }
    }
}

#[derive(Clone)]
struct StudioBriefPlanningSpecialistRegressionTestRuntime {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl InferenceRuntime for StudioBriefPlanningSpecialistRegressionTestRuntime {
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
                    "audience": "tech enthusiasts and industry professionals",
                    "jobToBeDone": "explore and learn about new AI tools for editorial purposes through an interactive HTML artifact",
                    "subjectDomain": "AI tools in content creation and management",
                    "artifactThesis": "An interactive HTML artifact that showcases the latest AI tools for editorial use, providing a seamless learning experience through engaging interactions.",
                    "requiredConcepts": ["AI tool integration", "content generation", "editorial workflow optimization"],
                    "requiredInteractions": ["tool comparison slider", "interactive demo", "case study viewer"],
                    "visualTone": ["modern", "innovative"],
                    "factualAnchors": ["latest AI advancements in content creation", "industry expert insights on editorial tools"],
                    "styleDirectives": ["clean layout", "responsive design"],
                    "referenceHints": ["AI-driven content platforms", "editorial technology trends"]
                }),
            )
        } else if prompt.contains("typed artifact brief repairer") {
            (
                "brief-repair",
                serde_json::json!({
                    "audience": "tech enthusiasts and industry professionals",
                    "jobToBeDone": "explore and learn about new AI tools for editorial purposes through an interactive HTML artifact",
                    "subjectDomain": "AI tools in content creation and management",
                    "artifactThesis": "An interactive HTML artifact that showcases the latest AI tools for editorial use, providing a seamless learning experience through engaging interactions.",
                    "requiredConcepts": ["AI tool demonstrations", "editorial workflow optimization", "content generation examples"],
                    "requiredInteractions": ["tool demo video playback", "interactive quiz on AI applications", "live coding sessions"],
                    "visualTone": ["modern and sleek", "informative and educational"],
                    "factualAnchors": ["According to recent studies, AI tools can significantly enhance the efficiency of content creation processes."],
                    "styleDirectives": ["Use clear and concise language", "Ensure interactive elements are intuitive and user-friendly"],
                    "referenceHints": ["https://www.nature.com/articles/s41597-020-00683-w", "https://www.sciencedirect.com/science/article/pii/S030645731930265X"]
                }),
            )
        } else if prompt.contains("typed artifact brief planner") {
            (
                "brief",
                serde_json::json!({
                    "audience": "tech enthusiasts and industry professionals",
                    "jobToBeDone": "explore and learn about new AI tools for editorial purposes",
                    "subjectDomain": "AI tools in content creation and management",
                    "artifactThesis": "An interactive HTML artifact that showcases the latest AI tools for editorial use, providing a seamless learning experience through engaging interactions.",
                    "requiredConcepts": ["AI tool demonstrations", "editorial workflow optimization", "content generation examples"],
                    "requiredInteractions": ["tool demo video playback", "interactive quiz on AI applications"],
                    "visualTone": ["modern and sleek", "informative and educational"],
                    "factualAnchors": ["According to recent studies, AI tools can significantly enhance the efficiency of content creation processes."],
                    "styleDirectives": ["Use clear and concise language", "Ensure interactive elements are intuitive and user-friendly"],
                    "referenceHints": ["https://www.nature.com/articles/s41597-020-00683-w", "https://www.sciencedirect.com/science/article/pii/S030645731930265X"]
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
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "ollama-openai".to_string(),
            model: Some("qwen2.5:7b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
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
async fn explicit_single_document_html_routes_without_router_inference() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(FailingStudioOutcomeRuntime);

    let planned = plan_studio_outcome_with_runtime(
        runtime,
        "Create an interactive HTML artifact that explains quantum computers.",
        None,
        None,
    )
    .await
    .expect("explicit single-document artifact requests should short-circuit routing");

    assert_eq!(planned.outcome_kind, StudioOutcomeKind::Artifact);
    assert_eq!(
        planned.execution_strategy,
        StudioExecutionStrategy::DirectAuthor
    );
    assert!(planned.confidence > 0.9);
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
    assert!(artifact.verification.require_render);
    assert!(!artifact.verification.require_build);
    assert!(!artifact.verification.require_preview);
}

#[tokio::test]
async fn route_planning_reconciles_explicit_downloadable_fileset_intent() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioOutcomeTestRuntime {
        payload: r#"{
          "outcomeKind":"artifact",
          "confidence":0.99,
          "needsClarification":false,
          "clarificationQuestions":[],
          "artifact":{
            "artifactClass":"document",
            "deliverableShape":"single_file",
            "renderer":"markdown",
            "presentationSurface":"side_panel",
            "persistence":"shared_artifact_scoped",
            "executionSubstrate":"none",
            "workspaceRecipeId":null,
            "presentationVariantId":null,
            "scope":{"targetProject":null,"createNewWorkspace":false,"mutationBoundary":["artifact"]},
            "verification":{"requireRender":false,"requireBuild":false,"requirePreview":false,"requireExport":false,"requireDiffReview":false}
          }
        }"#
        .to_string(),
    });

    let planned = plan_studio_outcome_with_runtime(
        runtime,
        "Create a downloadable artifact bundle with a CSV and README",
        None,
        None,
    )
    .await
    .expect("route planning should reconcile explicit fileset requests");

    let artifact = planned.artifact.expect("artifact request");
    assert_eq!(artifact.renderer, StudioRendererKind::DownloadCard);
    assert_eq!(
        artifact.artifact_class,
        StudioArtifactClass::DownloadableFile
    );
    assert_eq!(
        artifact.deliverable_shape,
        StudioArtifactDeliverableShape::FileSet
    );
    assert_eq!(
        artifact.persistence,
        StudioArtifactPersistenceMode::SharedArtifactScoped
    );
    assert_eq!(artifact.execution_substrate, StudioExecutionSubstrate::None);
    assert!(artifact.verification.require_export);
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
async fn materialization_accepts_file_content_aliases_without_repair() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioDownloadAliasTestRuntime {
        calls: calls.clone(),
    });

    let payload = materialize_studio_artifact_candidate_with_runtime(
        runtime,
        "Launch bundle",
        "Create a downloadable artifact bundle with a CSV and README",
        &request_for(
            StudioArtifactClass::DownloadableFile,
            StudioRendererKind::DownloadCard,
        ),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "download the launch exports".to_string(),
            subject_domain: "launch metrics".to_string(),
            artifact_thesis: "Provide a CSV export and README bundle.".to_string(),
            required_concepts: vec![
                "csv export".to_string(),
                "readme".to_string(),
                "launch bundle".to_string(),
            ],
            required_interactions: Vec::new(),
            visual_tone: vec!["clear".to_string()],
            factual_anchors: vec!["launch metrics".to_string()],
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        },
        None,
        None,
        "candidate-1",
        42,
        0.2,
    )
    .await
    .expect("content aliases should materialize without repair");

    assert_eq!(payload.files.len(), 2);
    assert!(payload.files[0].body.contains("Launch bundle"));
    assert!(payload.files[1].body.contains("lane,metric,value"));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["materialize"]);
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
            "switch launch sections".to_string(),
            "compare editorial callouts".to_string()
        ]
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(
        recorded_calls,
        vec!["brief", "brief-repair", "brief-field-repair"]
    );
}

#[tokio::test]
async fn local_html_brief_planner_uses_compact_prompt_and_budget() {
    let calls = Arc::new(Mutex::new(Vec::<(String, u32)>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioBriefPromptCaptureTestRuntime {
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
    .expect("brief planning should succeed");

    assert_eq!(brief.subject_domain, "AI tools editorial launch page");

    let recorded_calls = calls.lock().expect("calls lock");
    assert_eq!(recorded_calls.len(), 1);
    assert_eq!(
        recorded_calls[0].1,
        brief_planner_max_tokens_for_runtime(
            StudioRendererKind::HtmlIframe,
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        )
    );
    assert!(recorded_calls[0].0.contains("Artifact request focus JSON"));
    assert!(recorded_calls[0].0.contains(
        "requiredInteractions must include at least two concrete multi-word on-page interactions with visible response"
    ));
    assert!(!recorded_calls[0]
        .0
        .contains("Renderer-aware brief guidance"));
}

#[tokio::test]
async fn local_html_brief_planner_regrounds_specialist_interactions() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioBriefPlanningSpecialistRegressionTestRuntime {
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
    .expect("specialist brief should be re-grounded");

    assert!(brief.required_interactions.iter().any(|interaction| {
        interaction
            == "switch AI tool demonstrations sections to update the visible comparison panel"
    }));
    assert!(brief.required_interactions.iter().any(|interaction| {
        interaction == "compare editorial workflow optimization callouts in the shared detail panel"
    }));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["brief"]);
}

#[tokio::test]
async fn brief_field_repair_deterministically_salvages_release_checklist_core_fields() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioBriefDeterministicSalvageTestRuntime {
        calls: calls.clone(),
    });

    let brief = plan_studio_artifact_brief_with_runtime(
        runtime,
        "Release checklist",
        "Create a markdown artifact that documents a release checklist",
        &request_for(StudioArtifactClass::Document, StudioRendererKind::Markdown),
        None,
    )
    .await
    .expect("deterministic salvage should recover the brief");

    assert_eq!(brief.subject_domain, "Release checklist");
    assert_eq!(brief.audience, "people reviewing the Release checklist");

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert_eq!(recorded_calls, vec!["brief"]);
}

#[tokio::test]
async fn brief_field_repair_salvage_uses_artifact_thesis_when_title_is_generic() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioBriefSubjectFallbackTestRuntime {
        calls: calls.clone(),
    });

    let brief = plan_studio_artifact_brief_with_runtime(
        runtime,
        "Download bundle",
        "Create a downloadable artifact bundle with a CSV and README",
        &request_for(
            StudioArtifactClass::DownloadableFile,
            StudioRendererKind::DownloadCard,
        ),
        None,
    )
    .await
    .expect("artifact thesis fallback should recover the subject domain");

    assert_eq!(
        brief.subject_domain,
        "downloadable artifact bundle with a CSV and README"
    );
    assert_eq!(brief.audience, "users");

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
            None,
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
            None,
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
fn populated_html_evidence_region_count_prefers_leaf_views_over_wrapper_section() {
    let html = "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Switch between evidence views.</p></section><section class=\"evidence\"><div><h2>AI tools overview</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"AI tools overview\"><rect x=\"20\" y=\"48\" width=\"36\" height=\"52\"></rect><rect x=\"84\" y=\"34\" width=\"36\" height=\"66\"></rect><text x=\"20\" y=\"114\">Draft</text><text x=\"84\" y=\"114\">Review</text></svg></div><div><h2>AI tools features</h2><svg viewBox=\"0 0 240 120\" role=\"img\" aria-label=\"AI tools features\"><rect x=\"20\" y=\"40\" width=\"36\" height=\"60\"></rect><rect x=\"84\" y=\"28\" width=\"36\" height=\"72\"></rect><text x=\"20\" y=\"114\">Research</text><text x=\"84\" y=\"114\">Verify</text></svg></div></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected.</p></aside></main></body></html>";
    let lower = html.to_ascii_lowercase();

    assert_eq!(count_populated_html_evidence_regions(&lower), 2);
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
fn payload_normalization_hides_extra_visible_mapped_panels() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let raw = r#"{
        "summary": "Multiple visible mapped panels",
        "notes": [],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #ccc;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\"><article><h2>Metrics</h2><p>Metrics evidence should start hidden until selected.</p></article></section><aside><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
        }]
    }"#;

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("normalization should keep exactly one mapped panel visible");
    let html = &payload.files[0].body;

    assert!(html.contains("id=\"overview-panel\" data-view-panel=\"overview\""));
    assert!(
        html.contains("id=\"metrics-panel\" data-view-panel=\"metrics\" hidden")
            || html.contains(
                "id=\"metrics-panel\" data-view-panel=\"metrics\" aria-hidden=\"true\" hidden"
            )
    );
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
fn enrichment_repairs_unfocusable_rollover_marks_before_brief_validation() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = StudioArtifactBrief {
        audience: "AI tools editors".to_string(),
        job_to_be_done: "review the launch evidence".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "Compare the launch evidence across editorial workflows.".to_string(),
        required_concepts: vec![
            "AI tools editorial launch page".to_string(),
            "client sandbox execution".to_string(),
        ],
        required_interactions: vec![
            "click to explore AI tools features".to_string(),
            "hover to reveal editorial content highlights".to_string(),
        ],
        visual_tone: vec!["modern".to_string(), "clean".to_string()],
        factual_anchors: vec!["AI tools editorial launch page".to_string()],
        style_directives: vec!["responsive design".to_string()],
        reference_hints: vec!["html_iframe renderer".to_string()],
    };
    let mut payload = StudioGeneratedArtifactPayload {
        summary: "Unfocusable rollover marks".to_string(),
        notes: vec![],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #cbd5e1;border-radius:12px;}svg{width:100%;max-width:320px;height:auto;}</style></head><body><main><section><h1>AI tools editorial launch</h1><p>Compare readiness, adoption, and support demand through a focused rollout story with visible evidence marks.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"signals\" aria-controls=\"signals-panel\">Signals</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Overview evidence stays visible here with trend notes, operator context, and one shared detail region.</p><svg viewBox=\"0 0 320 120\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"24\" y=\"28\" width=\"52\" height=\"64\" fill=\"#2563eb\" data-detail=\"Readiness signal\"></rect><rect x=\"104\" y=\"16\" width=\"52\" height=\"76\" fill=\"#0f766e\" data-detail=\"Adoption signal\"></rect><rect x=\"184\" y=\"36\" width=\"52\" height=\"56\" fill=\"#b45309\" data-detail=\"Support signal\"></rect></svg></article></section><section id=\"signals-panel\" data-view-panel=\"signals\" hidden><article><h2>Signals</h2><ul><li>Fact-check coverage held steady.</li><li>Revision throughput improved.</li><li>Operator guidance stayed visible.</li></ul></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Readiness signal is selected by default.</p></aside><footer><p>Footer note summarizing next steps and verification posture.</p></footer><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('focus',()=>{detail.textContent=mark.getAttribute('data-detail');});mark.addEventListener('mouseenter',()=>{detail.textContent=mark.getAttribute('data-detail');});});document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-view-panel]').forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});}));</script></main></body></html>".to_string(),
        }],
    };

    enrich_generated_artifact_payload(&mut payload, &request, &brief);
    let html = &payload.files[0].body;

    assert!(!html_has_unfocusable_rollover_marks(
        &html.to_ascii_lowercase()
    ));
    assert!(
        html.contains("data-detail=\"Readiness signal\" tabindex=\"0\"")
            || html.contains("tabindex=\"0\" data-detail=\"Readiness signal\"")
    );
    assert!(
        html.contains("data-detail=\"Adoption signal\" tabindex=\"0\"")
            || html.contains("tabindex=\"0\" data-detail=\"Adoption signal\"")
    );
    assert!(
        html.contains("data-detail=\"Support signal\" tabindex=\"0\"")
            || html.contains("tabindex=\"0\" data-detail=\"Support signal\"")
    );
}

#[test]
fn rollover_focus_validation_ignores_script_template_markup() {
    let html = "<!doctype html><html><body><main><section><h1>Launch review</h1><p>Inspect the live artifact.</p></section><aside><p id=\"detail-copy\">Overview selected by default.</p></aside><script>const template = `<div data-detail=\"ghost detail\"></div>`; document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('focus',()=>{document.getElementById('detail-copy').textContent = mark.dataset.detail;});});</script></main></body></html>";

    assert!(!html_has_unfocusable_rollover_marks(
        &html.to_ascii_lowercase()
    ));
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
async fn modal_first_judge_contract_downgrades_incomplete_html_documents() {
    with_modal_first_html_env_async(|| async {
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
            "Quantum computing explainer",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &sample_quantum_explainer_brief(),
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Quantum explainer draft".to_string(),
                notes: vec![],
                files: vec![StudioGeneratedArtifactFile {
                    path: "index.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button></section><section><article><h2>Quantum circuit</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Quantum circuit\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Gate</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Superposition is selected by default.</p></aside><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.getElementById('detail-copy').textContent=button.dataset.view;}));</script><div class=\"".to_string(),
                }],
            },
        )
        .await
        .expect("judge contract should downgrade incomplete html");

        assert_eq!(
            result.classification,
            StudioArtifactJudgeClassification::Repairable
        );
        assert!(!result.deserves_primary_artifact_view);
        assert_eq!(
            result.strongest_contradiction.as_deref(),
            Some("HTML iframe artifacts must contain a fully closed </body></html> document.")
        );
    })
    .await;
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
fn local_markdown_judge_prompt_uses_ultra_compact_document_contract() {
    let payload = build_studio_artifact_judge_prompt_for_runtime(
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
            notes: vec!["expanded checklist".to_string(), "ops-facing".to_string()],
            files: vec![StudioGeneratedArtifactFile {
                path: "release-checklist.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                body: format!("START\n{}\nEND", "cut release branch\n".repeat(200)),
            }],
        },
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    )
    .expect("local judge prompt should build");

    let user_content = payload[1]["content"]
        .as_str()
        .expect("user content should be a string");
    assert!(user_content.contains("verdict: pass|repairable|blocked"));
    assert!(user_content.contains("faithfulness: 1-5"));
    assert!(user_content.contains("coverage: 1-5"));
    assert!(user_content.contains("complete: 1-5"));
    assert!(user_content.contains("next: accept|repair|block"));
    assert!(!user_content.contains("interactionVerdict"));
    assert!(!user_content.contains("fileFindings"));
    assert!(!user_content.contains("truthfulnessWarnings"));
    assert!(!user_content.contains("strengths: item; item"));
    assert!(user_content.contains("No JSON or fences."));
    assert!(user_content.contains("file1: release-checklist.md"));
    assert!(user_content.contains("[truncated"));
}

#[test]
fn modal_first_local_html_judge_prompt_rejects_generic_interactive_shells() {
    with_modal_first_html_env(|| {
        let payload = build_studio_artifact_judge_prompt_for_runtime(
            "Quantum computing explainer",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &sample_quantum_explainer_brief(),
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Quantum explainer draft".to_string(),
                notes: vec!["interactive".to_string()],
                files: vec![StudioGeneratedArtifactFile {
                    path: "artifact.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Quantum</h1><button>Toggle</button></section></main></body></html>".to_string(),
                }],
            },
            StudioRuntimeProvenanceKind::RealLocalRuntime,
        )
        .expect("modal-first local html judge prompt should build");

        let user_content = payload[1]["content"]
            .as_str()
            .expect("user content should be a string");
        assert!(user_content.contains("classification: pass|repairable|blocked"));
        assert!(user_content.contains("interactionRelevance: 1-5"));
        assert!(user_content.contains("deservesPrimaryArtifactView: true|false"));
        assert!(user_content.contains("No JSON or markdown fences."));
        assert!(user_content.contains("generic dashboard chrome"));
        assert!(user_content.contains("file: path=artifact.html"));
    });
}

#[test]
fn modal_first_local_html_judge_prompt_carries_render_eval_focus() {
    with_modal_first_html_env(|| {
        let render_evaluation = studio_test_render_evaluation(
            17,
            true,
            vec![StudioArtifactRenderFinding {
                code: "visual_hierarchy_flat".to_string(),
                severity: StudioArtifactRenderFindingSeverity::Warning,
                summary:
                    "The capture reads as visually flat instead of establishing a clear first-paint hierarchy."
                        .to_string(),
            }],
            vec![
                studio_test_render_capture(
                    StudioArtifactRenderCaptureViewport::Desktop,
                    24,
                    280,
                    2,
                ),
                studio_test_render_capture(
                    StudioArtifactRenderCaptureViewport::Mobile,
                    20,
                    240,
                    2,
                ),
            ],
        );
        let payload = super::judging::build_studio_artifact_judge_prompt_with_render_eval_for_runtime(
            "Quantum computing explainer",
            &request_for(
                StudioArtifactClass::InteractiveSingleFile,
                StudioRendererKind::HtmlIframe,
            ),
            &sample_quantum_explainer_brief(),
            None,
            &StudioGeneratedArtifactPayload {
                summary: "Quantum explainer draft".to_string(),
                notes: vec!["interactive".to_string()],
                files: vec![StudioGeneratedArtifactFile {
                    path: "artifact.html".to_string(),
                    mime: "text/html".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: true,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "<!doctype html><html><body><main><section><h1>Quantum</h1><button>Toggle</button></section></main></body></html>".to_string(),
                }],
            },
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            Some(&render_evaluation),
        )
        .expect("modal-first local html judge prompt with render eval should build");

        let user_content = payload[1]["content"]
            .as_str()
            .expect("user content should be a string");
        assert!(user_content.contains("Render evaluation JSON"));
        assert!(user_content.contains("\"overallScore\":17"));
        assert!(user_content.contains("visually flat"));
        assert!(user_content
            .contains("recommendedNextPass: accept|structural_repair|polish_pass|hold_block"));
        assert!(user_content.contains("classification: pass|repairable|blocked"));
    });
}

#[test]
fn local_download_card_judge_prompt_uses_compact_bundle_contract() {
    let payload = build_studio_artifact_judge_prompt_for_runtime(
        "Bundle download",
        &request_for(
            StudioArtifactClass::DownloadableFile,
            StudioRendererKind::DownloadCard,
        ),
        &StudioArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "download a csv and readme bundle".to_string(),
            subject_domain: "release operations".to_string(),
            artifact_thesis: "ship a usable bundle".to_string(),
            required_concepts: vec!["CSV".to_string(), "README".to_string()],
            required_interactions: vec![],
            visual_tone: vec![],
            factual_anchors: vec![],
            style_directives: vec![],
            reference_hints: vec![],
        },
        None,
        &StudioGeneratedArtifactPayload {
            summary: "Bundle draft".to_string(),
            notes: vec!["ready for export".to_string()],
            files: vec![
                StudioGeneratedArtifactFile {
                    path: "README.md".to_string(),
                    mime: "text/markdown".to_string(),
                    role: StudioArtifactFileRole::Primary,
                    renderable: false,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "# README\nThis bundle explains the export.".to_string(),
                },
                StudioGeneratedArtifactFile {
                    path: "data.csv".to_string(),
                    mime: "text/csv".to_string(),
                    role: StudioArtifactFileRole::Export,
                    renderable: false,
                    downloadable: true,
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: "name,value\nalpha,1\nbeta,2".to_string(),
                },
            ],
        },
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    )
    .expect("local bundle judge prompt should build");

    let user_content = payload[1]["content"]
        .as_str()
        .expect("user content should be a string");
    assert!(user_content.contains("classification: pass|repairable|blocked"));
    assert!(user_content.contains("recommendedNextPass: accept|structural_repair|hold_block"));
    assert!(user_content.contains("Judge only whether this is a usable downloadable bundle"));
    assert!(!user_content.contains("requestFaithfulness: 1-5"));
    assert!(!user_content.contains("deservesPrimaryArtifactView: true|false"));
    assert!(user_content.contains("file1: path=README.md"));
    assert!(user_content.contains("file2: path=data.csv"));
}

#[test]
fn parse_studio_artifact_judge_result_hydrates_compact_document_verdict() {
    let raw = serde_json::json!({
        "classification": "pass",
        "requestFaithfulness": 5,
        "conceptCoverage": 4,
        "completeness": 4,
        "genericShellDetected": false,
        "trivialShellDetected": false,
        "deservesPrimaryArtifactView": true,
        "strengths": ["Request concepts remain visible."],
        "blockedReasons": [],
        "recommendedNextPass": "accept",
        "rationale": "Candidate stays specific and complete enough to lead."
    })
    .to_string();

    let result = parse_studio_artifact_judge_result(&raw)
        .expect("compact document verdict should hydrate into a full judge result");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_eq!(result.request_faithfulness, 5);
    assert_eq!(result.concept_coverage, 4);
    assert_eq!(result.completeness, 4);
    assert_eq!(result.interaction_relevance, 4);
    assert_eq!(result.layout_coherence, 4);
    assert_eq!(result.visual_hierarchy, 4);
    assert_eq!(result.recommended_next_pass.as_deref(), Some("accept"));
}

#[test]
fn parse_studio_artifact_judge_result_recovers_ultra_compact_markdown_plaintext() {
    let result = parse_studio_artifact_judge_result(
        r#"
verdict: pass
faithfulness: 5
coverage: 4
complete: 4
generic: false
trivial: false
primary: true
next: accept
why: Candidate stays specific and usable enough to lead.
"#,
    )
    .expect("ultra compact markdown plaintext should recover");

    assert_eq!(
        result.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_eq!(result.request_faithfulness, 5);
    assert_eq!(result.concept_coverage, 4);
    assert_eq!(result.completeness, 4);
    assert_eq!(result.interaction_relevance, 4);
    assert_eq!(result.layout_coherence, 4);
    assert_eq!(result.visual_hierarchy, 4);
    assert!(!result.generic_shell_detected);
    assert!(!result.trivial_shell_detected);
    assert!(result.deserves_primary_artifact_view);
    assert_eq!(result.recommended_next_pass.as_deref(), Some("accept"));
    assert_eq!(
        result.rationale,
        "Candidate stays specific and usable enough to lead."
    );
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

    assert_eq!(bundle.winning_candidate_id.as_deref(), Some("candidate-2"));
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

    assert_eq!(
        bundle.winning_candidate_id.as_deref(),
        Some("candidate-1-refine-1")
    );
    assert_ne!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Blocked
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
    let production_judge_count = recorded_calls
        .iter()
        .filter(|call| *call == "production:judge")
        .count();
    assert!((1..=2).contains(&production_judge_count));
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

    assert_eq!(bundle.winning_candidate_id.as_deref(), Some("candidate-1"));
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
async fn local_html_renderer_keeps_judged_path_instead_of_forcing_draft() {
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

    assert_eq!(bundle.winning_candidate_id.as_deref(), Some("candidate-1"));
    assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Judged);
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_ne!(
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
    assert!(recorded_calls.iter().any(|call| call == "production:judge"));
    assert!(recorded_calls.iter().any(|call| call == "acceptance:judge"));
}

#[test]
fn local_generation_remote_acceptance_matching_local_provenance_disables_draft_fast_path() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "openai-compatible",
        "qwen3:8b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "openai-compatible",
        "qwen3:8b",
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
    assert!(matches!(
        acceptance_binding.provenance.kind,
        StudioRuntimeProvenanceKind::RealLocalRuntime
    ));
    assert_eq!(acceptance_binding.provenance.label, "openai-compatible");
    assert_eq!(
        acceptance_binding.provenance.model.as_deref(),
        Some("qwen3:8b")
    );
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("acceptance_runtime_not_distinct")
    );
}

#[test]
fn local_generation_remote_acceptance_ignores_lane_only_endpoint_tags_when_matching_local_provenance(
) {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "openai-compatible",
        "qwen3:8b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioTestRuntime::new(
        StudioRuntimeProvenanceKind::RealLocalRuntime,
        "openai-compatible",
        "qwen3:8b",
        "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance",
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
    assert!(matches!(
        acceptance_binding.provenance.kind,
        StudioRuntimeProvenanceKind::RealLocalRuntime
    ));
    assert_eq!(acceptance_binding.provenance.label, "openai-compatible");
    assert_eq!(
        acceptance_binding.provenance.model.as_deref(),
        Some("qwen3:8b")
    );
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("acceptance_runtime_not_distinct")
    );
}

#[tokio::test]
async fn fully_local_matching_provenance_runs_acceptance_instead_of_pending_draft_shortcut() {
    #[derive(Clone)]
    struct MatchingLocalRuntime {
        provenance: StudioRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for MatchingLocalRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
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

            let response = match stage {
                "brief" => serde_json::json!({
                    "audience": "AI tools editors and publishers",
                    "jobToBeDone": "launch an AI tools editorial with an interactive HTML artifact",
                    "subjectDomain": "AI tools editorial launch",
                    "artifactThesis": "an interactive HTML artifact that showcases AI tools for editorial use",
                    "requiredConcepts": ["AI tools", "editorial launch", "interactive HTML"],
                    "requiredInteractions": ["click to explore AI tools", "hover to view tool features"],
                    "visualTone": ["modern", "clean", "professional"],
                    "factualAnchors": ["AI tools editorial launch page"],
                    "styleDirectives": ["responsive design", "user-friendly interface"],
                    "referenceHints": ["HTML iframe integration"]
                }),
                "materialize" => serde_json::json!({
                    "summary": "AI tools editorial launch artifact",
                    "notes": ["request-grounded local draft"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><style>body{margin:0;font-family:Inter,system-ui,sans-serif;background:#f5efe6;color:#1d1b19;}main{display:grid;gap:1rem;padding:1.5rem;}section,article,aside,footer{background:#fffaf4;border:1px solid #dbc9b2;border-radius:18px;padding:1rem;}nav{display:flex;gap:.5rem;flex-wrap:wrap;}button{border:1px solid #8b6b3f;background:#f1e0c2;border-radius:999px;padding:.45rem .85rem;cursor:pointer;}svg{width:100%;height:auto;}table{width:100%;border-collapse:collapse;}th,td{padding:.4rem .5rem;border-bottom:1px solid #e8dccd;text-align:left;}</style></head><body><main><section><h1>AI tools editorial launch page</h1><p>Explore launch-ready tools, compare editorial roles, and inspect hover details from a single interactive artifact.</p><nav><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\" aria-selected=\"true\">Overview</button><button type=\"button\" data-view=\"tooling\" aria-controls=\"tooling-panel\" aria-selected=\"false\">Tooling</button></nav></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Launch readiness map</h2><svg viewBox=\"0 0 280 150\" role=\"img\" aria-label=\"AI tools editorial launch readiness\"><rect x=\"18\" y=\"42\" width=\"56\" height=\"76\" tabindex=\"0\" data-detail=\"Writers need fast brief-to-draft handoff.\"></rect><rect x=\"112\" y=\"26\" width=\"56\" height=\"92\" tabindex=\"0\" data-detail=\"Editors compare structure, tone, and citations.\"></rect><rect x=\"206\" y=\"34\" width=\"56\" height=\"84\" tabindex=\"0\" data-detail=\"Publishers validate readiness and launch timing.\"></rect><text x=\"18\" y=\"138\">Writers</text><text x=\"112\" y=\"138\">Editors</text><text x=\"206\" y=\"138\">Publishers</text></svg></article></section><section id=\"tooling-panel\" data-view-panel=\"tooling\" hidden><article><h2>Tool comparison</h2><table><tr><th>Tool</th><th>Editorial value</th></tr><tr><td>Research copilot</td><td>Speeds briefing with grounded citations.</td></tr><tr><td>Draft assistant</td><td>Turns outlines into structured launch copy.</td></tr><tr><td>Review verifier</td><td>Flags weak claims before publication.</td></tr></table></article></section><aside><h2>Shared detail</h2><p id=\"detail-copy\">Overview is selected by default for the editorial launch.</p></aside><footer><p>Use the view switcher to compare launch surfaces, then hover the chart marks to inspect each editorial role.</p></footer><script>const detail=document.getElementById('detail-copy');const controls=document.querySelectorAll('button[data-view]');const panels=document.querySelectorAll('[data-view-panel]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});controls.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=`${button.dataset.view} selected for the editorial launch.`;}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=`Hover: ${mark.dataset.detail}`;});mark.addEventListener('focus',()=>{detail.textContent=`Focus: ${mark.dataset.detail}`;});});</script></main></body></html>"
                    }]
                }),
                "judge" => serde_json::json!({
                    "classification": "pass",
                    "requestFaithfulness": 5,
                    "conceptCoverage": 5,
                    "interactionRelevance": 5,
                    "layoutCoherence": 4,
                    "visualHierarchy": 5,
                    "completeness": 5,
                    "genericShellDetected": false,
                    "trivialShellDetected": false,
                    "deservesPrimaryArtifactView": true,
                    "patchedExistingArtifact": null,
                    "continuityRevisionUx": null,
                    "strongestContradiction": null,
                    "rationale": format!("{} cleared the editorial launch artifact.", self.role)
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

    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(MatchingLocalRuntime {
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3:8b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        role: "production",
        calls: calls.clone(),
    });
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(MatchingLocalRuntime {
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3:8b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        role: "acceptance",
        calls: calls.clone(),
    });
    let evaluator = StudioSlowRenderEvaluator;

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let planning_context = prepared_context_for_request(&request, &sample_html_brief());
    let bundle =
        generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::FullyLocal,
            "AI tools editorial launch page",
            "Create an interactive HTML artifact for an AI tools editorial launch page",
            &request,
            None,
            &planning_context,
            Some(&evaluator),
        )
        .await
        .expect("bundle should generate");

    assert_eq!(
        bundle.runtime_policy.as_ref().map(|policy| policy.profile),
        Some(StudioArtifactRuntimePolicyProfile::FullyLocal)
    );
    assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Judged);
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_ne!(
        bundle.judge.strongest_contradiction.as_deref(),
        Some("Acceptance judging is still pending for this draft.")
    );
    assert_eq!(bundle.winning_candidate_id.as_deref(), Some("candidate-1"));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert!(recorded_calls.iter().any(|call| call == "production:judge"));
    assert!(!recorded_calls.iter().any(|call| call == "acceptance:judge"));
}

#[tokio::test]
async fn lane_tagged_matching_local_provenance_runs_acceptance_instead_of_pending_draft_shortcut() {
    #[derive(Clone)]
    struct MatchingLocalRuntime {
        provenance: StudioRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for MatchingLocalRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
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

            let response = match stage {
                "brief" => serde_json::json!({
                    "audience": "AI tools editors and publishers",
                    "jobToBeDone": "launch an AI tools editorial with an interactive HTML artifact",
                    "subjectDomain": "AI tools editorial launch",
                    "artifactThesis": "an interactive HTML artifact that showcases AI tools for editorial use",
                    "requiredConcepts": ["AI tools", "editorial launch", "interactive HTML"],
                    "requiredInteractions": ["click to explore AI tools", "hover to view tool features"],
                    "visualTone": ["modern", "clean", "professional"],
                    "factualAnchors": ["AI tools editorial launch page"],
                    "styleDirectives": ["responsive design", "user-friendly interface"],
                    "referenceHints": ["HTML iframe integration"]
                }),
                "materialize" => serde_json::json!({
                    "summary": "AI tools editorial launch artifact",
                    "notes": ["request-grounded local draft"],
                    "files": [{
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><style>body{margin:0;font-family:Inter,system-ui,sans-serif;background:#f5efe6;color:#1d1b19;}main{display:grid;gap:1rem;padding:1.5rem;}section,article,aside,footer{background:#fffaf4;border:1px solid #dbc9b2;border-radius:18px;padding:1rem;}nav{display:flex;gap:.5rem;flex-wrap:wrap;}button{border:1px solid #8b6b3f;background:#f1e0c2;border-radius:999px;padding:.45rem .85rem;cursor:pointer;}svg{width:100%;height:auto;}table{width:100%;border-collapse:collapse;}th,td{padding:.4rem .5rem;border-bottom:1px solid #e8dccd;text-align:left;}</style></head><body><main><section><h1>AI tools editorial launch page</h1><p>Explore launch-ready tools, compare editorial roles, and inspect hover details from a single interactive artifact.</p><nav><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\" aria-selected=\"true\">Overview</button><button type=\"button\" data-view=\"tooling\" aria-controls=\"tooling-panel\" aria-selected=\"false\">Tooling</button></nav></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Launch readiness map</h2><svg viewBox=\"0 0 280 150\" role=\"img\" aria-label=\"AI tools editorial launch readiness\"><rect x=\"18\" y=\"42\" width=\"56\" height=\"76\" tabindex=\"0\" data-detail=\"Writers need fast brief-to-draft handoff.\"></rect><rect x=\"112\" y=\"26\" width=\"56\" height=\"92\" tabindex=\"0\" data-detail=\"Editors compare structure, tone, and citations.\"></rect><rect x=\"206\" y=\"34\" width=\"56\" height=\"84\" tabindex=\"0\" data-detail=\"Publishers validate readiness and launch timing.\"></rect><text x=\"18\" y=\"138\">Writers</text><text x=\"112\" y=\"138\">Editors</text><text x=\"206\" y=\"138\">Publishers</text></svg></article></section><section id=\"tooling-panel\" data-view-panel=\"tooling\" hidden><article><h2>Tool comparison</h2><table><tr><th>Tool</th><th>Editorial value</th></tr><tr><td>Research copilot</td><td>Speeds briefing with grounded citations.</td></tr><tr><td>Draft assistant</td><td>Turns outlines into structured launch copy.</td></tr><tr><td>Review verifier</td><td>Flags weak claims before publication.</td></tr></table></article></section><aside><h2>Shared detail</h2><p id=\"detail-copy\">Overview is selected by default for the editorial launch.</p></aside><footer><p>Use the view switcher to compare launch surfaces, then hover the chart marks to inspect each editorial role.</p></footer><script>const detail=document.getElementById('detail-copy');const controls=document.querySelectorAll('button[data-view]');const panels=document.querySelectorAll('[data-view-panel]');controls.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});controls.forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=`${button.dataset.view} selected for the editorial launch.`;}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=`Hover: ${mark.dataset.detail}`;});mark.addEventListener('focus',()=>{detail.textContent=`Focus: ${mark.dataset.detail}`;});});</script></main></body></html>"
                    }]
                }),
                "judge" => serde_json::json!({
                    "classification": "pass",
                    "requestFaithfulness": 5,
                    "conceptCoverage": 5,
                    "interactionRelevance": 5,
                    "layoutCoherence": 4,
                    "visualHierarchy": 5,
                    "completeness": 5,
                    "genericShellDetected": false,
                    "trivialShellDetected": false,
                    "deservesPrimaryArtifactView": true,
                    "patchedExistingArtifact": null,
                    "continuityRevisionUx": null,
                    "strongestContradiction": null,
                    "rationale": format!("{} cleared the editorial launch artifact.", self.role)
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

    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(MatchingLocalRuntime {
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3:8b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        role: "production",
        calls: calls.clone(),
    });
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(MatchingLocalRuntime {
        provenance: StudioRuntimeProvenance {
            kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3:8b".to_string()),
            endpoint: Some(
                "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
            ),
        },
        role: "acceptance",
        calls: calls.clone(),
    });

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let planning_context = prepared_context_for_request(&request, &sample_html_brief());
    let bundle =
        generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
            "AI tools editorial launch page",
            "Create an interactive HTML artifact for an AI tools editorial launch page",
            &request,
            None,
            &planning_context,
            None,
        )
        .await
        .expect("bundle should generate");

    assert_eq!(
        bundle.runtime_policy.as_ref().map(|policy| policy.profile),
        Some(StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance)
    );
    assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Judged);
    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_ne!(
        bundle.judge.strongest_contradiction.as_deref(),
        Some("Acceptance judging is still pending for this draft.")
    );
    assert_eq!(bundle.winning_candidate_id.as_deref(), Some("candidate-1"));

    let recorded_calls = calls.lock().expect("calls lock").clone();
    assert!(recorded_calls.iter().any(|call| call == "production:judge"));
    assert!(!recorded_calls.iter().any(|call| call == "acceptance:judge"));
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
        None,
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

    assert_eq!(
        bundle.winning_candidate_id.as_deref(),
        Some("candidate-1-refine-1")
    );
    assert_ne!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Blocked
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
        bundle.winning_candidate_id.as_deref()
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
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        &request,
        production_runtime.clone(),
        Some(acceptance_runtime.clone()),
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration,
    );
    let planning_context = planned_prepared_context_with_runtime_plan(
        &runtime_plan,
        "Instacart rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request,
        None,
    )
    .await;

    let bundle = generate_studio_artifact_bundle_with_runtimes_and_planning_context(
        production_runtime,
        Some(acceptance_runtime),
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration,
        "Instacart rollout artifact",
        "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
        &request,
        None,
        &planning_context,
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

    assert_eq!(
        bundle.winning_candidate_id.as_deref(),
        Some("candidate-1-refine-2")
    );
    assert_ne!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Blocked
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

#[tokio::test]
async fn local_generation_remote_acceptance_materializes_html_on_primary_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioWarmupRecordingRuntime::new(
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            "local producer",
            "qwen2.5:14b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StudioWarmupRecordingRuntime::new(
            StudioRuntimeProvenanceKind::RealLocalRuntime,
            "local specialist",
            "qwen2.5:7b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "acceptance",
            calls.clone(),
        ));

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let planning_context = prepared_context_for_request(&request, &sample_html_brief());
    let bundle =
        generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
            production_runtime,
            Some(acceptance_runtime),
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
            "AI tools editorial launch page",
            "Create an interactive HTML artifact for an AI tools editorial launch page",
            &request,
            None,
            &planning_context,
            None,
        )
        .await
        .expect("generation bundle");

    assert_ne!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Blocked
    );

    let recorded_calls = calls.lock().expect("calls lock").clone();
    let materialize_index = recorded_calls
        .iter()
        .position(|entry| entry == "production:materialize")
        .expect("primary materialize call");

    assert!(materialize_index < recorded_calls.len());
    assert!(!recorded_calls
        .iter()
        .any(|entry| entry == "production:brief"));
    assert!(!recorded_calls
        .iter()
        .any(|entry| entry == "acceptance:materialize"));
}

#[tokio::test]
async fn modal_first_local_generation_remote_acceptance_materializes_html_on_primary_runtime() {
    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(StudioWarmupRecordingRuntime::new(
                StudioRuntimeProvenanceKind::RealLocalRuntime,
                "local producer",
                "qwen2.5:14b",
                "http://127.0.0.1:11434/v1/chat/completions",
                "production",
                calls.clone(),
            ));
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(StudioWarmupRecordingRuntime::new(
                StudioRuntimeProvenanceKind::RealLocalRuntime,
                "local specialist",
                "qwen3.5:9b",
                "http://127.0.0.1:11434/v1/chat/completions",
                "acceptance",
                calls.clone(),
            ));

        let request = request_for(
            StudioArtifactClass::InteractiveSingleFile,
            StudioRendererKind::HtmlIframe,
        );
        let planning_context = prepared_context_for_request(&request, &sample_html_brief());
        let bundle =
            generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
                production_runtime,
                Some(acceptance_runtime),
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
                "AI tools editorial launch page",
                "Create an interactive HTML artifact for an AI tools editorial launch page",
                &request,
                None,
                &planning_context,
                None,
            )
            .await
            .expect("generation bundle");

        assert_ne!(
            bundle.judge.classification,
            StudioArtifactJudgeClassification::Blocked
        );

        let recorded_calls = calls.lock().expect("calls lock").clone();
        let materialize_index = recorded_calls
            .iter()
            .position(|entry| entry == "production:materialize")
            .expect("primary materialize call");

        assert!(materialize_index < recorded_calls.len());
        assert!(!recorded_calls
            .iter()
            .any(|entry| entry == "production:brief"));
        assert!(!recorded_calls
            .iter()
            .any(|entry| entry == "acceptance:materialize"));
    })
    .await;
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

#[test]
fn swarm_patch_gate_rejects_out_of_scope_regions() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let mut payload = StudioGeneratedArtifactPayload {
        summary: "Interactive rollout".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><main><!-- STUDIO_REGION_START:section:hero --><section><h1>Old hero</h1></section><!-- STUDIO_REGION_END:section:hero --></main></body></html>".to_string(),
        }],
    };
    let work_item = StudioArtifactWorkItem {
        id: "section-1".to_string(),
        title: "Section 1".to_string(),
        role: StudioArtifactWorkerRole::SectionContent,
        summary: "Own the hero section.".to_string(),
        spawned_from_id: None,
        read_paths: vec!["index.html".to_string()],
        write_paths: vec!["index.html".to_string()],
        write_regions: vec!["section:hero".to_string()],
        lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
        acceptance_criteria: vec!["Hero stays request-grounded.".to_string()],
        dependency_ids: vec!["skeleton".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(SwarmVerificationPolicy::Normal),
        retry_budget: Some(0),
        status: StudioArtifactWorkItemStatus::Pending,
    };
    let envelope = super::generation::StudioArtifactPatchEnvelope {
        summary: Some("Attempted invalid patch".to_string()),
        notes: Vec::new(),
        operations: vec![super::generation::StudioArtifactPatchOperation {
            kind: super::generation::StudioArtifactPatchOperationKind::ReplaceRegion,
            path: "index.html".to_string(),
            region_id: Some("section:other".to_string()),
            mime: None,
            role: None,
            renderable: None,
            downloadable: None,
            encoding: None,
            body: Some("<section><h1>Wrong region</h1></section>".to_string()),
        }],
    };

    let error = super::generation::apply_studio_swarm_patch_envelope(
        &request,
        &mut payload,
        &work_item,
        &envelope,
    )
    .expect_err("out-of-scope region should be rejected");

    assert!(error.contains("out-of-scope region"));
    assert!(payload.files[0].body.contains("Old hero"));
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
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":judge"))
                .count(),
            2
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
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":judge"))
                .count(),
            2
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
