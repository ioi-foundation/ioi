use super::*;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
fn parses_planning_payload_with_renderer_derived_defaults() {
    let parsed = parse_studio_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "renderer": "markdown"
            }
        }"#,
    )
    .expect("planning payload should derive renderer-shaped defaults");

    let artifact = parsed.artifact.expect("artifact payload");
    assert_eq!(artifact.artifact_class, StudioArtifactClass::Document);
    assert_eq!(
        artifact.deliverable_shape,
        StudioArtifactDeliverableShape::SingleFile
    );
    assert_eq!(artifact.renderer, StudioRendererKind::Markdown);
    assert_eq!(
        artifact.presentation_surface,
        StudioPresentationSurface::SidePanel
    );
    assert_eq!(
        artifact.persistence,
        StudioArtifactPersistenceMode::SharedArtifactScoped
    );
    assert_eq!(artifact.execution_substrate, StudioExecutionSubstrate::None);
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
fn parses_planning_payload_preserves_execution_strategy() {
    let parsed = parse_studio_outcome_planning_payload(
        r#"{
            "outcomeKind": "artifact",
            "executionStrategy": "single-pass",
            "confidence": 0.93,
            "needsClarification": false,
            "clarificationQuestions": [],
            "artifact": {
                "renderer": "markdown"
            }
        }"#,
    )
    .expect("planning payload should preserve execution strategy");

    assert_eq!(
        parsed.execution_strategy,
        StudioExecutionStrategy::SinglePass
    );
}

#[test]
fn outcome_router_prompt_spells_out_html_vs_jsx_contracts() {
    let prompt = build_studio_outcome_router_prompt(
        "Create an interactive HTML artifact that explains a product rollout with charts",
        None,
        None,
    );
    let prompt_text = serde_json::to_string(&prompt).expect("prompt text");
    assert!(prompt_text.contains("executionStrategy"));
    assert!(prompt_text.contains("direct_author = direct first-pass authoring"));
    assert!(
        prompt_text.contains("Prefer direct_author for a fresh coherent single-file document ask")
    );
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
fn outcome_router_prompt_compacts_for_local_runtime() {
    let full_prompt = build_studio_outcome_router_prompt(
        "Create a markdown artifact that documents a release checklist",
        None,
        None,
    );
    let compact_prompt = build_studio_outcome_router_prompt_for_runtime(
        "Create a markdown artifact that documents a release checklist",
        None,
        None,
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    let full_prompt_text = serde_json::to_string(&full_prompt).expect("full prompt text");
    let compact_prompt_text = decode_studio_test_prompt(
        &serde_json::to_vec(&compact_prompt).expect("compact prompt bytes"),
    );

    assert!(compact_prompt_text.len() < full_prompt_text.len());
    assert!(compact_prompt_text.len() * 2 < full_prompt_text.len());
    assert!(compact_prompt_text.contains("executionStrategy"));
    assert!(compact_prompt_text.contains("Return exactly one JSON object"));
    assert!(compact_prompt_text.contains("Renderer meanings:"));
    assert!(compact_prompt_text.contains("Defaults are derived from renderer when omitted"));
    assert!(compact_prompt_text.contains(
        "Explicit medium-plus-deliverable requests are sufficiently specified artifact work."
    ));
    assert!(compact_prompt_text.contains("Do not use lexical fallbacks or benchmark phrase maps."));
    assert!(!compact_prompt_text
        .contains("Create an interactive HTML artifact for an AI tools editorial launch page"));
}

#[test]
fn local_outcome_router_prompt_uses_summarized_active_artifact_context() {
    let prompt = build_studio_outcome_router_prompt_for_runtime(
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
                body: "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>".repeat(20),
            }],
            selected_targets: Vec::new(),
            taste_memory: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        }),
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    let prompt_text =
        decode_studio_test_prompt(&serde_json::to_vec(&prompt).expect("prompt bytes"));

    assert!(prompt_text.contains("Active artifact context summary JSON"));
    assert!(prompt_text.contains("\"bodyChars\""));
    assert!(prompt_text.contains("\"lineCount\""));
    assert!(!prompt_text.contains("bodyPreview"));
}

#[tokio::test(flavor = "current_thread")]
async fn local_outcome_router_uses_text_json_contract() {
    #[derive(Debug, Clone)]
    struct LocalOutcomeRouterRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
        json_modes: Arc<Mutex<Vec<bool>>>,
        max_tokens: Arc<Mutex<Vec<u32>>>,
    }

    #[async_trait]
    impl InferenceRuntime for LocalOutcomeRouterRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            self.prompts
                .lock()
                .expect("prompt log")
                .push(decode_studio_test_prompt(input_context));
            self.json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            self.max_tokens
                .lock()
                .expect("max tokens log")
                .push(options.max_tokens);
            Ok(serde_json::json!({
                "outcomeKind": "artifact",
                "executionStrategy": "direct_author",
                "confidence": 0.97,
                "needsClarification": false,
                "clarificationQuestions": [],
                "artifact": {
                    "renderer": "html_iframe"
                }
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
                label: "local router".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let max_tokens = Arc::new(Mutex::new(Vec::<u32>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(LocalOutcomeRouterRuntime {
        prompts: prompts.clone(),
        json_modes: json_modes.clone(),
        max_tokens: max_tokens.clone(),
    });

    let planning = plan_studio_outcome_with_runtime(
        runtime,
        "Create an interactive HTML canvas artifact that explains quantum computers",
        None,
        None,
    )
    .await
    .expect("local routing should succeed");

    assert_eq!(planning.outcome_kind, StudioOutcomeKind::Artifact);
    assert_eq!(
        planning.execution_strategy,
        StudioExecutionStrategy::DirectAuthor
    );
    assert_eq!(
        planning.artifact.expect("artifact").renderer,
        StudioRendererKind::HtmlIframe
    );
    assert!(json_modes
        .lock()
        .expect("json mode log")
        .iter()
        .all(|json_mode| !json_mode));
    assert!(max_tokens
        .lock()
        .expect("max tokens log")
        .iter()
        .all(|max_tokens| *max_tokens <= 224));
    let prompt_log = prompts.lock().expect("prompt log");
    assert_eq!(prompt_log.len(), 1);
    assert!(prompt_log[0].contains("typed outcome router for local runtimes"));
    assert!(prompt_log[0].contains("Renderer meanings:"));
    assert!(prompt_log[0].contains("JSON only."));
}

#[tokio::test(flavor = "current_thread")]
async fn local_html_brief_planner_uses_text_json_contract() {
    #[derive(Debug, Clone)]
    struct LocalBriefPlannerRuntime {
        json_modes: Arc<Mutex<Vec<bool>>>,
    }

    #[async_trait]
    impl InferenceRuntime for LocalBriefPlannerRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            self.json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            Ok(serde_json::to_string(&sample_html_brief())
                .expect("sample html brief")
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
                label: "local brief planner".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(LocalBriefPlannerRuntime {
        json_modes: json_modes.clone(),
    });
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );

    let brief = plan_studio_artifact_brief_with_runtime(
        runtime,
        "Quantum explainer",
        "Create an interactive HTML canvas artifact that explains quantum computers",
        &request,
        None,
    )
    .await
    .expect("brief planning should succeed");

    assert_eq!(brief.subject_domain, sample_html_brief().subject_domain);
    assert!(json_modes
        .lock()
        .expect("json mode log")
        .iter()
        .all(|json_mode| !json_mode));
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
