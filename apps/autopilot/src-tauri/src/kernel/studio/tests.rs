use super::content_session::studio_outcome_request_with_runtime_timeout;
use super::proof::run_studio_current_task_turn_for_proof_with_route_timeout;
use super::revisions::apply_revision_to_studio_session;
use super::*;
use crate::models::ClarificationRequest;
use crate::models::{
    StudioArtifactDeliverableShape, StudioArtifactFileRole, StudioExecutionSubstrate,
    StudioVerifiedReply,
};
use async_trait::async_trait;
use ioi_api::vm::inference::UnavailableInferenceRuntime;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
#[derive(Debug, Clone)]
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

    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        Ok(Vec::new())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SlowStudioOutcomeTestRuntime {
    payload: String,
    delay: Duration,
}

#[async_trait]
impl InferenceRuntime for SlowStudioOutcomeTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        tokio::time::sleep(self.delay).await;
        Ok(self.payload.clone().into_bytes())
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
}

fn empty_task(intent: &str) -> AgentTask {
    AgentTask {
        id: "task-1".to_string(),
        intent: intent.to_string(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 20,
        current_step: "Initializing...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("task-1".to_string()),
        credential_request: None,
        clarification_request: None,
        history: Vec::new(),
        events: Vec::new(),
        artifacts: Vec::new(),
        studio_session: None,
        studio_outcome: None,
        renderer_session: None,
        build_session: None,
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    }
}

#[test]
fn typed_outcome_router_accepts_conversation_payload() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"conversation",
              "confidence":0.81,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":null
            }"#
        .to_string(),
    });

    let planned = tauri::async_runtime::block_on(plan_studio_outcome_with_runtime(
        runtime,
        "do you like flowers?",
        None,
        None,
    ))
    .expect("typed outcome should parse");

    assert_eq!(planned.outcome_kind, StudioOutcomeKind::Conversation);
    assert!(planned.artifact.is_none());
}

#[test]
fn typed_outcome_router_accepts_workspace_artifact_payload() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioOutcomeTestRuntime {
            payload: r#"{
              "outcomeKind":"artifact",
              "confidence":0.97,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":{
                "artifactClass":"workspace_project",
                "deliverableShape":"workspace_project",
                "renderer":"workspace_surface",
                "presentationSurface":"tabbed_panel",
                "persistence":"workspace_filesystem",
                "executionSubstrate":"workspace_runtime",
                "workspaceRecipeId":"react-vite",
                "presentationVariantId":null,
                "scope":{"targetProject":"autopilot-core","createNewWorkspace":true,"mutationBoundary":["workspace"]},
                "verification":{"requireRender":true,"requireBuild":true,"requirePreview":true,"requireExport":false,"requireDiffReview":true}
              }
            }"#
            .to_string(),
        });

    let planned = tauri::async_runtime::block_on(plan_studio_outcome_with_runtime(
        runtime,
        "build a roadmap dashboard",
        None,
        None,
    ))
    .expect("workspace outcome should parse");

    assert_eq!(planned.outcome_kind, StudioOutcomeKind::Artifact);
    assert_eq!(
        planned.artifact.as_ref().map(|artifact| artifact.renderer),
        Some(StudioRendererKind::WorkspaceSurface)
    );
    assert_eq!(
        planned
            .artifact
            .as_ref()
            .and_then(|artifact| artifact.workspace_recipe_id.as_deref()),
        Some("react-vite")
    );
}

#[test]
fn typed_outcome_router_times_out_with_slow_runtime() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowStudioOutcomeTestRuntime {
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
    });

    let error = studio_outcome_request_with_runtime_timeout(
        runtime,
        "Create an interactive HTML artifact about routing timeouts",
        None,
        None,
        Duration::from_millis(5),
    )
    .expect_err("router should time out");

    assert!(error.contains("timed out"));
}

#[test]
fn materialize_nonworkspace_artifact_times_out_generation_for_slow_runtime() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowStudioOutcomeTestRuntime {
        payload: "{}".to_string(),
        delay: Duration::from_millis(50),
    });
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };

    let materialized = materialize_non_workspace_artifact_with_dependencies_and_timeout(
        &proof_memory_runtime(),
        Some(runtime.clone()),
        Some(runtime),
        "thread-1",
        "Post-quantum explainer",
        "Create an interactive HTML artifact that explains post-quantum computers",
        &request,
        None,
        Duration::from_millis(5),
    )
    .expect("materialization should return a blocked artifact");

    assert_eq!(
        materialized
            .failure
            .as_ref()
            .expect("failure")
            .kind,
        crate::models::StudioArtifactFailureKind::GenerationFailure
    );
    assert_eq!(materialized.lifecycle_state, StudioArtifactLifecycleState::Blocked);
    assert!(materialized
        .failure
        .as_ref()
        .expect("failure")
        .message
        .contains("timed out"));
    assert!(materialized.candidate_summaries.is_empty());
}

#[test]
fn manifest_generation_for_markdown_artifacts_is_renderable() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Document,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::Markdown,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::None,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };

    let manifest = artifact_manifest_for_request(
        "Release checklist",
        &request,
        &[],
        None,
        None,
        StudioArtifactLifecycleState::Ready,
    );
    assert_eq!(manifest.renderer, StudioRendererKind::Markdown);
    assert_eq!(manifest.primary_tab, "render");
    assert_eq!(manifest.tabs.len(), 3);
}

#[test]
fn static_html_recipe_materializes_real_web_files() {
    let files = static_html_template_files(
        "tennis company html page",
        "tennis-company-html-page",
        Some(StudioStaticHtmlArchetype::SportEditorial),
    );
    let file_map = files.into_iter().collect::<HashMap<_, _>>();
    assert!(file_map.contains_key("index.html"));
    assert!(file_map.contains_key("styles.css"));
    assert!(file_map.contains_key("script.js"));
    assert!(file_map
        .get("index.html")
        .is_some_and(|content| content.contains("Every point")));
}

#[test]
fn static_html_archetypes_materialize_distinct_documents() {
    let agency = static_html_template_files(
        "marketing agency html page",
        "marketing-agency-html-page",
        Some(StudioStaticHtmlArchetype::MinimalAgency),
    );
    let product = static_html_template_files(
        "ai product launch html page",
        "ai-product-launch-html-page",
        Some(StudioStaticHtmlArchetype::ProductLaunch),
    );
    let agency_index = agency
        .into_iter()
        .find(|(path, _)| path == "index.html")
        .map(|(_, content)| content)
        .unwrap_or_default();
    let product_index = product
        .into_iter()
        .find(|(path, _)| path == "index.html")
        .map(|(_, content)| content)
        .unwrap_or_default();
    assert_ne!(agency_index, product_index);
    assert!(agency_index.contains("Independent studio practice"));
    assert!(product_index.contains("New release / product system"));
}

#[test]
fn html_iframe_generation_uses_model_first_runtime() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::Inline,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: Some("product-launch".to_string()),
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };

    let payload = generate_non_workspace_artifact_payload(
            "Dog shampoo rollout explainer",
            "Create an interactive HTML artifact that explains a product rollout with charts for dog shampoo",
            &request,
            Some(Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime)),
        )
        .expect("model-first html payload");

    assert_eq!(payload.files.len(), 1);
    assert!(payload.files[0]
        .body
        .contains("<!-- studio-section:chart -->"));
    assert!(!payload.files[0].body.contains("studio-rollout-briefing"));
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("patch-first refinements")));
}

#[test]
fn model_first_html_iframe_payload_clears_presentation_gate() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::Inline,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: Some("product-launch".to_string()),
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };

    let payload = generate_non_workspace_artifact_payload(
            "Dog shampoo rollout explainer",
            "Create an interactive HTML artifact that explains a product rollout with charts for dog shampoo",
            &request,
            Some(Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime)),
        )
        .expect("model-first html payload");
    let assessment =
        assess_materialized_artifact_presentation(&request, &generated_quality_files(&payload));

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
}

#[test]
fn html_generation_failure_blocks_primary_artifact_without_deterministic_fallback() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::Inline,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: Some("product-launch".to_string()),
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };

    let blocked = blocked_materialized_artifact_from_error(
            "Productivity assistant rollout",
            "Create an interactive HTML artifact that explains a product rollout with charts for a productivity assistant",
            &request,
            None,
            "simulated studio materialization failure",
            None,
            None,
            Vec::new(),
            Some(crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::OpaqueRuntime,
                label: "opaque test runtime".to_string(),
                model: None,
                endpoint: None,
            }),
            Some(crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            }),
        );

    assert!(!blocked.fallback_used);
    assert_eq!(
        blocked.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert_eq!(
        blocked.judge.as_ref().expect("judge result").classification,
        ioi_api::studio::StudioArtifactJudgeClassification::Blocked
    );
    assert_eq!(
        blocked.output_origin,
        StudioArtifactOutputOrigin::OpaqueRuntime
    );
    assert_eq!(
        blocked.failure.as_ref().expect("failure envelope").code,
        "inference_unavailable"
    );
    assert_eq!(
        blocked
            .production_provenance
            .as_ref()
            .expect("production provenance")
            .kind,
        crate::models::StudioRuntimeProvenanceKind::OpaqueRuntime
    );
    assert_eq!(
        blocked
            .acceptance_provenance
            .as_ref()
            .expect("acceptance provenance")
            .kind,
        crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
    );
    assert_eq!(blocked.files.len(), 0);
    assert_eq!(
        blocked.brief.subject_domain,
        "Productivity assistant rollout"
    );
    assert_eq!(
        blocked
            .judge
            .as_ref()
            .expect("judge result")
            .deserves_primary_artifact_view,
        false
    );
    assert!(blocked.notes.iter().any(|note: &String| {
        note.contains("refused to substitute mock or deterministic output")
    }));
}

#[test]
fn attach_blocked_failure_session_surfaces_inference_unavailable() {
    let prompt = "Create an interactive HTML artifact for a launch story";
    let mut task = empty_task(prompt);
    attach_blocked_studio_failure_session(
        &mut task,
        prompt,
        None,
        crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        },
        crate::models::StudioArtifactFailure {
            kind: crate::models::StudioArtifactFailureKind::InferenceUnavailable,
            code: "inference_unavailable".to_string(),
            message: "Local inference runtime is offline.".to_string(),
        },
    );
    let studio_session = task.studio_session.expect("studio session");

    assert_eq!(
        studio_session.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert_eq!(
        studio_session.artifact_manifest.verification.status,
        StudioArtifactVerificationStatus::Blocked
    );
    assert_eq!(
        studio_session
            .artifact_manifest
            .verification
            .production_provenance
            .as_ref()
            .expect("production provenance")
            .kind,
        crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
    );
    assert_eq!(
        studio_session
            .artifact_manifest
            .verification
            .failure
            .as_ref()
            .expect("failure")
            .code,
        "inference_unavailable"
    );
    assert_eq!(studio_session.artifact_manifest.files.len(), 0);
    assert!(studio_session
        .verified_reply
        .evidence
        .join("\n")
        .contains("inference_unavailable"));
}

#[test]
fn pipeline_steps_for_ready_markdown_artifact_are_complete() {
    let request = test_outcome_request().artifact.expect("artifact request");
    let manifest = test_manifest(StudioArtifactVerificationStatus::Ready);
    let materialization = materialization_contract_for_request(
        "Create a release artifact",
        &request,
        "Studio created the artifact.",
    );
    let steps = pipeline_steps_for_state(
        "Create a release artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Ready,
        None,
    );

    assert_eq!(steps.len(), 9);
    assert!(steps.iter().all(|step| step.status == "complete"));
}

#[test]
fn pipeline_steps_for_workspace_wait_for_verified_preview() {
    let request = test_workspace_request();
    let mut manifest = artifact_manifest_for_request(
        "Workspace artifact",
        &request,
        &["artifact-1".to_string()],
        None,
        None,
        StudioArtifactLifecycleState::Materializing,
    );
    manifest.primary_tab = "workspace".to_string();
    let mut materialization = materialization_contract_for_request(
        "Build a workspace artifact",
        &request,
        "Studio provisioned the workspace artifact.",
    );
    materialization
        .file_writes
        .push(StudioArtifactMaterializationFileWrite {
            path: "src/App.tsx".to_string(),
            kind: "create".to_string(),
            content_preview: Some("export default function App() {}".to_string()),
        });

    let pending_steps = pipeline_steps_for_state(
        "Build a workspace artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Materializing,
        Some(&test_build_session("scaffolded", "pending")),
    );
    let presentation = pending_steps
        .iter()
        .find(|step| step.id == "presentation")
        .expect("presentation step");
    assert_eq!(presentation.status, "pending");

    let mut ready_build = test_build_session("preview-ready", "passed");
    ready_build.preview_url = Some("http://127.0.0.1:4173".to_string());
    ready_build.ready_lenses = vec!["preview".to_string(), "workspace".to_string()];
    ready_build.receipts.push(StudioBuildReceipt {
        receipt_id: "receipt-1".to_string(),
        kind: "preview".to_string(),
        title: "Verify preview".to_string(),
        status: "success".to_string(),
        summary: "Preview responded successfully.".to_string(),
        started_at: now_iso(),
        finished_at: Some(now_iso()),
        artifact_ids: Vec::new(),
        command: Some("npm run preview".to_string()),
        exit_code: Some(0),
        duration_ms: Some(10),
        failure_class: None,
        replay_classification: Some("replay_safe".to_string()),
    });
    manifest.primary_tab = "preview".to_string();
    manifest.verification = StudioArtifactManifestVerification {
        status: StudioArtifactVerificationStatus::Ready,
        lifecycle_state: StudioArtifactLifecycleState::Ready,
        summary: "Preview verified and workspace lenses are ready.".to_string(),
        production_provenance: None,
        acceptance_provenance: None,
        failure: None,
    };
    let ready_steps = pipeline_steps_for_state(
        "Build a workspace artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Ready,
        Some(&ready_build),
    );
    let ready_presentation = ready_steps
        .iter()
        .find(|step| step.id == "presentation")
        .expect("presentation step");
    assert_eq!(ready_presentation.status, "complete");
}

#[test]
fn preview_launch_command_prefers_project_vite_entrypoint() {
    let workspace_root =
        std::env::temp_dir().join(format!("ioi-preview-command-{}", Uuid::new_v4()));
    let vite_bin_dir = workspace_root.join("node_modules").join("vite").join("bin");
    fs::create_dir_all(&vite_bin_dir).expect("create vite bin dir");
    fs::write(vite_bin_dir.join("vite.js"), "console.log('vite');").expect("write vite entry");

    let command = preview_launch_command(&workspace_root, 4173);

    assert_eq!(command.program, PathBuf::from("node"));
    assert_eq!(
        command.args.first().expect("vite entry"),
        &vite_bin_dir.join("vite.js").display().to_string()
    );
    assert_eq!(
        command.args[1..],
        [
            "preview".to_string(),
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "4173".to_string(),
        ]
    );
    assert!(command.display.contains("node"));
    assert!(command.display.contains("vite.js"));

    let _ = fs::remove_dir_all(workspace_root);
}

fn test_outcome_request() -> StudioOutcomeRequest {
    StudioOutcomeRequest {
        request_id: "request-1".to_string(),
        raw_prompt: "Create a release artifact".to_string(),
        active_artifact_id: None,
        outcome_kind: StudioOutcomeKind::Artifact,
        confidence: 0.98,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: Some(StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::Document,
            deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
            renderer: StudioRendererKind::Markdown,
            presentation_surface: StudioPresentationSurface::SidePanel,
            persistence: StudioArtifactPersistenceMode::ArtifactScoped,
            execution_substrate: StudioExecutionSubstrate::None,
            workspace_recipe_id: None,
            presentation_variant_id: None,
            scope: crate::models::StudioOutcomeArtifactScope {
                target_project: None,
                create_new_workspace: false,
                mutation_boundary: vec!["artifact".to_string()],
            },
            verification: crate::models::StudioOutcomeArtifactVerificationRequest {
                require_render: true,
                require_build: false,
                require_preview: false,
                require_export: true,
                require_diff_review: false,
            },
        }),
    }
}

fn test_materialization_contract() -> StudioArtifactMaterializationContract {
    StudioArtifactMaterializationContract {
        version: 1,
        request_kind: "artifact".to_string(),
        normalized_intent: "Create a release artifact".to_string(),
        summary: "Studio created an artifact.".to_string(),
        artifact_brief: None,
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        judge: None,
        output_origin: None,
        production_provenance: None,
        acceptance_provenance: None,
        fallback_used: false,
        ux_lifecycle: None,
        failure: None,
        navigator_nodes: Vec::new(),
        file_writes: Vec::new(),
        command_intents: Vec::new(),
        preview_intent: None,
        verification_steps: Vec::new(),
        pipeline_steps: Vec::new(),
        notes: Vec::new(),
    }
}

fn test_workspace_request() -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::WorkspaceProject,
        deliverable_shape: StudioArtifactDeliverableShape::WorkspaceProject,
        renderer: StudioRendererKind::WorkspaceSurface,
        presentation_surface: StudioPresentationSurface::TabbedPanel,
        persistence: StudioArtifactPersistenceMode::WorkspaceFilesystem,
        execution_substrate: StudioExecutionSubstrate::WorkspaceRuntime,
        workspace_recipe_id: Some("react-vite".to_string()),
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: Some("autopilot".to_string()),
            create_new_workspace: true,
            mutation_boundary: vec!["workspace".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: true,
            require_preview: true,
            require_export: false,
            require_diff_review: true,
        },
    }
}

fn test_manifest(status: StudioArtifactVerificationStatus) -> StudioArtifactManifest {
    StudioArtifactManifest {
        artifact_id: "artifact-1".to_string(),
        title: "Release artifact".to_string(),
        artifact_class: StudioArtifactClass::Document,
        renderer: StudioRendererKind::Markdown,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::Markdown),
            file_path: Some("artifact.md".to_string()),
            lens: Some("render".to_string()),
        }],
        files: vec![StudioArtifactManifestFile {
            path: "artifact.md".to_string(),
            mime: "text/markdown".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: Some("artifact-1".to_string()),
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status,
            lifecycle_state: if status == StudioArtifactVerificationStatus::Ready {
                StudioArtifactLifecycleState::Ready
            } else if status == StudioArtifactVerificationStatus::Failed {
                StudioArtifactLifecycleState::Failed
            } else if status == StudioArtifactVerificationStatus::Partial {
                StudioArtifactLifecycleState::Partial
            } else {
                StudioArtifactLifecycleState::Blocked
            },
            summary: "Studio verified the artifact.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    }
}

fn test_studio_session(status: StudioArtifactVerificationStatus) -> StudioArtifactSession {
    StudioArtifactSession {
        session_id: "studio-session-1".to_string(),
        thread_id: "thread-1".to_string(),
        artifact_id: "artifact-1".to_string(),
        title: "Release artifact".to_string(),
        summary: "Studio created a release artifact.".to_string(),
        current_lens: "render".to_string(),
        navigator_backing_mode: "artifact".to_string(),
        navigator_nodes: Vec::new(),
        attached_artifact_ids: vec!["artifact-1".to_string()],
        available_lenses: vec!["render".to_string(), "source".to_string()],
        materialization: test_materialization_contract(),
        outcome_request: test_outcome_request(),
        artifact_manifest: test_manifest(status),
        verified_reply: StudioVerifiedReply {
            status,
            lifecycle_state: if status == StudioArtifactVerificationStatus::Ready {
                StudioArtifactLifecycleState::Ready
            } else if status == StudioArtifactVerificationStatus::Failed {
                StudioArtifactLifecycleState::Failed
            } else if status == StudioArtifactVerificationStatus::Partial {
                StudioArtifactLifecycleState::Partial
            } else {
                StudioArtifactLifecycleState::Blocked
            },
            title: "Studio outcome: Release artifact".to_string(),
            summary: "Release artifact Studio verified the artifact.".to_string(),
            evidence: vec!["artifact.md".to_string()],
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
            updated_at: now_iso(),
        },
        lifecycle_state: if status == StudioArtifactVerificationStatus::Ready {
            StudioArtifactLifecycleState::Ready
        } else if status == StudioArtifactVerificationStatus::Failed {
            StudioArtifactLifecycleState::Failed
        } else if status == StudioArtifactVerificationStatus::Partial {
            StudioArtifactLifecycleState::Partial
        } else {
            StudioArtifactLifecycleState::Blocked
        },
        status: if status == StudioArtifactVerificationStatus::Failed {
            "failed".to_string()
        } else {
            "ready".to_string()
        },
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        selected_targets: Vec::new(),
        ux_lifecycle: None,
        created_at: now_iso(),
        updated_at: now_iso(),
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    }
}

fn test_selection_target() -> StudioArtifactSelectionTarget {
    StudioArtifactSelectionTarget {
        source_surface: "render".to_string(),
        path: Some("index.html".to_string()),
        label: "Chart section".to_string(),
        snippet: "Adoption by channel".to_string(),
    }
}

fn proof_memory_runtime() -> Arc<MemoryRuntime> {
    let path = std::env::temp_dir().join(format!("ioi-studio-proof-test-{}.db", Uuid::new_v4()));
    let runtime = Arc::new(MemoryRuntime::open_sqlite(&path).expect("memory runtime"));
    let _ = fs::remove_file(path);
    runtime
}

fn test_build_session(status: &str, verification_status: &str) -> BuildArtifactSession {
    BuildArtifactSession {
        session_id: "build-1".to_string(),
        studio_session_id: "studio-session-1".to_string(),
        workspace_root: "/tmp/studio".to_string(),
        entry_document: "src/App.tsx".to_string(),
        preview_url: None,
        preview_process_id: None,
        scaffold_recipe_id: "react-vite".to_string(),
        presentation_variant_id: None,
        package_manager: "npm".to_string(),
        build_status: status.to_string(),
        verification_status: verification_status.to_string(),
        receipts: Vec::new(),
        current_worker_execution: StudioCodeWorkerLease {
            backend: "hosted-fallback".to_string(),
            planner_authority: "studio".to_string(),
            allowed_mutation_scope: vec!["workspace".to_string()],
            allowed_command_classes: vec!["install".to_string(), "build".to_string()],
            execution_state: "running".to_string(),
            retry_classification: None,
            last_summary: None,
        },
        current_lens: "workspace".to_string(),
        available_lenses: vec!["workspace".to_string(), "evidence".to_string()],
        ready_lenses: vec!["workspace".to_string()],
        retry_count: 0,
        last_failure_summary: None,
    }
}

#[test]
fn derive_studio_taste_memory_accumulates_unique_directives() {
    let prior = StudioArtifactTasteMemory {
        directives: vec!["enterprise".to_string(), "calm".to_string()],
        summary: "Prior taste memory".to_string(),
    };
    let brief = StudioArtifactBrief {
        audience: "Platform operators".to_string(),
        job_to_be_done: "Explain rollout status".to_string(),
        subject_domain: "Instacart MCP".to_string(),
        artifact_thesis: "Show launch readiness by lane.".to_string(),
        required_concepts: Vec::new(),
        required_interactions: Vec::new(),
        visual_tone: vec!["enterprise".to_string(), "technical".to_string()],
        factual_anchors: Vec::new(),
        style_directives: vec!["grid-led".to_string()],
        reference_hints: Vec::new(),
    };
    let edit_intent = StudioArtifactEditIntent {
        mode: StudioArtifactEditMode::Patch,
        summary: "Patch the chart section.".to_string(),
        patch_existing_artifact: true,
        preserve_structure: true,
        target_scope: "chart".to_string(),
        target_paths: vec!["index.html".to_string()],
        requested_operations: vec!["change_chart_metric_adoption_by_channel".to_string()],
        tone_directives: vec!["technical".to_string(), "confident".to_string()],
        selected_targets: vec![test_selection_target()],
        style_directives: vec!["tight hierarchy".to_string()],
        branch_requested: false,
    };

    let taste_memory =
        derive_studio_taste_memory(Some(&prior), &brief, Some(&edit_intent)).expect("taste memory");

    assert_eq!(
        taste_memory.directives,
        vec![
            "enterprise".to_string(),
            "calm".to_string(),
            "technical".to_string(),
            "grid-led".to_string(),
            "confident".to_string(),
            "tight hierarchy".to_string(),
        ]
    );
}

#[test]
fn revision_branch_identity_allocates_new_branch_when_requested() {
    let mut studio_session = test_studio_session(StudioArtifactVerificationStatus::Ready);
    let base_revision = initial_revision_for_session(&studio_session, "Create the artifact");
    studio_session.active_revision_id = Some(base_revision.revision_id.clone());
    studio_session.revisions = vec![base_revision.clone()];
    let edit_intent = StudioArtifactEditIntent {
        mode: StudioArtifactEditMode::Branch,
        summary: "Branch this revision.".to_string(),
        patch_existing_artifact: true,
        preserve_structure: true,
        target_scope: "artifact".to_string(),
        target_paths: Vec::new(),
        requested_operations: vec!["branch_current_artifact".to_string()],
        tone_directives: Vec::new(),
        selected_targets: Vec::new(),
        style_directives: Vec::new(),
        branch_requested: true,
    };

    let (branch_id, branch_label, parent_revision_id) =
        revision_branch_identity(&studio_session, Some(&edit_intent));

    assert_eq!(branch_id, "branch-1");
    assert_eq!(branch_label, "Branch 1");
    assert_eq!(parent_revision_id, Some(base_revision.revision_id));
}

#[test]
fn apply_revision_to_studio_session_restores_manifest_and_selection() {
    let mut studio_session = test_studio_session(StudioArtifactVerificationStatus::Ready);
    studio_session.selected_targets = vec![test_selection_target()];
    let mut restored_revision = initial_revision_for_session(&studio_session, "Create artifact");
    restored_revision.revision_id = "revision-2".to_string();
    restored_revision.artifact_manifest.title = "Restored artifact".to_string();
    restored_revision.artifact_manifest.files = vec![StudioArtifactManifestFile {
        path: "restored.md".to_string(),
        mime: "text/markdown".to_string(),
        role: StudioArtifactFileRole::Primary,
        renderable: true,
        downloadable: true,
        artifact_id: Some("artifact-restored".to_string()),
        external_url: None,
    }];
    restored_revision.selected_targets = vec![StudioArtifactSelectionTarget {
        source_surface: "source".to_string(),
        path: Some("restored.md".to_string()),
        label: "Restored section".to_string(),
        snippet: "Keep this structure".to_string(),
    }];

    apply_revision_to_studio_session(&mut studio_session, &restored_revision);

    assert_eq!(studio_session.title, "Restored artifact");
    assert_eq!(
        studio_session.artifact_manifest.files[0].path,
        "restored.md"
    );
    assert_eq!(studio_session.selected_targets[0].label, "Restored section");
    assert_eq!(
        studio_session.active_revision_id,
        Some("revision-2".to_string())
    );
}

#[test]
fn revision_compare_detects_blob_changes_beyond_shared_preview_prefix() {
    let runtime = proof_memory_runtime();
    let thread_key = [7_u8; 32];
    let shared_prefix = format!("<!doctype html><html><body>{}", "A".repeat(180));
    let base_body = format!("{shared_prefix}baseline</body></html>");
    let refined_body = format!("{shared_prefix}technical-detail</body></html>");
    runtime
        .put_artifact_blob(thread_key, "artifact-base", base_body.as_bytes())
        .expect("base blob");
    runtime
        .put_artifact_blob(thread_key, "artifact-refined", refined_body.as_bytes())
        .expect("refined blob");

    let mut studio_session = test_studio_session(StudioArtifactVerificationStatus::Ready);
    studio_session.artifact_manifest.renderer = StudioRendererKind::HtmlIframe;
    studio_session.artifact_manifest.files = vec![StudioArtifactManifestFile {
        path: "index.html".to_string(),
        mime: "text/html".to_string(),
        role: StudioArtifactFileRole::Primary,
        renderable: true,
        downloadable: true,
        artifact_id: Some("artifact-base".to_string()),
        external_url: None,
    }];

    let preview = shared_prefix[..120].to_string();
    let mut base_revision = initial_revision_for_session(&studio_session, "Create artifact");
    base_revision.file_writes = vec![StudioArtifactMaterializationFileWrite {
        path: "index.html".to_string(),
        kind: "write".to_string(),
        content_preview: Some(preview.clone()),
    }];

    let mut refined_revision = base_revision.clone();
    refined_revision.revision_id = "revision-2".to_string();
    refined_revision.artifact_manifest.files[0].artifact_id = Some("artifact-refined".to_string());
    refined_revision.file_writes = vec![StudioArtifactMaterializationFileWrite {
        path: "index.html".to_string(),
        kind: "write".to_string(),
        content_preview: Some(preview),
    }];

    let changed_paths =
        changed_paths_between_revisions(&base_revision, &refined_revision, Some(&runtime));
    assert_eq!(changed_paths, vec!["index.html".to_string()]);
}

fn test_task(status: StudioArtifactVerificationStatus) -> AgentTask {
    AgentTask {
        id: "task-1".to_string(),
        intent: "Create a release artifact".to_string(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 20,
        current_step: "Initializing...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("task-1".to_string()),
        credential_request: None,
        clarification_request: None,
        history: Vec::new(),
        events: Vec::new(),
        artifacts: Vec::new(),
        studio_session: Some(test_studio_session(status)),
        studio_outcome: Some(test_outcome_request()),
        renderer_session: None,
        build_session: None,
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    }
}

#[test]
fn authoritative_studio_artifact_marks_task_complete_without_kernel_session() {
    let mut task = test_task(StudioArtifactVerificationStatus::Ready);
    assert!(task_is_studio_authoritative(&task));

    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Studio verified the artifact and is ready for the next request."
    );
}

#[test]
fn authoritative_workspace_artifact_stays_running_until_verification_passes() {
    let mut task = test_task(StudioArtifactVerificationStatus::Blocked);
    task.build_session = Some(test_build_session("preview-starting", "pending"));

    apply_studio_authoritative_status(&mut task, None);
    assert_eq!(task.phase, AgentPhase::Running);

    task.build_session = Some(test_build_session("preview-ready", "passed"));
    apply_studio_authoritative_status(&mut task, None);
    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(task.current_step, "Studio workspace renderer verified.");
}

#[test]
fn blocked_nonworkspace_artifact_marks_task_failed_without_clarification() {
    let mut task = test_task(StudioArtifactVerificationStatus::Blocked);
    task.studio_session
        .as_mut()
        .expect("studio session")
        .artifact_manifest
        .verification
        .failure = Some(StudioArtifactFailure {
        kind: StudioArtifactFailureKind::RoutingFailure,
        code: "routing_failure".to_string(),
        message: "Studio outcome planning timed out after 45s while routing the request."
            .to_string(),
    });

    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Failed);
    assert_eq!(
        task.current_step,
        "Studio outcome planning timed out after 45s while routing the request."
    );
}

#[test]
fn blocked_nonworkspace_artifact_allows_clarification_without_running_spinner() {
    let mut task = test_task(StudioArtifactVerificationStatus::Blocked);
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

    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Studio is waiting for clarification before it can materialize a usable artifact."
    );
}

#[test]
fn current_task_turn_surfaces_inference_unavailable_as_blocked_studio_session() {
    let prompt = "Create an interactive HTML artifact that explains a product rollout with charts";
    let mut task = empty_task(prompt);
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(UnavailableInferenceRuntime::new(
        "Inference is unavailable because no Studio runtime is configured.",
    ));
    let workspace_root_base =
        std::env::temp_dir().join(format!("ioi-studio-proof-workspaces-{}", Uuid::new_v4()));
    fs::create_dir_all(&workspace_root_base).expect("workspace root");

    run_studio_current_task_turn_for_proof(
        &mut task,
        prompt,
        proof_memory_runtime(),
        runtime.clone(),
        runtime,
        &workspace_root_base,
    )
    .expect("proof turn");

    let studio_session = task.studio_session.expect("studio session");
    assert_eq!(
        studio_session.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert_eq!(
        studio_session
            .artifact_manifest
            .verification
            .production_provenance
            .as_ref()
            .expect("provenance")
            .kind,
        crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable
    );
    assert_eq!(
        studio_session
            .artifact_manifest
            .verification
            .failure
            .as_ref()
            .expect("failure")
            .code,
        "inference_unavailable"
    );
    assert!(studio_session.artifact_manifest.files.is_empty());
    let _ = fs::remove_dir_all(workspace_root_base);
}

#[test]
fn current_task_turn_surfaces_routing_timeouts_as_blocked_studio_session() {
    let prompt = "Create an interactive HTML artifact that explains a product rollout with charts";
    let mut task = empty_task(prompt);
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowStudioOutcomeTestRuntime {
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
    });
    let workspace_root_base =
        std::env::temp_dir().join(format!("ioi-studio-proof-workspaces-{}", Uuid::new_v4()));
    fs::create_dir_all(&workspace_root_base).expect("workspace root");

    run_studio_current_task_turn_for_proof_with_route_timeout(
        &mut task,
        prompt,
        proof_memory_runtime(),
        runtime.clone(),
        runtime,
        &workspace_root_base,
        Duration::from_millis(5),
    )
    .expect("proof turn");

    let studio_session = task.studio_session.expect("studio session");
    assert_eq!(
        studio_session.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert_eq!(
        studio_session
            .artifact_manifest
            .verification
            .failure
            .as_ref()
            .expect("failure")
            .code,
        "routing_failure"
    );
    assert!(studio_session
        .artifact_manifest
        .verification
        .failure
        .as_ref()
        .expect("failure")
        .message
        .contains("timed out"));
    assert!(studio_session.artifact_manifest.files.is_empty());
    let _ = fs::remove_dir_all(workspace_root_base);
}

#[test]
fn current_task_turn_surfaces_non_artifact_routes_as_blocked_proof_sessions() {
    let prompt = "Create an interactive HTML artifact for an AI tools editorial launch page";
    let mut task = empty_task(prompt);
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioOutcomeTestRuntime {
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
        std::env::temp_dir().join(format!("ioi-studio-proof-workspaces-{}", Uuid::new_v4()));
    fs::create_dir_all(&workspace_root_base).expect("workspace root");

    run_studio_current_task_turn_for_proof(
        &mut task,
        prompt,
        proof_memory_runtime(),
        runtime.clone(),
        runtime,
        &workspace_root_base,
    )
    .expect("proof turn");

    let studio_session = task.studio_session.expect("studio session");
    assert_eq!(
        studio_session.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert_eq!(
        studio_session
            .artifact_manifest
            .verification
            .failure
            .as_ref()
            .expect("failure")
            .code,
        "routing_failure"
    );
    assert_eq!(
        studio_session
            .artifact_manifest
            .verification
            .failure
            .as_ref()
            .expect("failure")
            .kind,
        crate::models::StudioArtifactFailureKind::RoutingFailure
    );
    assert!(studio_session
        .artifact_manifest
        .verification
        .summary
        .contains("conversation instead of artifact materialization"));
    let _ = fs::remove_dir_all(workspace_root_base);
}

#[test]
fn partial_nonworkspace_artifact_marks_task_complete() {
    let mut task = test_task(StudioArtifactVerificationStatus::Partial);

    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Studio partially materialized the requested artifact and needs follow-up verification."
    );
}

#[test]
fn weak_html_artifact_is_downgraded_to_blocked() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><body><main><section><h1>Placeholder</h1><p>Coming soon.</p></section></main></body></html>"
                        .to_string(),
                ),
            }],
        );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(assessment.summary.contains("blocked"));
}

#[test]
fn acceptance_judge_promotes_soft_html_prefilter_findings_to_ready() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing, adoption by channel, partner enablement, and retailer milestones stay visible in this interactive rollout page.</p></section><section><h2>Why now</h2><p>The story focuses on channel readiness, store education, and repeat-purchase lift without falling back to a generic shell.</p></section></main></body></html>"
                        .to_string(),
                ),
            }],
        );
    let promoted = finalize_presentation_assessment(
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Pass,
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
            strongest_contradiction: None,
            rationale: "acceptance cleared the artifact".to_string(),
        },
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
    assert!(promoted.summary.contains("acceptance judging cleared"));
}

#[test]
fn mermaid_prefilter_does_not_block_valid_compact_diagram_documents() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Visual,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::Mermaid,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "approval_pipeline.mermaid".to_string(),
            mime: "text/plain".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "graph TD\n    A[Request] --> B[Review]\n    B --> C[Decision]\n    C --> D[Final Approval]\n"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
}

#[test]
fn repairable_acceptance_judge_keeps_html_out_of_ready_state() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><head><style>body { font-family: 'Avenir Next', sans-serif; background: #f6f1e7; color: #1b1a17; } main { display: grid; gap: 1.5rem; padding: 2rem; } .hero, .grid, .evidence, footer { background: #fffdf8; border: 1px solid #d5c7ad; border-radius: 20px; padding: 1.25rem; } .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; } .metric { background: #f0e2c8; border-radius: 14px; padding: 0.85rem; }</style></head><body><main><section class=\"hero\"><h1>Dog shampoo rollout command center</h1><p>The launch page keeps merchandisers, veterinary advisers, and regional channel leads aligned on the first four weeks of the dog shampoo launch. A compact narrative explains the gentle skin positioning, fragrance-free formula, and retail education plan so the first visible artifact already feels like a real launch surface instead of a placeholder shell.</p><p>Operators can compare mass retail, ecommerce, and boutique pet-store readiness without leaving the page, then use the follow-up refinement pass to deepen ingredient and pH evidence.</p></section><section class=\"grid\"><article class=\"metric\"><h2>Mass Retail</h2><p>Floor sets complete in 81% of target doors, with sampling carts scheduled for the highest-volume weekend windows.</p></article><article class=\"metric\"><h2>Ecommerce</h2><p>Subscription attach is pacing above plan because the bundle pairs the shampoo with a coat brush and refill reminder.</p></article><article class=\"metric\"><h2>Boutique</h2><p>Independent stores are asking for more shelf talkers and a clearer ingredient story before launch week.</p></article></section><article class=\"evidence\"><h2>Launch evidence rail</h2><p>Retail readiness notes, customer language, and merchandising checkpoints stay visible together so the surface can support real refinement decisions. Teams can inspect the copy, compare channels, and extend the page with more charts in the next judged revision.</p><button type=\"button\">Inspect rollout detail</button></article><aside><p>Readiness evidence remains visible beside the command surface so approval notes do not drift away from the rendered artifact.</p></aside><footer><p>Current gap: ingredient and pH comparison charts still need a dedicated visual treatment.</p></footer></main></body></html>"
                        .to_string(),
                ),
            }],
        );
    let promoted = finalize_presentation_assessment(
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Repairable,
            request_faithfulness: 4,
            concept_coverage: 3,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness: 4,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            strongest_contradiction: Some(
                "Missing ingredient analysis and pH level charts".to_string(),
            ),
            rationale: "Needs another refinement pass.".to_string(),
        },
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(promoted.summary.contains("kept it out of the primary view"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("Missing ingredient analysis")));
}

#[test]
fn draft_pending_acceptance_surfaces_viable_html_as_partial() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
        &request,
        &[MaterializedArtifactQualityFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            renderable: true,
            downloadable: true,
            text_content: Some(
                "<!doctype html><html><head><style>body { font-family: 'Avenir Next', sans-serif; background: #f6f1e7; color: #1b1a17; } main { display: grid; gap: 1.5rem; padding: 2rem; } .hero, .grid, .evidence, footer { background: #fffdf8; border: 1px solid #d5c7ad; border-radius: 20px; padding: 1.25rem; } .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; } .metric { background: #f0e2c8; border-radius: 14px; padding: 0.85rem; }</style></head><body><main><section class=\"hero\"><h1>Dog shampoo rollout command center</h1><p>The launch page keeps merchandisers, veterinary advisers, and regional channel leads aligned on the first four weeks of the dog shampoo launch. A compact narrative explains the gentle skin positioning, fragrance-free formula, and retail education plan so the first visible artifact already feels like a real launch surface instead of a placeholder shell.</p><p>Operators can compare mass retail, ecommerce, and boutique pet-store readiness without leaving the page, then use the follow-up refinement pass to deepen ingredient and pH evidence.</p></section><section class=\"grid\"><article class=\"metric\"><h2>Mass Retail</h2><p>Floor sets complete in 81% of target doors, with sampling carts scheduled for the highest-volume weekend windows.</p></article><article class=\"metric\"><h2>Ecommerce</h2><p>Subscription attach is pacing above plan because the bundle pairs the shampoo with a coat brush and refill reminder.</p></article><article class=\"metric\"><h2>Boutique</h2><p>Independent stores are asking for more shelf talkers and a clearer ingredient story before launch week.</p></article></section><article class=\"evidence\"><h2>Launch evidence rail</h2><p>Retail readiness notes, customer language, and merchandising checkpoints stay visible together so the surface can support real refinement decisions. Teams can inspect the copy, compare channels, and extend the page with more charts in the next judged revision.</p><button type=\"button\">Inspect rollout detail</button></article><aside><p>Readiness evidence remains visible beside the command surface so approval notes do not drift away from the rendered artifact.</p></aside><footer><p>Current gap: ingredient and pH comparison charts still need a dedicated visual treatment.</p></footer></main></body></html>"
                    .to_string(),
            ),
        }],
    );
    let promoted = finalize_presentation_assessment(
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Repairable,
            request_faithfulness: 4,
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
            strongest_contradiction: Some(
                "Acceptance judging is still pending for this draft.".to_string(),
            ),
            rationale: "Production surfaced a request-faithful draft.".to_string(),
        },
        false,
        true,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(promoted.summary.contains("request-faithful draft"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("Acceptance judging is still pending")));
}

#[test]
fn external_runtime_dependency_keeps_html_prefilter_blocked() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let assessment = assess_materialized_artifact_presentation(
            &request,
            &[MaterializedArtifactQualityFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                renderable: true,
                downloadable: true,
                text_content: Some(
                    "<!doctype html><html><body><main><section><h1>Instacart MCP rollout</h1><button type=\"button\">Inspect</button></section><article><svg id=\"chart\"></svg></article><aside><p>Timeline</p></aside><footer><script>const chart = d3.select('#chart');</script></footer></main></body></html>"
                        .to_string(),
                ),
            }],
        );
    let promoted = finalize_presentation_assessment(
        assessment,
        &StudioArtifactJudgeResult {
            classification: ioi_api::studio::StudioArtifactJudgeClassification::Pass,
            request_faithfulness: 5,
            concept_coverage: 5,
            interaction_relevance: 5,
            layout_coherence: 5,
            visual_hierarchy: 5,
            completeness: 5,
            generic_shell_detected: false,
            trivial_shell_detected: false,
            deserves_primary_artifact_view: true,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            strongest_contradiction: None,
            rationale: "acceptance liked the artifact".to_string(),
        },
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(promoted
        .summary
        .contains("blocked the primary presentation"));
}

#[test]
fn pdf_artifact_bytes_include_document_body() {
    let pdf = pdf_artifact_bytes(
            "Launch brief",
            "Executive summary\n\nThis launch brief includes the goals, rollout plan, owner table, and verification notes for the artifact stage.",
        );
    let pdf_text = String::from_utf8_lossy(&pdf);

    assert!(pdf_text.contains("Launch brief"));
    assert!(pdf_text.contains("Executive summary"));
    assert!(pdf.starts_with(b"%PDF-"));
}
