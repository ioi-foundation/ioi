use super::content_session::{
    apply_materialized_artifact_to_contract, studio_outcome_request_with_runtime_timeout,
    verification_steps_for_materialized_artifact,
};
use super::proof::run_studio_current_task_turn_for_proof_with_route_timeout;
use super::revisions::{
    apply_revision_to_studio_session, studio_artifact_exemplar_from_archival_record,
    STUDIO_ARTIFACT_EXEMPLAR_SCOPE,
};
use super::*;
use crate::models::ClarificationRequest;
use crate::models::{
    StudioArtifactDeliverableShape, StudioArtifactFileRole, StudioExecutionSubstrate,
    StudioVerifiedReply,
};
use async_trait::async_trait;
use ioi_api::studio::{
    compile_studio_artifact_ir, derive_studio_artifact_blueprint, ExecutionStage,
    StudioArtifactBrief, StudioArtifactExemplar, StudioArtifactMergeReceipt,
    StudioArtifactPatchReceipt, StudioArtifactRenderCapture, StudioArtifactRenderCaptureViewport,
    StudioArtifactRenderEvaluation, StudioArtifactRenderEvaluator, StudioArtifactRenderFinding,
    StudioArtifactRenderFindingSeverity, StudioArtifactSwarmExecutionSummary,
    StudioArtifactSwarmPlan, StudioArtifactVerificationReceipt, StudioArtifactWorkItem,
    StudioArtifactWorkItemStatus, StudioArtifactWorkerReceipt, StudioArtifactWorkerRole,
    StudioGeneratedArtifactFile, StudioGeneratedArtifactPayload,
};
use ioi_api::vm::inference::UnavailableInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::studio_render::BrowserStudioArtifactRenderEvaluator;
use ioi_memory::{ArchivalMemoryRecord, MemoryRuntime};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::StudioExecutionStrategy;
use ioi_types::error::VmError;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;

mod pipeline;
mod routing;

fn instrument_html_for_headless_validation(html: &str) -> String {
    let instrumentation_script = r#"<script data-studio-validation-probe="true">
window.addEventListener("error", (event) => {
  const root = document.documentElement;
  root.setAttribute("data-studio-validation-error", "true");
  root.setAttribute("data-studio-validation-error-message", String(event.message || "error"));
});
window.addEventListener("unhandledrejection", (event) => {
  const root = document.documentElement;
  root.setAttribute("data-studio-validation-error", "true");
  root.setAttribute(
    "data-studio-validation-error-message",
    String(event.reason || "unhandledrejection")
  );
});
</script>"#;

    if let Some(insert_at) = html.find("</head>") {
        let mut instrumented = String::with_capacity(html.len() + instrumentation_script.len());
        instrumented.push_str(&html[..insert_at]);
        instrumented.push_str(instrumentation_script);
        instrumented.push_str(&html[insert_at..]);
        instrumented
    } else if let Some(insert_at) = html.find("<body") {
        let mut instrumented = String::with_capacity(html.len() + instrumentation_script.len());
        instrumented.push_str(&html[..insert_at]);
        instrumented.push_str(instrumentation_script);
        instrumented.push_str(&html[insert_at..]);
        instrumented
    } else {
        format!("{instrumentation_script}{html}")
    }
}

fn write_temp_studio_html_fixture(name: &str, html: &str) -> PathBuf {
    let fixture_path = std::env::temp_dir().join(format!("{name}-{}.html", Uuid::new_v4()));
    fs::write(&fixture_path, html).expect("fixture should write");
    fixture_path
}
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
    provenance: Option<crate::models::StudioRuntimeProvenance>,
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

    fn studio_runtime_provenance(&self) -> crate::models::StudioRuntimeProvenance {
        self.provenance
            .clone()
            .unwrap_or(crate::models::StudioRuntimeProvenance {
                kind: crate::models::StudioRuntimeProvenanceKind::OpaqueRuntime,
                label: "opaque inference runtime".to_string(),
                model: None,
                endpoint: None,
            })
    }
}

#[derive(Debug, Clone)]
struct StudioArtifactGenerationTestRuntime {
    provenance: crate::models::StudioRuntimeProvenance,
}

impl StudioArtifactGenerationTestRuntime {
    fn new(
        kind: crate::models::StudioRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
    ) -> Self {
        Self {
            provenance: crate::models::StudioRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
        }
    }
}

#[async_trait]
impl InferenceRuntime for StudioArtifactGenerationTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let response = if prompt.contains("typed artifact brief planner") {
            serde_json::json!({
                "audience": "operators",
                "jobToBeDone": "explain the rollout",
                "subjectDomain": "studio rollout",
                "artifactThesis": "show the rollout clearly",
                "requiredConcepts": ["timeline", "owners", "metrics"],
                "requiredInteractions": ["view switching", "detail comparison"],
                "visualTone": ["grounded"],
                "factualAnchors": ["launch review"],
                "styleDirectives": [],
                "referenceHints": []
            })
        } else if prompt.contains("typed artifact materializer") {
            serde_json::json!({
                "summary": "Prepared a studio rollout artifact",
                "notes": ["request-grounded candidate"],
                "files": [{
                    "path": "index.html",
                    "mime": "text/html",
                    "role": "primary",
                    "renderable": true,
                    "downloadable": true,
                    "encoding": "utf8",
                    "body": "<!doctype html><html><head><style>:root{font-family:Georgia,serif;color:#1f1a16;background:#f7f1e8;}body{margin:0;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside,footer{background:#fffaf3;border:1px solid #d4c7b0;border-radius:16px;padding:1rem;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}table{width:100%;border-collapse:collapse;}th,td{padding:0.35rem 0.5rem;border-bottom:1px solid #d4c7b0;}svg{width:100%;height:auto;}</style></head><body><main><section><h1>Studio rollout</h1><p>Review pilot readiness, owner alignment, and launch metrics from one artifact without leaving the side panel. The default timeline opens with real evidence already visible so the first paint is useful before any interaction runs. Operators can compare the operational story, switch to performance metrics, and keep one shared explanation panel in view while they inspect the rollout.</p><button type=\"button\" data-view=\"timeline\" aria-controls=\"timeline-panel\" aria-selected=\"true\">Timeline</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics</button></section><section id=\"timeline-panel\" data-view-panel=\"timeline\"><article><h2>Timeline</h2><p>The rollout begins with a pilot checkpoint, then moves into readiness review and final launch approval. Each bar below represents a real milestone the operator can hover or focus to inspect the detail copy in the shared aside.</p><svg viewBox=\"0 0 120 80\" role=\"img\" aria-label=\"timeline\"><rect x=\"10\" y=\"20\" width=\"20\" height=\"40\" tabindex=\"0\" data-detail=\"Pilot checkpoint\"></rect><rect x=\"44\" y=\"12\" width=\"20\" height=\"48\" tabindex=\"0\" data-detail=\"Readiness review\"></rect><rect x=\"78\" y=\"8\" width=\"20\" height=\"52\" tabindex=\"0\" data-detail=\"Launch approval\"></rect><text x=\"10\" y=\"74\">Pilot</text><text x=\"44\" y=\"74\">Review</text><text x=\"78\" y=\"74\">Launch</text></svg><p>The pilot confirms store readiness, the review aligns owners, and the launch approval clears the final release gate.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics</h2><p>Accuracy, issue deflection, and launch velocity stay pre-rendered here for quick comparison when the operator switches views. The metrics panel is intentionally populated in the static markup so the alternative evidence surface is ready before any script runs.</p><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Accuracy</td><td>99%</td></tr><tr><td>Deflection</td><td>18%</td></tr><tr><td>Velocity</td><td>2.1x</td></tr></table></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Timeline selected by default with pilot, review, and launch evidence already visible. The detail region stays populated on first paint and updates as the operator inspects milestones or switches views.</p></aside><footer><p>The artifact stays request-faithful, interactive, and detailed enough to pass surfaced presentation once judged. It closes with a concise explanation of why the rollout is ready, who owns the next step, and which metrics matter most for launch confidence.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});document.querySelectorAll('button[data-view]').forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=button.dataset.view + ' selected';}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
                }]
            })
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
                "strongestContradiction": null,
                "rationale": "local runtime judged the artifact"
            })
        } else {
            return Err(VmError::HostError("unexpected Studio prompt".to_string()));
        };
        Ok(response.to_string().into_bytes())
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

    fn studio_runtime_provenance(&self) -> crate::models::StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

#[derive(Debug, Clone)]
struct StreamingDirectAuthorTestRuntime {
    provenance: crate::models::StudioRuntimeProvenance,
    chunk_delay: Duration,
}

#[async_trait]
impl InferenceRuntime for StreamingDirectAuthorTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        if prompt.contains("typed artifact judge") {
            return Ok(
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
                    "strongestContradiction": null,
                    "rationale": "streamed direct-author draft was accepted"
                })
                .to_string()
                .into_bytes(),
            );
        }
        Err(VmError::HostError("unexpected Studio prompt".to_string()))
    }

    async fn execute_inference_streaming(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
        token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        if !prompt.contains("direct document author") {
            return self
                .execute_inference(_model_hash, input_context, _options)
                .await;
        }

        let chunks = [
            "<!doctype html><html><head><title>Quantum computers</title><style>body{margin:0;font-family:system-ui,sans-serif;background:#08111d;color:#eef2ff;}main{max-width:900px;margin:0 auto;padding:24px;display:grid;gap:16px;}section{padding:16px;border:1px solid #35506d;border-radius:16px;background:#0f1b2a;}</style></head><body><main>",
            "<section><h1>Quantum computers</h1><p>Quantum computers use qubits, superposition, and interference to explore some calculations differently from classical bits.</p><button type=\"button\" data-view=\"qubits\" aria-controls=\"qubits-panel\" aria-selected=\"true\">Qubits</button><button type=\"button\" data-view=\"gates\" aria-controls=\"gates-panel\" aria-selected=\"false\">Gates</button></section>",
            "<section id=\"qubits-panel\" data-view-panel=\"qubits\"><h2>Qubits</h2><p>A qubit can occupy a blend of 0 and 1 until measurement collapses the state.</p></section><section id=\"gates-panel\" data-view-panel=\"gates\" hidden><h2>Gates</h2><p>Quantum gates rotate probability amplitudes so interference can strengthen correct paths.</p></section><aside><h2>Detail</h2><p id=\"detail-copy\">Qubits are selected by default.</p></aside>",
            "<script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});document.querySelectorAll('button[data-view]').forEach((control)=>control.setAttribute('aria-selected', String(control===button)));detail.textContent=button.dataset.view==='qubits'?'Qubits show blended state before measurement.':'Gates reshape amplitudes through interference.';}));</script></main></body></html>",
        ];

        let mut combined = String::new();
        for chunk in chunks {
            tokio::time::sleep(self.chunk_delay).await;
            combined.push_str(chunk);
            if let Some(sender) = token_stream.as_ref() {
                let _ = sender.send(chunk.to_string()).await;
            }
        }

        Ok(combined.into_bytes())
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

    fn studio_runtime_provenance(&self) -> crate::models::StudioRuntimeProvenance {
        self.provenance.clone()
    }
}

fn empty_task(intent: &str) -> AgentTask {
    let mut task = AgentTask {
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
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
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
    };
    task.sync_runtime_views();
    task
}

#[test]
fn materialize_nonworkspace_artifact_times_out_generation_for_slow_runtime() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowStudioOutcomeTestRuntime {
        payload: "{}".to_string(),
        delay: Duration::from_millis(50),
        provenance: Some(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "local timeout runtime".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
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
        None,
    )
    .expect("materialization should return a blocked timeout result");

    assert_eq!(
        materialized.failure.as_ref().expect("failure").kind,
        crate::models::StudioArtifactFailureKind::GenerationFailure
    );
    assert_eq!(
        materialized.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(!materialized.fallback_used);
    assert!(materialized.files.is_empty());
    assert!(materialized
        .failure
        .as_ref()
        .expect("failure")
        .message
        .contains("timed out"));
    assert_eq!(materialized.candidate_summaries.len(), 0);
    assert_eq!(
        materialized
            .judge
            .as_ref()
            .expect("judge result")
            .classification,
        ioi_api::studio::StudioArtifactJudgeClassification::Blocked
    );
}

#[test]
fn direct_author_streaming_progress_prevents_mid_document_kernel_timeout() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StreamingDirectAuthorTestRuntime {
        provenance: crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "streaming local runtime".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        chunk_delay: Duration::from_millis(120),
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

    let materialized =
        materialize_non_workspace_artifact_with_dependencies_and_timeout_and_execution_strategy(
            &proof_memory_runtime(),
            Some(runtime.clone()),
            Some(runtime),
            "thread-1",
            "Quantum explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            None,
            Duration::from_millis(250),
            None,
            StudioExecutionStrategy::DirectAuthor,
            Some(Arc::new(|_| {})),
        )
        .expect("active streaming progress should keep the direct-author run alive");

    assert!(!materialized.files.is_empty());
    assert!(materialized
        .files
        .iter()
        .any(|file| file.path == "index.html"));
    assert_ne!(
        materialized.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
}

#[test]
fn studio_generation_timeout_extends_local_modal_first_html_for_split_acceptance() {
    let previous_profile = std::env::var("AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE").ok();
    let previous_modal_first = std::env::var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML").ok();
    let previous_local_gpu = std::env::var("AUTOPILOT_LOCAL_GPU_DEV").ok();
    let previous_timeout = std::env::var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS").ok();

    std::env::set_var(
        "AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE",
        "local_generation_remote_acceptance",
    );
    std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", "1");
    std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV");
    std::env::remove_var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS");

    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioArtifactGenerationTestRuntime::new(
        crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen3:8b",
        "http://127.0.0.1:11434/v1/chat/completions",
    ));
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

    let timeout = studio_generation_timeout_for_request(&request, &runtime);

    match previous_profile {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE"),
    }
    match previous_modal_first {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML"),
    }
    match previous_local_gpu {
        Some(value) => std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", value),
        None => std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV"),
    }
    match previous_timeout {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS"),
    }

    assert_eq!(timeout, Duration::from_secs(1200));
}

#[test]
fn direct_author_timeout_uses_strategy_budget_for_local_html() {
    let previous_profile = std::env::var("AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE").ok();
    let previous_modal_first = std::env::var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML").ok();
    let previous_local_gpu = std::env::var("AUTOPILOT_LOCAL_GPU_DEV").ok();
    let previous_timeout = std::env::var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS").ok();

    std::env::set_var(
        "AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE",
        "local_generation_remote_acceptance",
    );
    std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", "1");
    std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV");
    std::env::remove_var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS");

    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioArtifactGenerationTestRuntime::new(
        crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen3.5:9b",
        "http://127.0.0.1:11434/v1/chat/completions",
    ));
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

    let timeout = studio_generation_timeout_for_request_and_execution_strategy(
        &request,
        &runtime,
        None,
        StudioExecutionStrategy::DirectAuthor,
    );

    match previous_profile {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE"),
    }
    match previous_modal_first {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_MODAL_FIRST_HTML"),
    }
    match previous_local_gpu {
        Some(value) => std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", value),
        None => std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV"),
    }
    match previous_timeout {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_GENERATION_TIMEOUT_SECS"),
    }

    assert_eq!(timeout, Duration::from_secs(135));
}

#[test]
fn nonworkspace_materialization_contract_starts_pending_and_blocks_truthfully_on_failure() {
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

    let contract = materialization_contract_for_request(
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        "Studio will author the artifact directly.",
        None,
        StudioExecutionStrategy::DirectAuthor,
    );
    assert_eq!(contract.verification_steps.len(), 2);
    assert_eq!(contract.verification_steps[0].status, "pending");
    assert_eq!(contract.verification_steps[1].status, "pending");

    let blocked = blocked_materialized_artifact_from_error(
        "Quantum explainer",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        None,
        "Studio artifact generation timed out after 135s while authoring the artifact directly.",
        None,
        None,
        None,
        Vec::new(),
        None,
        Vec::new(),
        Some(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
        Some(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        }),
    );
    let blocked_steps = verification_steps_for_materialized_artifact(&request, &blocked);
    assert_eq!(blocked_steps.len(), 2);
    assert_eq!(blocked_steps[0].status, "blocked");
    assert_eq!(blocked_steps[1].status, "blocked");
}

#[test]
fn apply_materialized_artifact_to_contract_marks_nonworkspace_steps_success_when_ready() {
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
    let mut contract = materialization_contract_for_request(
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        "Studio created an artifact.",
        None,
        StudioExecutionStrategy::DirectAuthor,
    );
    let mut ready = blocked_materialized_artifact_from_error(
        "Quantum explainer",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        None,
        "temporary failure used to seed a materialized artifact fixture",
        None,
        None,
        None,
        Vec::new(),
        None,
        Vec::new(),
        Some(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
        Some(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
    );
    ready.file_writes = vec![crate::models::StudioArtifactMaterializationFileWrite {
        path: "index.html".to_string(),
        kind: "primary".to_string(),
        content_preview: Some("<!doctype html>".to_string()),
    }];
    ready.lifecycle_state = StudioArtifactLifecycleState::Ready;
    ready.verification_summary = "Acceptance cleared the artifact.".to_string();
    ready.failure = None;
    ready.ux_lifecycle = StudioArtifactUxLifecycle::Judged;
    ready.winning_candidate_id = Some("candidate-1".to_string());
    ready.judge = Some(StudioArtifactJudgeResult {
        classification: ioi_api::studio::StudioArtifactJudgeClassification::Pass,
        request_faithfulness: 5,
        concept_coverage: 5,
        interaction_relevance: 4,
        layout_coherence: 4,
        visual_hierarchy: 4,
        completeness: 5,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: true,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes: Vec::new(),
        repair_hints: Vec::new(),
        strengths: vec!["Interactive explainer landed.".to_string()],
        blocked_reasons: Vec::new(),
        file_findings: Vec::new(),
        aesthetic_verdict: "clear".to_string(),
        interaction_verdict: "interactive".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("polish_pass".to_string()),
        strongest_contradiction: None,
        rationale: "artifact passed acceptance".to_string(),
    });

    apply_materialized_artifact_to_contract(
        &mut contract,
        &request,
        &ready,
        None,
        StudioExecutionStrategy::DirectAuthor,
    );

    assert_eq!(contract.verification_steps.len(), 2);
    assert_eq!(contract.verification_steps[0].status, "success");
    assert_eq!(contract.verification_steps[1].status, "success");
    assert_eq!(contract.file_writes.len(), 1);
    assert_eq!(contract.winning_candidate_id.as_deref(), Some("candidate-1"));
    assert!(contract.failure.is_none());
}

#[test]
fn provisional_nonworkspace_session_surfaces_planning_context_before_materialization_finishes() {
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
    let outcome_request = StudioOutcomeRequest {
        request_id: "request-1".to_string(),
        raw_prompt: "Create an interactive HTML artifact that explains a rollout".to_string(),
        active_artifact_id: None,
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy: StudioExecutionStrategy::AdaptiveWorkGraph,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: Some(request.clone()),
    };
    let title = "Rollout explainer";
    let summary = summary_for_request(&request, title);
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "explain launch readiness".to_string(),
        subject_domain: "rollout".to_string(),
        artifact_thesis: "Show the launch plan, milestones, and proof from one surface."
            .to_string(),
        required_concepts: vec!["timeline".to_string(), "owners".to_string()],
        required_interactions: vec!["view switching".to_string()],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["launch checkpoint".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["operator briefing".to_string()],
    };
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let mut materialization = materialization_contract_for_request(
        &outcome_request.raw_prompt,
        &request,
        &summary,
        None,
        outcome_request.execution_strategy,
    );
    materialization.artifact_brief = Some(brief);
    materialization.blueprint = Some(blueprint.clone());
    materialization.artifact_ir = Some(artifact_ir);
    materialization.selected_skills = vec![ioi_api::studio::StudioArtifactSelectedSkill {
        skill_hash: "a".repeat(64),
        name: "artifact__frontend_judge_spine".to_string(),
        description: "Front-end structural guidance".to_string(),
        lifecycle_state: "published".to_string(),
        source_type: "filesystem".to_string(),
        reliability_bps: 9500,
        semantic_score_bps: 9100,
        adjusted_score_bps: 9450,
        relative_path: Some("skills/artifact__frontend_judge_spine/SKILL.md".to_string()),
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![ioi_api::studio::StudioArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched the visual art direction need.".to_string(),
        guidance_markdown: Some("Use strong hierarchy and visible evidence framing.".to_string()),
    }];

    let studio_session = super::prepare::provisional_non_workspace_studio_session(
        "thread-1",
        "studio-session-1",
        title,
        &summary,
        "2026-04-04T00:00:00Z",
        &outcome_request,
        materialization,
    )
    .expect("provisional session");

    assert_eq!(
        studio_session.lifecycle_state,
        StudioArtifactLifecycleState::Materializing
    );
    assert_eq!(
        studio_session.artifact_manifest.verification.status,
        StudioArtifactVerificationStatus::Pending
    );
    assert_eq!(
        studio_session.verified_reply.status,
        StudioArtifactVerificationStatus::Pending
    );
    assert_eq!(studio_session.session_id, "studio-session-1");
    assert_eq!(studio_session.materialization.selected_skills.len(), 1);
    assert_eq!(studio_session.retrieved_exemplars.len(), 0);
    assert!(studio_session
        .artifact_manifest
        .verification
        .summary
        .contains(&blueprint.scaffold_family));
    assert!(studio_session
        .materialization
        .pipeline_steps
        .iter()
        .any(|step| step
            .outputs
            .iter()
            .any(|output| output == "selected_skills:1")));
}

#[test]
fn materialize_nonworkspace_artifact_falls_back_to_local_acceptance_when_no_acceptance_runtime_is_configured(
) {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StudioArtifactGenerationTestRuntime::new(
        crate::models::StudioRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
    ));
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
        Some(runtime),
        None,
        "thread-1",
        "Studio rollout",
        "Create an interactive HTML artifact that explains a product rollout with charts",
        &request,
        None,
        Duration::from_secs(5),
        None,
    )
    .expect("materialization should succeed with a local fallback");

    assert!(matches!(
        materialized.lifecycle_state,
        StudioArtifactLifecycleState::Partial | StudioArtifactLifecycleState::Blocked
    ));
    assert!(!materialized.fallback_used);
    assert_eq!(
        materialized
            .production_provenance
            .as_ref()
            .expect("production provenance")
            .label,
        "local producer"
    );
    assert_eq!(
        materialized
            .acceptance_provenance
            .as_ref()
            .expect("acceptance provenance")
            .label,
        "local producer"
    );
    assert_eq!(
        materialized
            .judge
            .as_ref()
            .expect("judge result")
            .classification,
        if materialized.lifecycle_state == StudioArtifactLifecycleState::Blocked {
            ioi_api::studio::StudioArtifactJudgeClassification::Blocked
        } else {
            ioi_api::studio::StudioArtifactJudgeClassification::Repairable
        }
    );
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
    assert!(payload.files[0].body.contains("<main"));
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
            None,
            Vec::new(),
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
    let studio_session = task.studio_session.as_ref().expect("studio session");

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
        None,
        StudioExecutionStrategy::PlanExecute,
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
        None,
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
        None,
    );
    let ready_presentation = ready_steps
        .iter()
        .find(|step| step.id == "presentation")
        .expect("presentation step");
    assert_eq!(ready_presentation.status, "complete");
}

#[test]
fn pipeline_specification_outputs_include_blueprint_and_ir_evidence() {
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
            require_export: false,
            require_diff_review: false,
        },
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "inspect the launch evidence".to_string(),
        subject_domain: "product rollout".to_string(),
        artifact_thesis: "Explain the rollout through visible comparisons.".to_string(),
        required_concepts: vec![
            "product rollout".to_string(),
            "adoption".to_string(),
            "comparison".to_string(),
        ],
        required_interactions: vec![
            "view switching".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["customer feedback".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: Vec::new(),
    };
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let manifest = artifact_manifest_for_request(
        "Release artifact",
        &request,
        &["artifact-1".to_string()],
        None,
        None,
        StudioArtifactLifecycleState::Ready,
    );
    let mut materialization = materialization_contract_for_request(
        "Create an interactive release artifact",
        &request,
        "Studio created an interactive artifact.",
        None,
        StudioExecutionStrategy::PlanExecute,
    );
    materialization.blueprint = Some(blueprint);
    materialization.artifact_ir = Some(artifact_ir);
    materialization.selected_skills = vec![ioi_api::studio::StudioArtifactSelectedSkill {
        skill_hash: "abc123".to_string(),
        name: "frontend_editorial_direction".to_string(),
        description: "Promoted editorial design guidance".to_string(),
        lifecycle_state: "promoted".to_string(),
        source_type: "imported".to_string(),
        reliability_bps: 9800,
        semantic_score_bps: 9100,
        adjusted_score_bps: 9300,
        relative_path: Some("skills/frontend_editorial_direction/SKILL.md".to_string()),
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![ioi_api::studio::StudioArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched visual art direction for the comparison story scaffold."
            .to_string(),
        guidance_markdown: Some("# frontend_editorial_direction".to_string()),
    }];

    let steps = pipeline_steps_for_state(
        "Create an interactive release artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Ready,
        None,
        None,
    );
    let specification = steps
        .iter()
        .find(|step| step.id == "specification")
        .expect("specification step");

    assert!(specification
        .outputs
        .iter()
        .any(|output| output.starts_with("blueprint:")));
    assert!(specification
        .outputs
        .iter()
        .any(|output| output.starts_with("skill_needs:")));
    assert!(specification
        .outputs
        .iter()
        .any(|output| output.starts_with("ir_nodes:")));
    assert!(specification
        .outputs
        .iter()
        .any(|output| output.starts_with("ir_interactions:")));
    assert!(specification
        .outputs
        .iter()
        .any(|output| output.starts_with("selected_skills:")));
}

#[test]
fn pipeline_steps_surface_candidates_judge_and_taste_memory() {
    let request = test_outcome_request().artifact.expect("artifact request");
    let manifest = test_manifest(StudioArtifactVerificationStatus::Ready);
    let mut materialization = test_materialization_contract();
    materialization.output_origin =
        Some(ioi_api::studio::StudioArtifactOutputOrigin::LiveInference);
    materialization.winning_candidate_id = Some("candidate-2".to_string());
    materialization.winning_candidate_rationale =
        Some("Repair pass cleared the mapped-panel contract.".to_string());
    materialization.candidate_summaries = vec![
        ioi_api::studio::StudioArtifactCandidateSummary {
            candidate_id: "candidate-1".to_string(),
            seed: 11,
            model: "fixture".to_string(),
            temperature: 0.4,
            strategy: "initial".to_string(),
            origin: ioi_api::studio::StudioArtifactOutputOrigin::FixtureRuntime,
            provenance: None,
            summary: "Initial draft".to_string(),
            renderable_paths: vec!["index.html".to_string()],
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::studio::StudioArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: None,
                pass_kind: "initial".to_string(),
                pass_index: 0,
                score_total: 15,
                score_delta_from_parent: None,
                terminated_reason: None,
            }),
            render_evaluation: None,
            judge: ioi_api::studio::StudioArtifactJudgeResult {
                classification: ioi_api::studio::StudioArtifactJudgeClassification::Repairable,
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
                issue_classes: vec!["renderer_contract".to_string()],
                repair_hints: vec!["Add mapped panels.".to_string()],
                strengths: Vec::new(),
                blocked_reasons: Vec::new(),
                file_findings: Vec::new(),
                aesthetic_verdict: "needs_density".to_string(),
                interaction_verdict: "needs_repair".to_string(),
                truthfulness_warnings: vec!["First paint is thin.".to_string()],
                recommended_next_pass: Some("structural_repair".to_string()),
                strongest_contradiction: Some("Panels were empty.".to_string()),
                rationale: "Initial draft missed the mapped panel contract.".to_string(),
            },
        },
        ioi_api::studio::StudioArtifactCandidateSummary {
            candidate_id: "candidate-2".to_string(),
            seed: 11,
            model: "fixture".to_string(),
            temperature: 0.25,
            strategy: "repair".to_string(),
            origin: ioi_api::studio::StudioArtifactOutputOrigin::LiveInference,
            provenance: None,
            summary: "Repaired winner".to_string(),
            renderable_paths: vec!["index.html".to_string()],
            selected: true,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::studio::StudioArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: Some("candidate-1".to_string()),
                pass_kind: "structural_repair".to_string(),
                pass_index: 1,
                score_total: 24,
                score_delta_from_parent: Some(9),
                terminated_reason: Some("accepted".to_string()),
            }),
            render_evaluation: None,
            judge: ioi_api::studio::StudioArtifactJudgeResult {
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
                issue_classes: vec!["renderer_contract".to_string()],
                repair_hints: vec!["Keep mapped panels pre-rendered.".to_string()],
                strengths: vec!["Repair pass cleared the first-paint contract.".to_string()],
                blocked_reasons: Vec::new(),
                file_findings: Vec::new(),
                aesthetic_verdict: "editorial_density_ok".to_string(),
                interaction_verdict: "mapped_panels_ready".to_string(),
                truthfulness_warnings: Vec::new(),
                recommended_next_pass: None,
                strongest_contradiction: None,
                rationale: "Repair pass cleared the mapped-panel contract.".to_string(),
            },
        },
    ];
    materialization.judge = materialization
        .candidate_summaries
        .last()
        .map(|candidate| candidate.judge.clone());
    materialization.artifact_ir = Some(ioi_api::studio::StudioArtifactIR {
        version: 1,
        renderer: StudioRendererKind::Markdown,
        scaffold_family: "editorial_markdown".to_string(),
        semantic_structure: Vec::new(),
        interaction_graph: Vec::new(),
        evidence_surfaces: Vec::new(),
        design_tokens: Vec::new(),
        motion_plan: Vec::new(),
        accessibility_obligations: Vec::new(),
        responsive_layout_rules: Vec::new(),
        component_bindings: Vec::new(),
        static_audit_expectations: vec![
            "first-paint content completeness".to_string(),
            "mapped panel visibility".to_string(),
        ],
        render_eval_checklist: Vec::new(),
    });
    let taste_memory = ioi_api::studio::StudioArtifactTasteMemory {
        directives: vec!["Keep the calm editorial tone.".to_string()],
        summary: "User prefers calm editorial hierarchy with explicit evidence labels.".to_string(),
        typography_preferences: Vec::new(),
        density_preference: None,
        tone_family: Vec::new(),
        motion_tolerance: None,
        preferred_scaffold_families: Vec::new(),
        preferred_component_patterns: Vec::new(),
        anti_patterns: Vec::new(),
    };

    let steps = pipeline_steps_for_state(
        "Create a release artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Ready,
        None,
        Some(&taste_memory),
    );
    let materialization_step = steps
        .iter()
        .find(|step| step.id == "materialization")
        .expect("materialization step");
    let verification_step = steps
        .iter()
        .find(|step| step.id == "verification")
        .expect("verification step");
    let reply_step = steps
        .iter()
        .find(|step| step.id == "reply")
        .expect("reply step");

    assert!(materialization_step
        .outputs
        .iter()
        .any(|output| output == "candidates:2"));
    assert!(materialization_step
        .outputs
        .iter()
        .any(|output| output.contains("winner:candidate-2")));
    assert!(materialization_step
        .outputs
        .iter()
        .any(|output| output == "repair_passes:1"));
    assert!(verification_step
        .outputs
        .iter()
        .any(|output| output == "judge:pass"));
    assert!(verification_step
        .outputs
        .iter()
        .any(|output| output == "audit_targets:2"));
    assert!(reply_step
        .outputs
        .iter()
        .any(|output| output.starts_with("taste_memory:")));
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
        execution_strategy: StudioExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
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
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope: None,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: None,
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
            } else if status == StudioArtifactVerificationStatus::Pending {
                StudioArtifactLifecycleState::Materializing
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
            } else if status == StudioArtifactVerificationStatus::Pending {
                StudioArtifactLifecycleState::Materializing
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
        } else if status == StudioArtifactVerificationStatus::Pending {
            StudioArtifactLifecycleState::Materializing
        } else if status == StudioArtifactVerificationStatus::Failed {
            StudioArtifactLifecycleState::Failed
        } else if status == StudioArtifactVerificationStatus::Partial {
            StudioArtifactLifecycleState::Partial
        } else {
            StudioArtifactLifecycleState::Blocked
        },
        status: if status == StudioArtifactVerificationStatus::Failed {
            "failed".to_string()
        } else if status == StudioArtifactVerificationStatus::Pending {
            "materializing".to_string()
        } else {
            "ready".to_string()
        },
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
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
        typography_preferences: vec!["jetbrains mono".to_string()],
        density_preference: Some("airy".to_string()),
        tone_family: vec!["calm".to_string()],
        motion_tolerance: Some("low".to_string()),
        preferred_scaffold_families: vec!["editorial_split".to_string()],
        preferred_component_patterns: vec!["comparison_grid".to_string()],
        anti_patterns: vec!["generic_cards".to_string()],
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
        derive_studio_taste_memory(Some(&prior), &brief, None, None, Some(&edit_intent), None)
            .expect("taste memory");

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
    assert_eq!(
        taste_memory.typography_preferences,
        vec!["jetbrains mono".to_string()]
    );
    assert_eq!(taste_memory.density_preference.as_deref(), Some("airy"));
    assert_eq!(
        taste_memory.tone_family,
        vec![
            "calm".to_string(),
            "enterprise".to_string(),
            "technical".to_string(),
            "confident".to_string(),
        ]
    );
    assert_eq!(taste_memory.motion_tolerance.as_deref(), Some("low"));
    assert_eq!(
        taste_memory.preferred_scaffold_families,
        vec!["editorial_split".to_string()]
    );
    assert_eq!(
        taste_memory.preferred_component_patterns,
        vec!["comparison_grid".to_string()]
    );
    assert_eq!(
        taste_memory.anti_patterns,
        vec!["generic_cards".to_string()]
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
    studio_session.taste_memory = Some(StudioArtifactTasteMemory {
        directives: vec!["legacy".to_string()],
        summary: "Legacy taste memory".to_string(),
        typography_preferences: Vec::new(),
        density_preference: None,
        tone_family: Vec::new(),
        motion_tolerance: None,
        preferred_scaffold_families: Vec::new(),
        preferred_component_patterns: Vec::new(),
        anti_patterns: Vec::new(),
    });
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
    restored_revision.taste_memory = Some(StudioArtifactTasteMemory {
        directives: vec!["editorial".to_string(), "proof-first".to_string()],
        summary: "Restored taste memory".to_string(),
        typography_preferences: vec!["jetbrains mono".to_string()],
        density_preference: Some("airy".to_string()),
        tone_family: vec!["editorial".to_string()],
        motion_tolerance: Some("low".to_string()),
        preferred_scaffold_families: vec!["comparison_story".to_string()],
        preferred_component_patterns: vec!["comparison_table".to_string()],
        anti_patterns: vec!["generic_cards".to_string()],
    });
    restored_revision.retrieved_exemplars = vec![StudioArtifactExemplar {
        record_id: 44,
        title: "Recovered exemplar".to_string(),
        summary: "Recovered summary".to_string(),
        renderer: StudioRendererKind::HtmlIframe,
        scaffold_family: "comparison_story".to_string(),
        thesis: "Lead with evidence.".to_string(),
        quality_rationale: "High judge score with clear structure.".to_string(),
        score_total: 31,
        design_cues: vec!["editorial".to_string()],
        component_patterns: vec!["comparison_table".to_string()],
        anti_patterns: vec!["generic_cards".to_string()],
        source_revision_id: Some("revision-source".to_string()),
    }];

    apply_revision_to_studio_session(&mut studio_session, &restored_revision);

    assert_eq!(studio_session.title, "Restored artifact");
    assert_eq!(
        studio_session.artifact_manifest.files[0].path,
        "restored.md"
    );
    assert_eq!(studio_session.selected_targets[0].label, "Restored section");
    assert_eq!(
        studio_session
            .taste_memory
            .as_ref()
            .and_then(|memory| memory.density_preference.as_deref()),
        Some("airy")
    );
    assert_eq!(studio_session.retrieved_exemplars.len(), 1);
    assert_eq!(studio_session.retrieved_exemplars[0].record_id, 44);
    assert_eq!(
        studio_session.active_revision_id,
        Some("revision-2".to_string())
    );
}

#[test]
fn exemplar_archival_record_round_trips_into_structured_exemplar() {
    let record = ArchivalMemoryRecord {
        id: 91,
        scope: STUDIO_ARTIFACT_EXEMPLAR_SCOPE.to_string(),
        thread_id: None,
        kind: "studio.artifact_exemplar".to_string(),
        content: "Renderer: html_iframe".to_string(),
        metadata_json: serde_json::json!({
            "trustLevel": "runtime_observed",
            "artifactId": "artifact-1",
            "revisionId": "revision-9",
            "renderer": "html_iframe",
            "scaffoldFamily": "comparison_story",
            "title": "Quantum explainer",
            "summary": "Interactive explainer with evidence-led sections.",
            "thesis": "Explain qubits through visible state transitions.",
            "qualityRationale": "High-clarity structure with verified interactions.",
            "scoreTotal": 33,
            "designCues": ["editorial", "science-led"],
            "componentPatterns": ["bloch_sphere_demo", "comparison_table"],
            "antiPatterns": ["generic_cards"]
        })
        .to_string(),
        created_at_ms: 42,
    };

    let exemplar =
        studio_artifact_exemplar_from_archival_record(&record).expect("structured exemplar");

    assert_eq!(exemplar.record_id, 91);
    assert_eq!(exemplar.renderer, StudioRendererKind::HtmlIframe);
    assert_eq!(exemplar.scaffold_family, "comparison_story");
    assert_eq!(
        exemplar.component_patterns,
        vec![
            "bloch_sphere_demo".to_string(),
            "comparison_table".to_string(),
        ]
    );
    assert_eq!(exemplar.source_revision_id.as_deref(), Some("revision-9"));
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
    let mut task = AgentTask {
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
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
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
    };
    task.sync_runtime_views();
    task
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
fn authoritative_ready_artifact_mentions_candidates_and_repairs_when_available() {
    let mut task = test_task(StudioArtifactVerificationStatus::Ready);
    task.studio_session
        .as_mut()
        .expect("studio session")
        .materialization
        .winning_candidate_id = Some("candidate-2".to_string());
    task.studio_session
        .as_mut()
        .expect("studio session")
        .materialization
        .candidate_summaries = vec![
        ioi_api::studio::StudioArtifactCandidateSummary {
            candidate_id: "candidate-1".to_string(),
            seed: 1,
            model: "fixture".to_string(),
            temperature: 0.4,
            strategy: "initial".to_string(),
            origin: ioi_api::studio::StudioArtifactOutputOrigin::FixtureRuntime,
            provenance: None,
            summary: "Initial".to_string(),
            renderable_paths: vec!["artifact.md".to_string()],
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::studio::StudioArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: None,
                pass_kind: "initial".to_string(),
                pass_index: 0,
                score_total: 10,
                score_delta_from_parent: None,
                terminated_reason: None,
            }),
            render_evaluation: None,
            judge: ioi_api::studio::StudioArtifactJudgeResult {
                classification: ioi_api::studio::StudioArtifactJudgeClassification::Repairable,
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
            },
        },
        ioi_api::studio::StudioArtifactCandidateSummary {
            candidate_id: "candidate-2".to_string(),
            seed: 1,
            model: "fixture".to_string(),
            temperature: 0.25,
            strategy: "repair".to_string(),
            origin: ioi_api::studio::StudioArtifactOutputOrigin::LiveInference,
            provenance: None,
            summary: "Winner".to_string(),
            renderable_paths: vec!["artifact.md".to_string()],
            selected: true,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::studio::StudioArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: Some("candidate-1".to_string()),
                pass_kind: "structural_repair".to_string(),
                pass_index: 1,
                score_total: 18,
                score_delta_from_parent: Some(8),
                terminated_reason: Some("accepted".to_string()),
            }),
            render_evaluation: None,
            judge: ioi_api::studio::StudioArtifactJudgeResult {
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
            },
        },
    ];

    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Studio verified candidate-2 after 2 candidate(s) and 1 repair pass(es)."
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

    assert_eq!(task.phase, AgentPhase::Running);
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

    let studio_session = task.studio_session.as_ref().expect("studio session");
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
        provenance: None,
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

    let studio_session = task.studio_session.as_ref().expect("studio session");
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
fn current_task_turn_surfaces_non_artifact_routes_as_shared_execution_sessions() {
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

    let studio_session = task.studio_session.as_ref().expect("studio session");
    assert_eq!(
        studio_session.lifecycle_state,
        StudioArtifactLifecycleState::Ready
    );
    assert!(studio_session
        .artifact_manifest
        .verification
        .failure
        .is_none());
    assert!(studio_session
        .artifact_manifest
        .verification
        .summary
        .contains("conversation and kept it on the shared execution lane"));
    assert_eq!(
        studio_session.outcome_request.outcome_kind,
        StudioOutcomeKind::Conversation
    );
    assert!(studio_session.materialization.swarm_execution.is_some());
    assert_eq!(
        studio_session
            .materialization
            .swarm_execution
            .as_ref()
            .expect("swarm execution")
            .execution_domain,
        "studio_conversation"
    );
    assert!(studio_session
        .materialization
        .pipeline_steps
        .iter()
        .any(|step| step.id == "reply"));
    assert!(task_is_studio_authoritative(&task));
    let _ = fs::remove_dir_all(workspace_root_base);
}

#[test]
fn authoritative_conversation_route_marks_task_complete_with_shared_summary() {
    let mut task = empty_task("Explain the rollout in chat");
    let outcome_request = StudioOutcomeRequest {
        request_id: "conversation-request".to_string(),
        raw_prompt: "Explain the rollout in chat".to_string(),
        active_artifact_id: None,
        outcome_kind: StudioOutcomeKind::Conversation,
        execution_strategy: StudioExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        artifact: None,
    };
    super::content_session::attach_non_artifact_studio_session(
        &mut task,
        "Explain the rollout in chat",
        crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_studio_authoritative(&task));
    apply_studio_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert!(task.current_step.contains("shared execution lane"));
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
        &request,
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
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec!["Acceptance cleared the artifact for primary presentation.".to_string()],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "clear_hierarchy_and_density".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance cleared the artifact".to_string(),
        },
        None,
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
fn render_eval_warning_keeps_html_out_of_ready_state_even_when_acceptance_passes() {
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
    let render_evaluation = StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: true,
        captures: vec![
            StudioArtifactRenderCapture {
                viewport: StudioArtifactRenderCaptureViewport::Desktop,
                width: 1440,
                height: 960,
                screenshot_sha256: "desktop".to_string(),
                screenshot_byte_count: 4096,
                visible_element_count: 26,
                visible_text_chars: 380,
                interactive_element_count: 2,
                screenshot_changed_from_previous: false,
            },
            StudioArtifactRenderCapture {
                viewport: StudioArtifactRenderCaptureViewport::Mobile,
                width: 390,
                height: 844,
                screenshot_sha256: "mobile".to_string(),
                screenshot_byte_count: 3980,
                visible_element_count: 24,
                visible_text_chars: 352,
                interactive_element_count: 2,
                screenshot_changed_from_previous: true,
            },
        ],
        layout_density_score: 3,
        spacing_alignment_score: 3,
        typography_contrast_score: 4,
        visual_hierarchy_score: 3,
        blueprint_consistency_score: 3,
        overall_score: 16,
        findings: vec![StudioArtifactRenderFinding {
            code: "visual_hierarchy_flat".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Warning,
            summary: "The capture reads as visually flat instead of establishing a clear first-paint hierarchy."
                .to_string(),
        }],
        summary:
            "Render evaluation found repairable desktop/mobile issues with an overall score of 16/25."
                .to_string(),
    };
    let promoted = finalize_presentation_assessment(
        &request,
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
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec!["Acceptance cleared the artifact for primary presentation.".to_string()],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "clear_hierarchy_and_density".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance cleared the artifact".to_string(),
        },
        Some(&render_evaluation),
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(promoted
        .summary
        .contains("render evaluation kept it provisional"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("visually flat")));
}

#[test]
fn render_eval_blocker_overrides_acceptance_pass_for_html_artifacts() {
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
    let render_evaluation = StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: false,
        interaction_capture_attempted: false,
        captures: vec![StudioArtifactRenderCapture {
            viewport: StudioArtifactRenderCaptureViewport::Desktop,
            width: 1440,
            height: 960,
            screenshot_sha256: "desktop".to_string(),
            screenshot_byte_count: 0,
            visible_element_count: 0,
            visible_text_chars: 0,
            interactive_element_count: 0,
            screenshot_changed_from_previous: false,
        }],
        layout_density_score: 1,
        spacing_alignment_score: 1,
        typography_contrast_score: 1,
        visual_hierarchy_score: 1,
        blueprint_consistency_score: 1,
        overall_score: 5,
        findings: vec![StudioArtifactRenderFinding {
            code: "capture_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary:
                "Desktop and mobile render captures must both exist before Studio can trust the surfaced first paint."
                    .to_string(),
        }],
        summary:
            "Render evaluation blocked the primary view after desktop/mobile capture with an overall score of 5/25."
                .to_string(),
    };
    let promoted = finalize_presentation_assessment(
        &request,
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
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec!["Acceptance cleared the artifact for primary presentation.".to_string()],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "clear_hierarchy_and_density".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance cleared the artifact".to_string(),
        },
        Some(&render_evaluation),
        false,
        false,
    );

    assert_eq!(
        promoted.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(promoted.summary.contains("render evaluation blocked"));
    assert!(promoted
        .findings
        .iter()
        .any(|finding| finding.contains("Desktop and mobile render captures must both exist")));
}

#[test]
fn html_prefilter_blocks_duplicate_mapped_view_tokens() {
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
                "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #ccc;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"overview\" hidden><article><h2>Metrics</h2><p>Metrics evidence should not reuse the overview token.</p></article></section><aside><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Blocked
    );
    assert!(assessment
        .findings
        .iter()
        .any(|finding| finding.contains("duplicates mapped evidence-panel tokens")));
}

#[test]
fn html_prefilter_marks_shim_heavy_output_as_partial() {
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
                "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside,footer{padding:1rem;border:1px solid #d7ccb8;border-radius:16px;}</style></head><body data-studio-normalized=\"true\"><main><section><h1>Launch review</h1><p>Compare readiness, risk, and adoption metrics without leaving the artifact. The review opens on a populated operational snapshot so the reader can assess baseline momentum before switching views.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here, including deployment confidence, operator trust, and a short narrative about what changed in the latest release.</p><p>The default view gives the artifact enough first-paint density to qualify as a real surface instead of a shell.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics</h2><p>Metrics evidence stays pre-rendered with retention, latency, and completion-rate notes so the comparison panel already exists before any interaction.</p><p>Secondary evidence remains hidden until the user switches views, but the content is still present in the DOM.</p></article></section><aside data-studio-normalized=\"true\"><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default with readiness evidence, deployment confidence, and release notes already visible.</p></aside><footer><p>Footer note summarizing next steps, ownership, and verification posture for the launch review.</p></footer><script data-studio-view-switch-repair=\"true\">const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(assessment
        .findings
        .iter()
        .any(|finding| finding.contains("leans on Studio repair shims")));
}

#[test]
fn html_prefilter_marks_unfocusable_rollover_targets_as_partial() {
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
                "<!doctype html><html><head><style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside,footer{padding:1rem;border:1px solid #cbd5e1;border-radius:16px;}svg{width:100%;max-width:320px;height:auto;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness, adoption, and support demand through a narrative artifact with visible evidence marks, a shared detail panel, and enough first-paint density to qualify as a real surface.</p></section><section><article><h2>Evidence</h2><p>The chart surfaces three evidence marks with rollout context, operator notes, and escalation posture already visible before interaction.</p><svg viewBox=\"0 0 320 120\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"24\" y=\"28\" width=\"52\" height=\"64\" fill=\"#2563eb\" data-detail=\"Readiness signal\"></rect><rect x=\"104\" y=\"16\" width=\"52\" height=\"76\" fill=\"#0f766e\" data-detail=\"Adoption signal\"></rect><rect x=\"184\" y=\"36\" width=\"52\" height=\"56\" fill=\"#b45309\" data-detail=\"Support signal\"></rect></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Readiness signal is selected by default with rollout evidence already visible.</p></aside><footer><p>Footer note summarizing next steps, ownership, and verification posture for the launch review.</p></footer><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('focus',()=>{detail.textContent=mark.getAttribute('data-detail');});mark.addEventListener('mouseenter',()=>{detail.textContent=mark.getAttribute('data-detail');});});</script></main></body></html>"
                    .to_string(),
            ),
        }],
    );

    assert_eq!(
        assessment.lifecycle_state,
        StudioArtifactLifecycleState::Partial
    );
    assert!(assessment
        .findings
        .iter()
        .any(|finding| finding.contains("non-focusable marks")));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Chromium to validate HTML artifact interactions"]
async fn html_headless_validation_probe_confirms_view_switching_without_runtime_errors() {
    let raw_html = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Studio validation probe</title>
    <style>
      body {
        font-family: system-ui, sans-serif;
        background: #f5f3ee;
        color: #1b1a17;
        margin: 0;
      }
      main {
        display: grid;
        gap: 1rem;
        padding: 1.5rem;
      }
      section,
      aside,
      footer {
        border: 1px solid #d7ccb8;
        border-radius: 16px;
        padding: 1rem;
        background: #fffdf8;
      }
      .control-bar {
        display: flex;
        gap: 0.75rem;
      }
      [hidden] {
        display: none !important;
      }
    </style>
  </head>
  <body>
    <main>
      <section>
        <h1>Launch review</h1>
        <p>Compare readiness, momentum, and operating metrics without leaving the artifact surface.</p>
        <div class="control-bar">
          <button type="button" data-view="overview" aria-controls="overview-panel">Overview</button>
          <button type="button" data-view="metrics" aria-controls="metrics-panel">Metrics</button>
        </div>
      </section>
      <section id="overview-panel" data-view-panel="overview">
        <article>
          <h2>Overview</h2>
          <p>Readiness evidence stays visible here with deployment confidence, change notes, and rollout context.</p>
        </article>
      </section>
      <section id="metrics-panel" data-view-panel="metrics" hidden>
        <article>
          <h2>Metrics</h2>
          <p>Metrics evidence stays pre-rendered with completion rate, latency, and incident posture already in the DOM.</p>
        </article>
      </section>
      <aside>
        <h2>Detail</h2>
        <p id="detail-copy">Overview is selected by default with readiness evidence already visible.</p>
      </aside>
      <footer>
        <p>Footer note summarizing next steps, owners, and verification posture.</p>
      </footer>
    </main>
    <script>
      const detail = document.getElementById("detail-copy");
      const panels = Array.from(document.querySelectorAll("[data-view-panel]"));
      document.querySelectorAll("button[data-view]").forEach((button) => {
        button.addEventListener("click", () => {
          panels.forEach((panel) => {
            panel.hidden = panel.dataset.viewPanel !== button.dataset.view;
          });
          detail.textContent = button.dataset.view + " selected with surfaced evidence.";
        });
      });
    </script>
  </body>
</html>
"#;
    let fixture_path = write_temp_studio_html_fixture(
        "studio-html-validation",
        &instrument_html_for_headless_validation(raw_html),
    );
    let fixture_url = format!("file://{}", fixture_path.display());

    let driver = BrowserDriver::new();
    driver.set_lease(true);
    driver
        .navigate(&fixture_url)
        .await
        .expect("fixture should load");

    let initial_errors = driver
        .probe_selector("html[data-studio-validation-error='true']")
        .await
        .expect("probe should succeed");
    assert!(
        !initial_errors.found,
        "fixture should not throw on first paint"
    );

    let overview_before = driver
        .probe_selector("#overview-panel")
        .await
        .expect("overview probe");
    let metrics_before = driver
        .probe_selector("#metrics-panel")
        .await
        .expect("metrics probe");
    assert!(overview_before.visible, "overview panel should be visible");
    assert!(!metrics_before.visible, "metrics panel should start hidden");
    assert_eq!(
        driver
            .selector_text("#detail-copy")
            .await
            .expect("detail copy lookup")
            .as_deref(),
        Some("Overview is selected by default with readiness evidence already visible.")
    );

    driver
        .click_selector("button[data-view='metrics']")
        .await
        .expect("metrics view should click");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let overview_after = driver
        .probe_selector("#overview-panel")
        .await
        .expect("overview probe after click");
    let metrics_after = driver
        .probe_selector("#metrics-panel")
        .await
        .expect("metrics probe after click");
    assert!(
        !overview_after.visible,
        "overview panel should hide after click"
    );
    assert!(
        metrics_after.visible,
        "metrics panel should show after click"
    );

    let detail_after = driver
        .selector_text("#detail-copy")
        .await
        .expect("detail copy after click")
        .unwrap_or_default();
    assert!(
        detail_after.contains("metrics selected"),
        "detail panel should reflect the switched view, got: {detail_after}"
    );

    let post_click_errors = driver
        .probe_selector("html[data-studio-validation-error='true']")
        .await
        .expect("post-click probe should succeed");
    assert!(
        !post_click_errors.found,
        "fixture should stay free of runtime errors after interaction"
    );

    let _ = fs::remove_file(&fixture_path);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "launches Chromium to validate browser-backed render evaluation"]
async fn browser_render_evaluator_captures_desktop_mobile_and_interaction() {
    let evaluator = BrowserStudioArtifactRenderEvaluator::default();
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
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "inspect an interactive rollout story".to_string(),
        subject_domain: "launch review".to_string(),
        artifact_thesis: "Show desktop and mobile hierarchy with a visible interaction change."
            .to_string(),
        required_concepts: vec!["timeline".to_string(), "metrics".to_string()],
        required_interactions: vec!["view switching".to_string()],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["launch evidence".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["comparison panel".to_string()],
    };
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Interactive rollout explainer".to_string(),
        notes: vec!["browser render evaluation validation pass".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><head><meta charset=\"utf-8\"><style>body{margin:0;font-family:Georgia,serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside{background:#fffdf8;border:1px solid #d5c7ad;border-radius:16px;padding:1rem;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}[hidden]{display:none !important;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics without leaving the artifact surface.</p><div><button type=\"button\" data-studio-render-primary-action=\"true\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"metrics\">Metrics</button></div></section><section id=\"overview-panel\" data-view-panel=\"overview\"><h2>Overview</h2><p>Readiness evidence stays visible on first paint.</p></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><h2>Metrics</h2><p>Metrics evidence becomes visible after interaction.</p></section><aside><p id=\"detail-copy\">Overview selected.</p></aside></main><script>const detail=document.getElementById('detail-copy');const panels=Array.from(document.querySelectorAll('[data-view-panel]'));document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected';}));</script></body></html>".to_string(),
        }],
    };

    let render_evaluation = evaluator
        .evaluate_candidate_render(&request, &brief, None, None, None, &candidate)
        .await
        .expect("render evaluation should succeed")
        .expect("html render evaluation should be supported");

    assert!(render_evaluation.supported);
    assert!(render_evaluation.first_paint_captured);
    assert!(render_evaluation.overall_score > 0);
    assert!(render_evaluation
        .captures
        .iter()
        .any(|capture| capture.viewport == StudioArtifactRenderCaptureViewport::Desktop));
    assert!(render_evaluation
        .captures
        .iter()
        .any(|capture| capture.viewport == StudioArtifactRenderCaptureViewport::Mobile));
    assert!(render_evaluation
        .captures
        .iter()
        .any(|capture| capture.viewport == StudioArtifactRenderCaptureViewport::Interaction));
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
        &request,
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
            issue_classes: vec!["content_gap".to_string()],
            repair_hints: vec![
                "Add ingredient analysis and pH comparison charts before promoting the artifact."
                    .to_string(),
            ],
            strengths: vec![
                "The launch surface is already coherent enough for a targeted refinement pass."
                    .to_string(),
            ],
            blocked_reasons: Vec::new(),
            file_findings: vec!["Missing ingredient analysis and pH level charts".to_string()],
            aesthetic_verdict: "serviceable_but_needs_more_visual_evidence".to_string(),
            interaction_verdict: "refinement_needed".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some("refinement_pass".to_string()),
            strongest_contradiction: Some(
                "Missing ingredient analysis and pH level charts".to_string(),
            ),
            rationale: "Needs another refinement pass.".to_string(),
        },
        None,
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
        &request,
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
            issue_classes: vec!["acceptance_pending".to_string()],
            repair_hints: vec![
                "Run the acceptance pass before promoting the draft into the ready state."
                    .to_string(),
            ],
            strengths: vec![
                "Production surfaced a request-faithful draft with viable structure.".to_string(),
            ],
            blocked_reasons: Vec::new(),
            file_findings: vec!["Acceptance judging is still pending for this draft.".to_string()],
            aesthetic_verdict: "provisionally_viable".to_string(),
            interaction_verdict: "awaiting_acceptance_confirmation".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some("acceptance_pass".to_string()),
            strongest_contradiction: Some(
                "Acceptance judging is still pending for this draft.".to_string(),
            ),
            rationale: "Production surfaced a request-faithful draft.".to_string(),
        },
        None,
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
        &request,
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
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths: vec![
                "Acceptance liked the artifact before renderer-truthfulness checks ran."
                    .to_string(),
            ],
            blocked_reasons: Vec::new(),
            file_findings: Vec::new(),
            aesthetic_verdict: "visually_clear".to_string(),
            interaction_verdict: "request_aligned".to_string(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: None,
            strongest_contradiction: None,
            rationale: "acceptance liked the artifact".to_string(),
        },
        None,
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
fn studio_artifact_benchmark_catalog_tracks_quantum_and_onboarding_cases() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root should resolve");
    let catalog_path =
        repo_root.join("docs/evidence/studio-artifact-surface/benchmark-suite.catalog.json");
    let raw = fs::read_to_string(&catalog_path).expect("benchmark catalog should exist");
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).expect("benchmark catalog should parse");
    let cases = parsed["cases"]
        .as_array()
        .expect("benchmark catalog should contain a cases array");

    let quantum_case = cases
        .iter()
        .find(|entry| entry["benchmarkId"] == "html-quantum-explainer")
        .expect("quantum parity target should be cataloged");
    assert_eq!(quantum_case["trackedParityTarget"], true);
    assert_eq!(quantum_case["outcomeRequest"]["renderer"], "html_iframe");

    let onboarding_case = cases
        .iter()
        .find(|entry| entry["benchmarkId"] == "html-guided-onboarding-explainer")
        .expect("guided onboarding benchmark should be cataloged");
    assert!(
        onboarding_case["caseBindings"].is_array(),
        "guided onboarding benchmark should expose explicit caseBindings metadata"
    );
}

#[test]
fn studio_artifact_corpus_summary_surfaces_benchmark_suite_metrics() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root should resolve");
    let summary_path = repo_root.join("docs/evidence/studio-artifact-surface/corpus-summary.json");
    let raw = fs::read_to_string(&summary_path).expect("corpus summary should exist");
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).expect("corpus summary should parse");
    let benchmark_suite = parsed["benchmarkSuite"]
        .as_object()
        .expect("corpus summary should include benchmarkSuite");

    assert!(
        benchmark_suite["totalBenchmarks"]
            .as_u64()
            .is_some_and(|count| count >= 7),
        "benchmark suite should expose at least the expected tracked benchmark count"
    );
    assert!(
        benchmark_suite["parityTargets"]
            .as_array()
            .expect("parityTargets should be an array")
            .iter()
            .any(|entry| entry == "html-quantum-explainer"),
        "quantum should remain a tracked parity target"
    );
    assert!(
        benchmark_suite["metrics"]["readyRate"]["available"]
            .as_bool()
            .expect("readyRate availability should be present"),
        "benchmark suite should compute grounded metrics from retained evidence"
    );
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
