use super::content_session::{
    apply_materialized_artifact_to_contract, clarification_request_for_outcome_request,
    infer_connector_route_context_from_catalog, route_decision_for_outcome_request,
    runtime_handoff_prompt_prefix_for_task, studio_outcome_request_with_runtime_timeout,
    verification_steps_for_materialized_artifact,
};
use super::proof::run_studio_current_task_turn_for_proof_with_route_timeout;
use super::revisions::{
    apply_revision_to_studio_session, studio_artifact_exemplar_from_archival_record,
    STUDIO_ARTIFACT_EXEMPLAR_SCOPE,
};
use super::*;
use crate::kernel::connectors::ConnectorCatalogEntry;
use crate::models::{ChatMessage, ClarificationRequest, GateInfo};
use crate::models::{
    StudioArtifactDeliverableShape, StudioArtifactFileRole, StudioExecutionSubstrate,
    StudioVerifiedReply,
};
use async_trait::async_trait;
use ioi_api::execution::{
    ExecutionCompletionInvariantStatus, ExecutionLivePreview, ExecutionLivePreviewKind,
};
use ioi_api::studio::{
    compile_studio_artifact_ir, derive_studio_artifact_blueprint,
    derive_studio_artifact_prepared_context, with_studio_modal_first_html_override,
    with_studio_runtime_locality_scope_hint_override, ExecutionStage, StudioArtifactBlueprint,
    StudioArtifactBrief, StudioArtifactExemplar, StudioArtifactGenerationProgress,
    StudioArtifactGenerationProgressObserver, StudioArtifactIR, StudioArtifactMergeReceipt,
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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;

mod artifact_quality;
mod artifact_runtime;
mod pipeline;
mod routing;
mod session_truth;

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

#[derive(Default)]
struct KernelPassingRenderEvaluator;

#[async_trait]
impl StudioArtifactRenderEvaluator for KernelPassingRenderEvaluator {
    async fn evaluate_candidate_render(
        &self,
        _request: &StudioOutcomeArtifactRequest,
        _brief: &StudioArtifactBrief,
        _blueprint: Option<&StudioArtifactBlueprint>,
        _artifact_ir: Option<&StudioArtifactIR>,
        _edit_intent: Option<&StudioArtifactEditIntent>,
        _candidate: &StudioGeneratedArtifactPayload,
    ) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
        Ok(Some(StudioArtifactRenderEvaluation {
            supported: true,
            first_paint_captured: true,
            interaction_capture_attempted: true,
            captures: vec![
                StudioArtifactRenderCapture {
                    viewport: StudioArtifactRenderCaptureViewport::Desktop,
                    width: 1440,
                    height: 960,
                    screenshot_sha256: "desktop-pass".to_string(),
                    screenshot_byte_count: 1024,
                    visible_element_count: 18,
                    visible_text_chars: 240,
                    interactive_element_count: 2,
                    screenshot_changed_from_previous: false,
                },
                StudioArtifactRenderCapture {
                    viewport: StudioArtifactRenderCaptureViewport::Mobile,
                    width: 430,
                    height: 932,
                    screenshot_sha256: "mobile-pass".to_string(),
                    screenshot_byte_count: 768,
                    visible_element_count: 16,
                    visible_text_chars: 220,
                    interactive_element_count: 2,
                    screenshot_changed_from_previous: true,
                },
            ],
            layout_density_score: 4,
            spacing_alignment_score: 4,
            typography_contrast_score: 4,
            visual_hierarchy_score: 4,
            blueprint_consistency_score: 4,
            overall_score: 20,
            findings: Vec::new(),
            acceptance_obligations: Vec::new(),
            execution_witnesses: Vec::new(),
            summary: "Render evaluation completed.".to_string(),
            observation: None,
            acceptance_policy: None,
        }))
    }
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
                    "body": "<!doctype html><html><head><style>:root{font-family:Georgia,serif;color:#1f1a16;background:#f7f1e8;}body{margin:0;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside,footer{background:#fffaf3;border:1px solid #d4c7b0;border-radius:16px;padding:1rem;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}table{width:100%;border-collapse:collapse;}th,td{padding:0.35rem 0.5rem;border-bottom:1px solid #d4c7b0;}svg{width:100%;height:auto;}</style></head><body><main><section><h1>Studio rollout</h1><p>Review pilot readiness, owner alignment, and launch metrics from one artifact without leaving the side panel. The default timeline opens with real evidence already visible so the first paint is useful before any interaction runs. Operators can compare the operational story, switch to performance metrics, and keep one shared explanation panel in view while they inspect the rollout.</p><button type=\"button\" data-view=\"timeline\" aria-controls=\"timeline-panel\" aria-selected=\"true\">Timeline</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\" aria-selected=\"false\">Metrics</button></section><section id=\"timeline-panel\" data-view-panel=\"timeline\"><article><h2>Timeline</h2><p>The rollout begins with a pilot checkpoint, then moves into readiness review and final launch approval. Each bar below represents a real milestone the operator can hover or focus to inspect the detail copy in the shared aside.</p><svg viewBox=\"0 0 120 80\" role=\"img\" aria-label=\"timeline\"><rect x=\"10\" y=\"20\" width=\"20\" height=\"40\" tabindex=\"0\" data-detail=\"Pilot checkpoint\"></rect><rect x=\"44\" y=\"12\" width=\"20\" height=\"48\" tabindex=\"0\" data-detail=\"Readiness review\"></rect><rect x=\"78\" y=\"8\" width=\"20\" height=\"52\" tabindex=\"0\" data-detail=\"Launch approval\"></rect><text x=\"10\" y=\"74\">Pilot</text><text x=\"44\" y=\"74\">Review</text><text x=\"78\" y=\"74\">Launch</text></svg><p>The pilot confirms store readiness, the review aligns owners, and the launch approval clears the final release gate.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics</h2><p>Accuracy, issue deflection, and launch velocity stay pre-rendered here for quick comparison when the operator switches views. The metrics panel is intentionally populated in the static markup so the alternative evidence surface is ready before any script runs.</p><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Accuracy</td><td>99%</td></tr><tr><td>Deflection</td><td>18%</td></tr><tr><td>Velocity</td><td>2.1x</td></tr></table></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Timeline selected by default with pilot, review, and launch evidence already visible. The detail region stays populated on first paint and updates as the operator inspects milestones or switches views.</p></aside><footer><p>The artifact stays request-faithful, interactive, and detailed enough to pass surfaced presentation once validated. It closes with a concise explanation of why the rollout is ready, who owns the next step, and which metrics matter most for launch confidence.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});document.querySelectorAll('button[data-view]').forEach((control)=>{control.setAttribute('aria-selected', String(control===button));});detail.textContent=button.dataset.view + ' selected';}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
                }]
            })
        } else if prompt.contains("typed artifact validation") {
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
                "rationale": "local runtime validated the artifact"
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
        if prompt.contains("typed artifact validation") {
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
                "strongestContradiction": null,
                "rationale": "streamed direct-author draft was accepted"
            })
            .to_string()
            .into_bytes());
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
        if !prompt.contains("direct document author")
            && !prompt.contains("Return only one complete self-contained index.html")
        {
            return self
                .execute_inference(_model_hash, input_context, _options)
                .await;
        }

        let chunks = [
            "<!doctype html><html><head><title>Quantum computers</title><style>body{margin:0;font-family:system-ui,sans-serif;background:#08111d;color:#eef2ff;}main{max-width:900px;margin:0 auto;padding:24px;display:grid;gap:16px;}section{padding:16px;border:1px solid #35506d;border-radius:16px;background:#0f1b2a;}</style></head><body><main>",
            "<section><h1>Quantum computers</h1><p>Quantum computers use qubits, superposition, and interference to explore some calculations differently from classical bits.</p><button type=\"button\" data-view=\"qubits\" aria-controls=\"qubits-panel\" aria-selected=\"true\">Qubits</button><button type=\"button\" data-view=\"gates\" aria-controls=\"gates-panel\" aria-selected=\"false\">Gates</button></section>",
            "<section id=\"qubits-panel\" data-view-panel=\"qubits\"><h2>Qubits</h2><dl><dt>State blend</dt><dd>A qubit can occupy a blend of 0 and 1 until measurement collapses the state.</dd><dt>Measurement</dt><dd>Observed amplitudes resolve into one sampled outcome.</dd></dl></section><section id=\"gates-panel\" data-view-panel=\"gates\" hidden><h2>Gates</h2><dl><dt>Rotation</dt><dd>Quantum gates rotate probability amplitudes.</dd><dt>Interference</dt><dd>Constructive interference strengthens correct paths.</dd></dl></section><aside><h2>Detail</h2><p id=\"detail-copy\">Qubits are selected by default.</p></aside>",
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

#[derive(Debug, Clone)]
struct SilentDirectAuthorReplanTestRuntime {
    provenance: crate::models::StudioRuntimeProvenance,
    direct_author_delay: Duration,
}

#[async_trait]
impl InferenceRuntime for SilentDirectAuthorReplanTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let response = if prompt.contains("typed artifact materializer") {
            serde_json::json!({
                "summary": "Recovered the requested artifact after replanning",
                "notes": ["plan-execute recovered the stalled direct-author run"],
                "files": [{
                    "path": "index.html",
                    "mime": "text/html",
                    "role": "primary",
                    "renderable": true,
                    "downloadable": true,
                    "encoding": "utf8",
                    "body": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum computers</title><style>:root{font-family:Georgia,serif;background:#08111d;color:#f5f2eb;}body{margin:0;}main{display:grid;gap:16px;max-width:960px;margin:0 auto;padding:24px;}section,aside{background:#111b2b;border:1px solid #2f4a68;border-radius:18px;padding:18px;}button{border:1px solid #5cc7ff;background:#10263a;color:#f5f2eb;border-radius:999px;padding:10px 14px;}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border-bottom:1px solid #29415a;}</style></head><body><main><section><h1>Quantum computers</h1><p>Quantum computers use qubits, interference, and measurement to process some problems differently from classical machines.</p><button type=\"button\" data-view=\"basics\" aria-controls=\"basics-panel\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"gates\" aria-controls=\"gates-panel\" aria-selected=\"false\">Gates</button></section><section id=\"basics-panel\" data-view-panel=\"basics\"><h2>Qubits</h2><dl><dt>State blend</dt><dd>A qubit can carry amplitudes for both 0 and 1 until measurement selects one outcome.</dd><dt>Observation</dt><dd>Measurement resolves the blended state into a sampled result.</dd></dl></section><section id=\"gates-panel\" data-view-panel=\"gates\" hidden><h2>Gates</h2><dl><dt>Rotation</dt><dd>Quantum gates rotate amplitudes to reshape the result distribution.</dd><dt>Interference</dt><dd>Constructive interference strengthens useful answers.</dd></dl></section><aside><h2>Detail</h2><p id=\"detail-copy\">Basics selected by default so the first paint already explains the artifact.</p><table><tr><th>Concept</th><th>Why it matters</th></tr><tr><td>Superposition</td><td>Keeps multiple amplitudes in play.</td></tr><tr><td>Interference</td><td>Amplifies useful paths.</td></tr></table></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});document.querySelectorAll('button[data-view]').forEach((control)=>control.setAttribute('aria-selected', String(control===button)));detail.textContent=button.dataset.view==='basics'?'Basics selected by default so the first paint already explains the artifact.':'Gate view selected to show how amplitudes are transformed.';}));</script></main></body></html>"
                }]
            })
            .to_string()
        } else if prompt.contains("typed artifact validation") {
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
                "rationale": "replanned artifact satisfied the request"
            })
            .to_string()
        } else {
            return Err(VmError::HostError(format!(
                "unexpected Studio prompt in replan test: {prompt}"
            )));
        };

        Ok(response.into_bytes())
    }

    async fn execute_inference_streaming(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        _token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        if prompt.contains("direct document author")
            || prompt.contains("Return only one complete self-contained index.html")
        {
            tokio::time::sleep(self.direct_author_delay).await;
            return Ok("<!doctype html><html>".as_bytes().to_vec());
        }

        self.execute_inference(model_hash, input_context, options)
            .await
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
        routing_hints: Vec::new(),
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
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
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
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
        validation: None,
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
        runtime_narration_events: Vec::new(),
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
        widget_state: None,
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
        query_profile: None,
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
        quality_rationale: "High validation score with clear structure.".to_string(),
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
