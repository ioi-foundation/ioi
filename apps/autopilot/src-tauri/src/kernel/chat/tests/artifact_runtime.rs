use super::*;
use ioi_api::chat::execution_strategy_for_outcome;

#[test]
fn materialize_nonworkspace_artifact_replans_after_direct_author_timeout_then_reports_generation_failure(
) {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: "{}".to_string(),
        delay: Duration::from_millis(50),
        provenance: Some(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "local timeout runtime".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
    });
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
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let planning_context = derive_chat_artifact_prepared_context(
        &request,
        &ChatArtifactBrief {
            audience: "operators".to_string(),
            job_to_be_done: "explain the post-quantum rollout".to_string(),
            subject_domain: "post-quantum computing".to_string(),
            artifact_thesis: "Keep the explainer specific and interactive.".to_string(),
            required_concepts: vec![
                "qubits".to_string(),
                "superposition".to_string(),
                "quantum gates".to_string(),
            ],
            required_interactions: vec!["switch between basics and gates".to_string()],
            visual_tone: vec!["editorial".to_string(), "technical".to_string()],
            factual_anchors: vec!["measurement collapses state".to_string()],
            style_directives: vec!["keep first paint useful".to_string()],
            reference_hints: Vec::new(),
            query_profile: None,
        },
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    let materialized =
        materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy(
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
            Some(planning_context),
            execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&request)),
            None,
        )
        .expect("materialization should return a blocked timeout result");

    assert_eq!(
        materialized.failure.as_ref().expect("failure").kind,
        crate::models::ChatArtifactFailureKind::GenerationFailure
    );
    assert_eq!(
        materialized.lifecycle_state,
        ChatArtifactLifecycleState::Blocked
    );
    assert!(!materialized.degraded_path_used);
    assert!(materialized.files.is_empty());
    assert!(materialized.operator_steps.iter().any(|step| {
        step.phase == ioi_api::runtime_harness::ArtifactOperatorPhase::RepairArtifact
            && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete
    }));
    assert!(materialized.operator_steps.iter().any(|step| {
        step.phase == ioi_api::runtime_harness::ArtifactOperatorPhase::AuthorArtifact
            && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Blocked
            && step.detail.contains("stalled")
    }));
    assert!(materialized
        .failure
        .as_ref()
        .expect("failure")
        .message
        .contains("did not produce a valid candidate"));
    assert!(!materialized.candidate_summaries.is_empty());
    assert_eq!(
        materialized
            .validation
            .as_ref()
            .expect("validation result")
            .classification,
        ioi_api::chat::ChatArtifactValidationStatus::Blocked
    );
}

fn chat_artifact_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("chat artifact test env lock")
}

#[test]
fn direct_author_streaming_progress_prevents_mid_document_kernel_timeout() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StreamingDirectAuthorTestRuntime {
        provenance: crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "streaming local runtime".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        chunk_delay: Duration::from_millis(120),
    });
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
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let planning_context = derive_chat_artifact_prepared_context(
        &request,
        &ChatArtifactBrief {
            audience: "curious learners".to_string(),
            job_to_be_done: "Understand how quantum computers differ from classical computers."
                .to_string(),
            subject_domain: "quantum computing".to_string(),
            artifact_thesis:
                "Use a lightweight interactive explainer to contrast qubits and gates.".to_string(),
            required_concepts: vec![
                "qubits".to_string(),
                "superposition".to_string(),
                "quantum gates".to_string(),
            ],
            required_interactions: vec!["toggle between qubit and gate explanations".to_string()],
            visual_tone: vec!["editorial".to_string(), "technical".to_string()],
            factual_anchors: vec!["measurement collapses state".to_string()],
            style_directives: vec!["keep the first paint immediately useful".to_string()],
            reference_hints: Vec::new(),
            query_profile: None,
        },
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let observed_progress = Arc::new(Mutex::new(Vec::<ChatArtifactGenerationProgress>::new()));
    let progress_sink = observed_progress.clone();

    let render_evaluator = KernelPassingRenderEvaluator;
    let materialized = materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy_and_render_evaluator(
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
        Some(planning_context),
        ChatExecutionStrategy::DirectAuthor,
        Some(Arc::new(move |progress| {
            progress_sink.lock().expect("progress log").push(progress);
        })),
        Some(&render_evaluator),
    )
    .expect("active streaming progress should keep the direct-author run alive");

    assert!(
        !materialized.files.is_empty(),
        "failure={:?} lifecycle={:?} notes={:?} validation={:?}",
        materialized.failure,
        materialized.lifecycle_state,
        materialized.notes,
        materialized.validation
    );
    assert!(
        materialized
            .files
            .iter()
            .any(|file| file.path == "index.html"),
        "failure={:?} lifecycle={:?} notes={:?} validation={:?} operator_steps={:?}",
        materialized.failure,
        materialized.lifecycle_state,
        materialized.notes,
        materialized.validation,
        materialized.operator_steps
    );
    assert_ne!(
        materialized.lifecycle_state,
        ChatArtifactLifecycleState::Blocked
    );
    let observed_progress = observed_progress.lock().expect("progress log");
    assert!(observed_progress.iter().any(|progress| {
        progress
            .execution_envelope
            .as_ref()
            .map(|envelope| {
                envelope.live_previews.iter().any(|preview| {
                    preview.label == "Direct author output"
                        && preview.content.contains("<!doctype html>")
                })
            })
            .unwrap_or(false)
    }));
    assert!(observed_progress.iter().any(|progress| {
        progress.operator_steps.iter().any(|step| {
            step.phase == ioi_api::runtime_harness::ArtifactOperatorPhase::AuthorArtifact
                && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Active
        })
    }));
    let render_eval_index = observed_progress.iter().position(|progress| {
        progress
            .current_step
            .contains("Checking the rendered draft for runtime errors")
    });
    let acceptance_index = observed_progress.iter().position(|progress| {
        progress
            .current_step
            .contains("Running acceptance verification for the direct-authored draft")
    });
    let runtime_sanity_complete_index = observed_progress.iter().position(|progress| {
        progress
            .current_step
            .contains("Runtime sanity complete. Surfacing the direct-authored artifact")
    });
    assert!(
        render_eval_index.is_some(),
        "expected a direct-author runtime sanity progress step"
    );
    assert!(
        runtime_sanity_complete_index.is_some(),
        "expected the direct-author fast path to report runtime-sanity completion"
    );
    assert!(
        acceptance_index.is_none(),
        "local direct-author html should no longer run the slow acceptance verification step"
    );
    assert!(
        render_eval_index < runtime_sanity_complete_index,
        "runtime sanity should be surfaced before the artifact handoff completes"
    );
}

#[derive(Debug, Clone)]
struct StreamingSilentDirectAuthorReplanTestRuntime {
    provenance: crate::models::ChatRuntimeProvenance,
    direct_author_delay: Duration,
    stream_attempts: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl InferenceRuntime for StreamingSilentDirectAuthorReplanTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let response = if prompt.contains("typed artifact brief planner") {
            serde_json::json!({
                "audience": "curious learners",
                "jobToBeDone": "Understand how quantum computers differ from classical computers.",
                "subjectDomain": "quantum computing",
                "artifactThesis": "Use a lightweight interactive explainer to contrast qubits and gates.",
                "requiredConcepts": ["qubits", "superposition", "quantum gates"],
                "requiredInteractions": ["toggle between qubit and gate explanations"],
                "visualTone": ["editorial", "technical"],
                "factualAnchors": ["measurement collapses state"],
                "styleDirectives": ["keep the first paint immediately useful"],
                "referenceHints": []
            })
            .to_string()
        } else if prompt.contains("typed artifact materializer") {
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
                    "body": slow_replan_quantum_repair_document()
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
                "unexpected Chat prompt in streaming replan test: {prompt}"
            )));
        };

        Ok(response.into_bytes())
    }

    async fn execute_inference_streaming(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        if prompt.contains("Author the artifact directly")
            || prompt.contains("direct document author")
            || prompt.contains("Return only one complete self-contained index.html")
        {
            let attempt = self
                .stream_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt == 0 {
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(
                            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum explorer</title><style>body{background:#0f172a;color:#e2e8f0;}".to_string(),
                        )
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                tokio::time::sleep(self.direct_author_delay).await;
                return Ok("<!doctype html><html>".as_bytes().to_vec());
            }

            return Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum computers</title><style>:root{font-family:Georgia,serif;background:#08111d;color:#f5f2eb;}body{margin:0;}main{display:grid;gap:16px;max-width:960px;margin:0 auto;padding:24px;}section,aside{background:#111b2b;border:1px solid #2f4a68;border-radius:18px;padding:18px;}button{border:1px solid #5cc7ff;background:#10263a;color:#f5f2eb;border-radius:999px;padding:10px 14px;}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border-bottom:1px solid #29415a;}</style></head><body><main><section><h1>Quantum computers</h1><p>Quantum computers use qubits, interference, and measurement to process some problems differently from classical machines.</p><button type=\"button\" data-view=\"basics\" aria-controls=\"basics-panel\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"gates\" aria-controls=\"gates-panel\" aria-selected=\"false\">Gates</button></section><section id=\"basics-panel\" data-view-panel=\"basics\"><h2>Qubits</h2><dl><dt>State blend</dt><dd>A qubit can carry amplitudes for both 0 and 1 until measurement selects one outcome.</dd><dt>Observation</dt><dd>Measurement resolves the blended state into a sampled result.</dd></dl></section><section id=\"gates-panel\" data-view-panel=\"gates\" hidden><h2>Gates</h2><dl><dt>Rotation</dt><dd>Quantum gates rotate amplitudes to reshape the result distribution.</dd><dt>Interference</dt><dd>Constructive interference strengthens useful answers.</dd></dl></section><aside><h2>Detail</h2><p id=\"detail-copy\">Basics selected by default so the first paint already explains the artifact.</p><table><tr><th>Concept</th><th>Why it matters</th></tr><tr><td>Superposition</td><td>Keeps multiple amplitudes in play.</td></tr><tr><td>Interference</td><td>Amplifies useful paths.</td></tr></table></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});document.querySelectorAll('button[data-view]').forEach((control)=>control.setAttribute('aria-selected', String(control===button)));detail.textContent=button.dataset.view==='basics'?'Basics selected by default so the first paint already explains the artifact.':'Gate view selected to show how amplitudes are transformed.';}));</script></main></body></html>".as_bytes().to_vec());
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

    fn chat_runtime_provenance(&self) -> crate::models::ChatRuntimeProvenance {
        self.provenance.clone()
    }
}

#[derive(Debug, Clone)]
struct SlowPlanExecuteAfterReplanTestRuntime {
    provenance: crate::models::ChatRuntimeProvenance,
    direct_author_delay: Duration,
    plan_execute_delay: Duration,
    stream_attempts: Arc<std::sync::atomic::AtomicUsize>,
}

fn slow_replan_quantum_repair_document() -> &'static str {
    r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Quantum computers</title><style>:root{font-family:Arial,sans-serif;background:#f5f7fb;color:#111827;}body{margin:0;background:#f5f7fb;color:#111827;}main{display:grid;gap:18px;max-width:980px;margin:0 auto;padding:24px;}section,aside,fieldset{background:#ffffff;color:#111827;border:1px solid #9ca3af;border-radius:10px;padding:20px;}h1{font-size:36px;line-height:1.1;margin:0 0 12px;}h2{font-size:24px;line-height:1.2;margin:0 0 10px;}p{font-size:16px;line-height:1.55;}fieldset{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;}legend{font-weight:800;padding:0 6px;}label{display:flex;gap:8px;align-items:center;border:1px solid #6b7280;border-radius:8px;padding:12px;background:#eef2ff;color:#111827;font-weight:700;}input{accent-color:#111827;}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border-bottom:1px solid #9ca3af;text-align:left;}th{font-weight:800;}</style></head><body><main><section><h1>Quantum computers</h1><p>Quantum computers use qubits, gates, interference, and measurement to process some problems differently from classical machines.</p></section><fieldset aria-label="Switch explainer focus"><legend>Switch between concepts</legend><label><input type="radio" name="focus" value="basics">Basics</label><label><input type="radio" name="focus" value="qubits">Qubits</label><label><input type="radio" name="focus" value="gates">Gates</label><label><input type="radio" name="focus" value="measurement">Measurement</label></fieldset><section><h2>Qubits</h2><p>A qubit carries amplitudes for multiple outcomes until measurement returns one classical result.</p></section><section><h2>Quantum gates</h2><p>Gates rotate amplitudes and make useful answers more likely through interference.</p></section><section><h2>Measurement</h2><p>Measurement converts the quantum state into observed bits, so algorithms are designed around probability and verification.</p></section><aside role="status" aria-live="polite"><h2>Classical vs quantum</h2><p id="detail-copy">Basics selected: classical bits hold one visible value, while qubits carry amplitudes that can interfere before measurement.</p><table><tr><th>Concept</th><th>Why it matters</th></tr><tr><td>Superposition</td><td>Keeps multiple amplitudes in play.</td></tr><tr><td>Interference</td><td>Amplifies useful paths.</td></tr><tr><td>Measurement</td><td>Returns one classical outcome.</td></tr></table></aside><script>const detail=document.getElementById('detail-copy');const copy={basics:'Basics selected: classical bits hold one visible value, while qubits carry amplitudes that can interfere before measurement.',qubits:'Qubits selected: amplitudes describe possible outcomes before an observation is made.',gates:'Gates selected: operations rotate amplitudes so interference can strengthen useful answers.',measurement:'Measurement selected: the final readout samples one classical result from the quantum state.'};document.querySelectorAll('input[name="focus"]').forEach((control)=>control.addEventListener('change',()=>{if(control.checked&&detail){detail.textContent=copy[control.value]||copy.basics;}}));</script></main></body></html>"#
}

#[async_trait]
impl InferenceRuntime for SlowPlanExecuteAfterReplanTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context);
        let response = if prompt.contains("typed artifact brief planner") {
            tokio::time::sleep(self.plan_execute_delay).await;
            serde_json::json!({
                "audience": "curious learners",
                "jobToBeDone": "Understand how quantum computers differ from classical computers.",
                "subjectDomain": "quantum computing",
                "artifactThesis": "Use a lightweight interactive explainer to contrast qubits and gates.",
                "requiredConcepts": ["qubits", "superposition", "quantum gates"],
                "requiredInteractions": ["toggle between qubit and gate explanations"],
                "visualTone": ["editorial", "technical"],
                "factualAnchors": ["measurement collapses state"],
                "styleDirectives": ["keep the first paint immediately useful"],
                "referenceHints": []
            })
            .to_string()
        } else if prompt.contains("typed direct document repair author") {
            tokio::time::sleep(self.plan_execute_delay).await;
            slow_replan_quantum_repair_document().to_string()
        } else if prompt.contains("typed artifact materializer") {
            tokio::time::sleep(self.plan_execute_delay).await;
            serde_json::json!({
                "summary": "Recovered the requested artifact after replanning",
                "notes": ["plan-execute stayed alive through a quiet materialization pass"],
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
            tokio::time::sleep(self.plan_execute_delay).await;
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
                "rationale": "plan-execute quiet phases should not trip the outer inactivity watchdog"
            })
            .to_string()
        } else {
            return Err(VmError::HostError(format!(
                "unexpected Chat prompt in slow plan-execute replan test: {prompt}"
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
        if prompt.contains("typed direct document repair author") {
            tokio::time::sleep(self.plan_execute_delay).await;
            return Ok(slow_replan_quantum_repair_document().as_bytes().to_vec());
        }
        if prompt.contains("Author the artifact directly")
            || prompt.contains("direct document author")
            || prompt.contains("Return only one complete self-contained index.html")
        {
            let attempt = self
                .stream_attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt == 0 {
                tokio::time::sleep(self.direct_author_delay).await;
                return Ok("<!doctype html><html>".as_bytes().to_vec());
            }

            tokio::time::sleep(self.plan_execute_delay).await;
            return Ok(slow_replan_quantum_repair_document().as_bytes().to_vec());
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

    fn chat_runtime_provenance(&self) -> crate::models::ChatRuntimeProvenance {
        self.provenance.clone()
    }
}

#[test]
fn direct_author_inactivity_replans_to_plan_execute_and_returns_artifact() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SilentDirectAuthorReplanTestRuntime {
        provenance: crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "silent direct-author runtime".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        direct_author_delay: Duration::from_millis(400),
        stream_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    });
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
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let planning_context = derive_chat_artifact_prepared_context(
        &request,
        &ChatArtifactBrief {
            audience: "curious learners".to_string(),
            job_to_be_done: "Understand how quantum computers differ from classical computers."
                .to_string(),
            subject_domain: "quantum computing".to_string(),
            artifact_thesis:
                "Use a request-specific interactive explainer to contrast qubits and gates."
                    .to_string(),
            required_concepts: vec![
                "qubits".to_string(),
                "superposition".to_string(),
                "quantum gates".to_string(),
            ],
            required_interactions: vec!["switch between basics and gates".to_string()],
            visual_tone: vec!["editorial".to_string(), "technical".to_string()],
            factual_anchors: vec!["measurement collapses state".to_string()],
            style_directives: vec!["keep first paint useful".to_string()],
            reference_hints: Vec::new(),
            query_profile: None,
        },
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    let materialized =
        materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy(
            &proof_memory_runtime(),
            Some(runtime.clone()),
            Some(runtime),
            "thread-1",
            "Quantum explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            None,
            Duration::from_millis(120),
            None,
            Some(planning_context),
            ChatExecutionStrategy::DirectAuthor,
            None,
        )
        .expect("silent direct-author runs should replan instead of blocking the artifact route");

    assert!(
        materialized
            .files
            .iter()
            .any(|file| file.path == "index.html"),
        "failure={:?} lifecycle={:?} notes={:?} validation={:?} operator_steps={:?}",
        materialized.failure,
        materialized.lifecycle_state,
        materialized.notes,
        materialized.validation,
        materialized.operator_steps
    );
    assert_eq!(
        materialized
            .execution_envelope
            .as_ref()
            .and_then(|envelope| envelope.strategy),
        Some(ChatExecutionStrategy::PlanExecute)
    );
    assert!(materialized.operator_steps.iter().any(|step| {
        step.phase == ioi_api::runtime_harness::ArtifactOperatorPhase::RepairArtifact
            && step
                .detail
                .contains("continuing with plan execute so the artifact route can still finish")
    }));
    assert!(materialized.failure.is_none());
}

#[test]
fn direct_author_replan_terminalizes_stale_stream_preview_before_plan_execute() {
    let _env_guard = chat_artifact_env_lock();
    let runtime: Arc<dyn InferenceRuntime> =
        Arc::new(StreamingSilentDirectAuthorReplanTestRuntime {
            provenance: crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "streaming silent direct-author runtime".to_string(),
                model: Some("qwen3.5:9b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            },
            direct_author_delay: Duration::from_millis(400),
            stream_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
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
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let planning_context = derive_chat_artifact_prepared_context(
        &request,
        &ChatArtifactBrief {
            audience: "curious learners".to_string(),
            job_to_be_done: "Understand how quantum computers differ from classical computers."
                .to_string(),
            subject_domain: "quantum computing".to_string(),
            artifact_thesis:
                "Use a request-specific interactive explainer to contrast qubits and gates."
                    .to_string(),
            required_concepts: vec![
                "qubits".to_string(),
                "superposition".to_string(),
                "quantum gates".to_string(),
            ],
            required_interactions: vec!["switch between basics and gates".to_string()],
            visual_tone: vec!["editorial".to_string(), "technical".to_string()],
            factual_anchors: vec!["measurement collapses state".to_string()],
            style_directives: vec!["keep first paint useful".to_string()],
            reference_hints: Vec::new(),
            query_profile: None,
        },
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let observed_progress = Arc::new(Mutex::new(Vec::<ChatArtifactGenerationProgress>::new()));
    let progress_observer: ChatArtifactGenerationProgressObserver = {
        let observed_progress = observed_progress.clone();
        Arc::new(move |progress| {
            observed_progress
                .lock()
                .expect("progress log")
                .push(progress);
        })
    };

    let materialized =
        materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy(
            &proof_memory_runtime(),
            Some(runtime.clone()),
            Some(runtime),
            "thread-1",
            "Quantum explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            None,
            Duration::from_millis(120),
            None,
            Some(planning_context),
            ChatExecutionStrategy::DirectAuthor,
            Some(progress_observer),
        )
        .expect("streaming direct-author runs should replan instead of leaving the preview live");

    assert!(
        materialized
            .files
            .iter()
            .any(|file| file.path == "index.html"),
        "failure={:?} lifecycle={:?} notes={:?} validation={:?} operator_steps={:?}",
        materialized.failure,
        materialized.lifecycle_state,
        materialized.notes,
        materialized.validation,
        materialized.operator_steps
    );
    assert_eq!(
        materialized
            .execution_envelope
            .as_ref()
            .and_then(|envelope| envelope.strategy),
        Some(ChatExecutionStrategy::PlanExecute)
    );

    let observed_progress = observed_progress.lock().expect("progress log");
    assert!(observed_progress.iter().any(|progress| {
        progress
            .execution_envelope
            .as_ref()
            .map(|envelope| {
                envelope.live_previews.iter().any(|preview| {
                    preview.label == "Direct author output"
                        && preview.status == "streaming"
                        && preview.content.contains("Quantum explorer")
                })
            })
            .unwrap_or(false)
    }));
    assert!(observed_progress.iter().any(|progress| {
        progress.current_step == "Direct author stalled. Replanning artifact execution."
            && progress
                .execution_envelope
                .as_ref()
                .and_then(|envelope| {
                    envelope
                        .live_previews
                        .iter()
                        .find(|preview| preview.label == "Direct author output")
                })
                .map(|preview| preview.status == "interrupted" && preview.is_final)
                .unwrap_or(false)
    }));
}

#[test]
fn replanned_plan_execute_quiet_materialization_stays_alive_past_outer_inactivity_budget() {
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowPlanExecuteAfterReplanTestRuntime {
        provenance: crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "slow replanned plan-execute runtime".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        },
        direct_author_delay: Duration::from_millis(400),
        plan_execute_delay: Duration::from_millis(400),
        stream_attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    });
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
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let planning_context = derive_chat_artifact_prepared_context(
        &request,
        &ChatArtifactBrief {
            audience: "curious learners".to_string(),
            job_to_be_done: "Understand how quantum computers differ from classical computers."
                .to_string(),
            subject_domain: "quantum computing".to_string(),
            artifact_thesis:
                "Use a request-specific interactive explainer to contrast qubits and gates."
                    .to_string(),
            required_concepts: vec![
                "qubits".to_string(),
                "superposition".to_string(),
                "quantum gates".to_string(),
            ],
            required_interactions: vec!["switch between basics and gates".to_string()],
            visual_tone: vec!["editorial".to_string(), "technical".to_string()],
            factual_anchors: vec!["measurement collapses state".to_string()],
            style_directives: vec!["keep first paint useful".to_string()],
            reference_hints: Vec::new(),
            query_profile: None,
        },
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    let materialized =
        materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy(
            &proof_memory_runtime(),
            Some(runtime.clone()),
            Some(runtime),
            "thread-1",
            "Quantum explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            None,
            Duration::from_millis(120),
            None,
            Some(planning_context),
            ChatExecutionStrategy::DirectAuthor,
            None,
        )
        .expect(
            "quiet replanned plan-execute phases should stay alive instead of tripping outer inactivity",
        );

    assert!(materialized
        .files
        .iter()
        .any(|file| file.path == "index.html"));
    assert_eq!(
        materialized
            .execution_envelope
            .as_ref()
            .and_then(|envelope| envelope.strategy),
        Some(ChatExecutionStrategy::PlanExecute)
    );
    assert!(materialized.failure.is_none());
    assert_ne!(
        materialized.lifecycle_state,
        ChatArtifactLifecycleState::Blocked,
        "validation={:?} notes={:?} operator_steps={:?}",
        materialized.validation,
        materialized.notes,
        materialized.operator_steps
    );
}

#[test]
fn chat_generation_timeout_extends_local_modal_first_html_for_split_acceptance() {
    let _env_guard = chat_artifact_env_lock();
    let previous_profile = std::env::var("AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE").ok();
    let previous_timeout = std::env::var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS").ok();

    std::env::set_var(
        "AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE",
        "local_generation_remote_acceptance",
    );
    std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS");

    let runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatArtifactGenerationTestRuntime::new(
        crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen3:8b",
        "http://127.0.0.1:11434/v1/chat/completions",
    ));
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
            require_export: true,
            require_diff_review: false,
        },
    };

    let timeout = with_chat_modal_first_html_override(true, || {
        chat_generation_timeout_for_request(&request, &runtime)
    });

    match previous_profile {
        Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE", value),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE"),
    }
    match previous_timeout {
        Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS", value),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS"),
    }

    assert_eq!(timeout, Duration::from_secs(1200));
}

#[test]
fn direct_author_timeout_uses_strategy_budget_for_local_html() {
    let _env_guard = chat_artifact_env_lock();
    let previous_profile = std::env::var("AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE").ok();
    let previous_timeout = std::env::var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS").ok();

    std::env::set_var(
        "AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE",
        "local_generation_remote_acceptance",
    );
    std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS");

    let runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatArtifactGenerationTestRuntime::new(
        crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen3.5:9b",
        "http://127.0.0.1:11434/v1/chat/completions",
    ));
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
            require_export: true,
            require_diff_review: false,
        },
    };

    let timeout = with_chat_modal_first_html_override(true, || {
        chat_generation_timeout_for_request_and_execution_strategy(
            &request,
            &runtime,
            None,
            ChatExecutionStrategy::DirectAuthor,
        )
    });

    match previous_profile {
        Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE", value),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_MODEL_ROUTING_PROFILE"),
    }
    match previous_timeout {
        Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS", value),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_GENERATION_TIMEOUT_SECS"),
    }

    assert_eq!(timeout, Duration::from_secs(155));
}

#[test]
fn nonworkspace_materialization_contract_starts_pending_and_blocks_truthfully_on_failure() {
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
            require_export: true,
            require_diff_review: false,
        },
    };

    let contract = materialization_contract_for_request(
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        "Chat will author the artifact directly.",
        None,
        ChatExecutionStrategy::DirectAuthor,
    );
    assert_eq!(contract.operator_steps.len(), 2);
    assert!(contract.operator_steps.iter().any(|step| {
        step.step_id == "materialize_artifact"
            && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Pending
    }));
    assert!(contract.operator_steps.iter().any(|step| {
        step.step_id == "verify_artifact_contract"
            && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Pending
    }));

    let blocked = blocked_materialized_artifact_from_error(
        "Quantum explainer",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        None,
        "Chat artifact generation timed out after 135s while authoring the artifact directly.",
        None,
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
        Some(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
        Some(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        }),
    );
    assert!(blocked.operator_steps.iter().any(|step| {
        step.step_id == "present_artifact"
            && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Blocked
    }));
}

#[test]
fn blocked_nonworkspace_artifact_terminalizes_preview_and_invariant_state() {
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
            require_export: true,
            require_diff_review: false,
        },
    };

    let mut contract = materialization_contract_for_request(
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        "Chat will author the artifact directly.",
        None,
        ChatExecutionStrategy::DirectAuthor,
    );
    contract
        .execution_envelope
        .as_mut()
        .expect("direct author contract should seed an execution envelope")
        .live_previews
        .push(ExecutionLivePreview {
            id: "candidate-1-live-output".to_string(),
            kind: ExecutionLivePreviewKind::TokenStream,
            label: "Direct author output".to_string(),
            work_item_id: None,
            role: None,
            status: "streaming".to_string(),
            language: Some("html".to_string()),
            content: "<style>.callout.show { display: block; }</style>".to_string(),
            is_final: false,
            updated_at: "2026-04-12T17:59:00Z".to_string(),
        });

    let blocked = blocked_materialized_artifact_from_error(
        "Quantum explainer",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        None,
        "attempt 2 inference failed: Host function error: Local Ollama native chat ended without content",
        None,
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
        contract.execution_envelope.clone(),
        None,
        None,
        vec![ioi_api::runtime_harness::ArtifactOperatorStep {
            step_id: "author_artifact:candidate-1".to_string(),
            origin_prompt_event_id: String::new(),
            phase: ioi_api::runtime_harness::ArtifactOperatorPhase::AuthorArtifact,
            engine: "materialization".to_string(),
            status: ioi_api::runtime_harness::ArtifactOperatorRunStatus::Blocked,
            label: "Write artifact".to_string(),
            detail: "Chat is authoring the first attempt.".to_string(),
            started_at_ms: 0,
            finished_at_ms: Some(0),
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        }],
        Some(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
        Some(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
    );

    let invariant = blocked
        .execution_envelope
        .as_ref()
        .and_then(|envelope| envelope.completion_invariant.as_ref())
        .expect("blocked artifact should retain a completion invariant");
    assert_eq!(
        invariant.status,
        ExecutionCompletionInvariantStatus::Blocked
    );

    let latest_preview = blocked
        .execution_envelope
        .as_ref()
        .and_then(|envelope| envelope.live_previews.last())
        .expect("blocked artifact should retain the latest preview");
    assert_eq!(latest_preview.status, "interrupted");
    assert!(latest_preview.is_final);

    let latest_preview_event = blocked
        .operator_steps
        .iter()
        .rev()
        .find_map(|step| step.preview.as_ref())
        .expect("blocked artifact should retain a terminal preview on the blocked author step");
    assert_eq!(latest_preview_event.status, "interrupted");
    assert!(latest_preview_event.is_final);
}

#[test]
fn apply_materialized_artifact_to_contract_marks_nonworkspace_steps_success_when_ready() {
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
            require_export: true,
            require_diff_review: false,
        },
    };
    let mut contract = materialization_contract_for_request(
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        "Chat created an artifact.",
        None,
        ChatExecutionStrategy::DirectAuthor,
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
        None,
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
        Some(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
        Some(crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
            label: "openai-compatible".to_string(),
            model: Some("qwen3.5:9b".to_string()),
            endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
        }),
    );
    ready.file_writes = vec![crate::models::ChatArtifactMaterializationFileWrite {
        path: "index.html".to_string(),
        kind: "primary".to_string(),
        content_preview: Some("<!doctype html>".to_string()),
    }];
    ready.lifecycle_state = ChatArtifactLifecycleState::Ready;
    ready.verification_summary = "Acceptance cleared the artifact.".to_string();
    ready.failure = None;
    ready.ux_lifecycle = ChatArtifactUxLifecycle::Validated;
    ready.winning_candidate_id = Some("candidate-1".to_string());
    ready.validation = Some(ChatArtifactValidationResult {
        classification: ioi_api::chat::ChatArtifactValidationStatus::Pass,
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
        ..chat_validation_fixture()
    });
    ready.operator_steps = vec![
        ioi_api::runtime_harness::ArtifactOperatorStep {
            step_id: "materialize_artifact".to_string(),
            origin_prompt_event_id: String::new(),
            phase: ioi_api::runtime_harness::ArtifactOperatorPhase::AuthorArtifact,
            engine: "materialization".to_string(),
            status: ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete,
            label: "Materialize artifact".to_string(),
            detail: "Materialize artifact completed.".to_string(),
            started_at_ms: 0,
            finished_at_ms: Some(0),
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        },
        ioi_api::runtime_harness::ArtifactOperatorStep {
            step_id: "verify_artifact_contract".to_string(),
            origin_prompt_event_id: String::new(),
            phase: ioi_api::runtime_harness::ArtifactOperatorPhase::VerifyArtifact,
            engine: "materialization".to_string(),
            status: ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete,
            label: "Verify artifact contract".to_string(),
            detail: "Verify artifact contract completed.".to_string(),
            started_at_ms: 0,
            finished_at_ms: Some(0),
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        },
    ];

    apply_materialized_artifact_to_contract(
        &mut contract,
        &request,
        &ready,
        None,
        ChatExecutionStrategy::DirectAuthor,
    );

    assert!(contract.operator_steps.iter().any(|step| {
        step.step_id == "materialize_artifact"
            && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete
    }));
    assert!(contract.operator_steps.iter().any(|step| {
        step.step_id == "verify_artifact_contract"
            && step.status == ioi_api::runtime_harness::ArtifactOperatorRunStatus::Complete
    }));
    assert_eq!(contract.file_writes.len(), 1);
    assert_eq!(
        contract.winning_candidate_id.as_deref(),
        Some("candidate-1")
    );
    assert!(contract.failure.is_none());
}

#[test]
fn provisional_nonworkspace_session_surfaces_planning_context_before_materialization_finishes() {
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
            require_export: true,
            require_diff_review: false,
        },
    };
    let outcome_request = ChatOutcomeRequest {
        request_id: "request-1".to_string(),
        raw_prompt: "Create an interactive HTML artifact that explains a rollout".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Artifact,
        execution_strategy: ChatExecutionStrategy::AdaptiveWorkGraph,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: Vec::new(),
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request.clone()),
    };
    let title = "Rollout explainer";
    let summary = summary_for_request(&request, title);
    let brief = ChatArtifactBrief {
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
        query_profile: None,
    };
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);
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
    materialization.selected_skills = vec![ioi_api::chat::ChatArtifactSelectedSkill {
        skill_hash: "a".repeat(64),
        name: "artifact__frontend_validation_spine".to_string(),
        description: "Front-end structural guidance".to_string(),
        lifecycle_state: "published".to_string(),
        source_type: "filesystem".to_string(),
        reliability_bps: 9500,
        semantic_score_bps: 9100,
        adjusted_score_bps: 9450,
        relative_path: Some("skills/artifact__frontend_validation_spine/SKILL.md".to_string()),
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![ioi_api::chat::ChatArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched the visual art direction need.".to_string(),
        guidance_markdown: Some("Use strong hierarchy and visible evidence framing.".to_string()),
    }];

    let chat_session = super::prepare::provisional_non_workspace_chat_session(
        "thread-1",
        "chat-session-1",
        title,
        &summary,
        "2026-04-04T00:00:00Z",
        &outcome_request,
        Some("prompt-evt-1"),
        materialization,
    )
    .expect("provisional session");

    assert_eq!(
        chat_session.lifecycle_state,
        ChatArtifactLifecycleState::Materializing
    );
    assert_eq!(
        chat_session.artifact_manifest.verification.status,
        ChatArtifactVerificationStatus::Pending
    );
    assert_eq!(
        chat_session.verified_reply.status,
        ChatArtifactVerificationStatus::Pending
    );
    assert_eq!(chat_session.session_id, "chat-session-1");
    assert_eq!(chat_session.materialization.selected_skills.len(), 1);
    assert_eq!(chat_session.retrieved_exemplars.len(), 0);
    assert!(chat_session
        .artifact_manifest
        .verification
        .summary
        .contains(&blueprint.scaffold_family));
    assert!(chat_session
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
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatArtifactGenerationTestRuntime::new(
        crate::models::ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
    ));
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
            require_export: true,
            require_diff_review: false,
        },
    };

    let materialized =
        materialize_chat_artifact_with_dependencies_and_timeout_and_execution_strategy(
            &proof_memory_runtime(),
            Some(runtime),
            None,
            "thread-1",
            "Chat rollout",
            "Create an interactive HTML artifact that explains a product rollout with charts",
            &request,
            None,
            Duration::from_secs(5),
            None,
            None,
            execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&request)),
            None,
        )
        .expect("materialization should succeed with a local fallback");

    assert!(matches!(
        materialized.lifecycle_state,
        ChatArtifactLifecycleState::Partial | ChatArtifactLifecycleState::Blocked
    ));
    assert!(!materialized.degraded_path_used);
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
            .validation
            .as_ref()
            .expect("validation result")
            .classification,
        if materialized.lifecycle_state == ChatArtifactLifecycleState::Blocked {
            ioi_api::chat::ChatArtifactValidationStatus::Blocked
        } else {
            ioi_api::chat::ChatArtifactValidationStatus::Repairable
        }
    );
}

#[test]
fn manifest_generation_for_markdown_artifacts_is_renderable() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Document,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::Markdown,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::None,
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
        ChatArtifactLifecycleState::Ready,
    );
    assert_eq!(manifest.renderer, ChatRendererKind::Markdown);
    assert_eq!(manifest.primary_tab, "render");
    assert_eq!(manifest.tabs.len(), 3);
}

#[test]
fn static_html_recipe_materializes_real_web_files() {
    let files = static_html_template_files(
        "tennis company html page",
        "tennis-company-html-page",
        Some(ChatStaticHtmlArchetype::SportEditorial),
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
        Some(ChatStaticHtmlArchetype::MinimalAgency),
    );
    let product = static_html_template_files(
        "ai product launch html page",
        "ai-product-launch-html-page",
        Some(ChatStaticHtmlArchetype::ProductLaunch),
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
    assert!(agency_index.contains("Independent chat practice"));
    assert!(product_index.contains("New release / product system"));
}

#[test]
fn html_iframe_generation_uses_model_first_runtime() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::Inline,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: Some("product-launch".to_string()),
        scope: crate::models::ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::ChatOutcomeArtifactVerificationRequest {
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
    assert!(!payload.files[0].body.contains("chat-rollout-briefing"));
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("patch-first refinements")));
}

#[test]
fn model_first_html_iframe_payload_clears_presentation_gate() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::Inline,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: Some("product-launch".to_string()),
        scope: crate::models::ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::ChatOutcomeArtifactVerificationRequest {
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
        ChatArtifactLifecycleState::Ready
    );
}

#[test]
fn html_generation_failure_blocks_primary_artifact_without_synthetic_fallback() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::Inline,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: Some("product-launch".to_string()),
        scope: crate::models::ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::ChatOutcomeArtifactVerificationRequest {
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
            "simulated chat materialization failure",
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
            Some(crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
                label: "opaque test runtime".to_string(),
                model: None,
                endpoint: None,
            }),
            Some(crate::models::ChatRuntimeProvenance {
                kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            }),
        );

    assert!(!blocked.degraded_path_used);
    assert_eq!(blocked.lifecycle_state, ChatArtifactLifecycleState::Blocked);
    assert_eq!(
        blocked
            .validation
            .as_ref()
            .expect("validation result")
            .classification,
        ioi_api::chat::ChatArtifactValidationStatus::Blocked
    );
    assert_eq!(
        blocked.output_origin,
        ChatArtifactOutputOrigin::OpaqueRuntime
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
        crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime
    );
    assert_eq!(
        blocked
            .acceptance_provenance
            .as_ref()
            .expect("acceptance provenance")
            .kind,
        crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable
    );
    assert_eq!(blocked.files.len(), 0);
    assert_eq!(
        blocked.brief.subject_domain,
        "Productivity assistant rollout"
    );
    assert_eq!(
        blocked
            .validation
            .as_ref()
            .expect("validation result")
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
    attach_blocked_chat_failure_session(
        &mut task,
        prompt,
        None,
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        },
        crate::models::ChatArtifactFailure {
            kind: crate::models::ChatArtifactFailureKind::InferenceUnavailable,
            code: "inference_unavailable".to_string(),
            message: "Local inference runtime is offline.".to_string(),
        },
    );
    let chat_session = task.chat_session.as_ref().expect("chat session");

    assert_eq!(
        chat_session.lifecycle_state,
        ChatArtifactLifecycleState::Blocked
    );
    assert_eq!(
        chat_session.artifact_manifest.verification.status,
        ChatArtifactVerificationStatus::Blocked
    );
    assert_eq!(
        chat_session
            .artifact_manifest
            .verification
            .production_provenance
            .as_ref()
            .expect("production provenance")
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
    assert_eq!(chat_session.artifact_manifest.files.len(), 0);
    assert!(chat_session
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
        ChatArtifactLifecycleState::Materializing,
    );
    manifest.primary_tab = "workspace".to_string();
    let mut materialization = materialization_contract_for_request(
        "Build a workspace artifact",
        &request,
        "Chat provisioned the workspace artifact.",
        None,
        ChatExecutionStrategy::PlanExecute,
    );
    materialization
        .file_writes
        .push(ChatArtifactMaterializationFileWrite {
            path: "src/App.tsx".to_string(),
            kind: "create".to_string(),
            content_preview: Some("export default function App() {}".to_string()),
        });

    let pending_steps = pipeline_steps_for_state(
        "Build a workspace artifact",
        &request,
        &manifest,
        &materialization,
        ChatArtifactLifecycleState::Materializing,
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
    ready_build.receipts.push(ChatBuildReceipt {
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
    manifest.verification = ChatArtifactManifestVerification {
        status: ChatArtifactVerificationStatus::Ready,
        lifecycle_state: ChatArtifactLifecycleState::Ready,
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
        ChatArtifactLifecycleState::Ready,
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
    let brief = ChatArtifactBrief {
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
        query_profile: None,
    };
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);
    let manifest = artifact_manifest_for_request(
        "Release artifact",
        &request,
        &["artifact-1".to_string()],
        None,
        None,
        ChatArtifactLifecycleState::Ready,
    );
    let mut materialization = materialization_contract_for_request(
        "Create an interactive release artifact",
        &request,
        "Chat created an interactive artifact.",
        None,
        ChatExecutionStrategy::PlanExecute,
    );
    materialization.blueprint = Some(blueprint);
    materialization.artifact_ir = Some(artifact_ir);
    materialization.selected_skills = vec![ioi_api::chat::ChatArtifactSelectedSkill {
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
        matched_need_kinds: vec![ioi_api::chat::ChatArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched visual art direction for the comparison story scaffold."
            .to_string(),
        guidance_markdown: Some("# frontend_editorial_direction".to_string()),
    }];

    let steps = pipeline_steps_for_state(
        "Create an interactive release artifact",
        &request,
        &manifest,
        &materialization,
        ChatArtifactLifecycleState::Ready,
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
fn pipeline_steps_surface_candidates_validation_and_taste_memory() {
    let request = test_outcome_request().artifact.expect("artifact request");
    let manifest = test_manifest(ChatArtifactVerificationStatus::Ready);
    let mut materialization = test_materialization_contract();
    materialization.output_origin = Some(ioi_api::chat::ChatArtifactOutputOrigin::LiveInference);
    materialization.winning_candidate_id = Some("candidate-2".to_string());
    materialization.winning_candidate_rationale =
        Some("Repair pass cleared the mapped-panel contract.".to_string());
    materialization.candidate_summaries = vec![
        ioi_api::chat::ChatArtifactCandidateSummary {
            candidate_id: "candidate-1".to_string(),
            seed: 11,
            model: "fixture".to_string(),
            temperature: 0.4,
            strategy: "initial".to_string(),
            origin: ioi_api::chat::ChatArtifactOutputOrigin::FixtureRuntime,
            provenance: None,
            summary: "Initial draft".to_string(),
            renderable_paths: vec!["index.html".to_string()],
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::chat::ChatArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: None,
                pass_kind: "initial".to_string(),
                pass_index: 0,
                score_total: 15,
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
                ..chat_validation_fixture()
            },
        },
        ioi_api::chat::ChatArtifactCandidateSummary {
            candidate_id: "candidate-2".to_string(),
            seed: 11,
            model: "fixture".to_string(),
            temperature: 0.25,
            strategy: "repair".to_string(),
            origin: ioi_api::chat::ChatArtifactOutputOrigin::LiveInference,
            provenance: None,
            summary: "Repaired winner".to_string(),
            renderable_paths: vec!["index.html".to_string()],
            selected: true,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::chat::ChatArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: Some("candidate-1".to_string()),
                pass_kind: "structural_repair".to_string(),
                pass_index: 1,
                score_total: 24,
                score_delta_from_parent: Some(9),
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
                ..chat_validation_fixture()
            },
        },
    ];
    materialization.validation = materialization
        .candidate_summaries
        .last()
        .map(|candidate| candidate.validation.clone());
    materialization.artifact_ir = Some(ioi_api::chat::ChatArtifactIR {
        version: 1,
        renderer: ChatRendererKind::Markdown,
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
    let taste_memory = ioi_api::chat::ChatArtifactTasteMemory {
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
        ChatArtifactLifecycleState::Ready,
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
        .any(|output| output == "validation:pass"));
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
fn pipeline_steps_keep_skill_discovery_distinct_from_brief_preparation() {
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
            require_export: true,
            require_diff_review: false,
        },
    };
    let brief = ChatArtifactBrief {
        audience: "curious learners".to_string(),
        job_to_be_done: "understand quantum computing through an interactive artifact".to_string(),
        subject_domain: "quantum computing".to_string(),
        artifact_thesis: "Explain quantum computing through visible evidence and interaction."
            .to_string(),
        required_concepts: vec![
            "qubits".to_string(),
            "superposition".to_string(),
            "measurement".to_string(),
        ],
        required_interactions: vec!["view switching".to_string()],
        visual_tone: vec!["editorial".to_string(), "technical".to_string()],
        factual_anchors: vec!["qubit states".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["quantum comparisons".to_string()],
        query_profile: None,
    };
    let prepared_context = derive_chat_artifact_prepared_context(
        &request,
        &brief,
        None,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let mut materialization = materialization_contract_for_request(
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        "Chat is preparing the artifact.",
        None,
        ChatExecutionStrategy::DirectAuthor,
    );
    materialization.preparation_needs = prepared_context.preparation_needs.clone();
    materialization.skill_discovery_resolution =
        Some(ioi_api::chat::ChatArtifactSkillDiscoveryResolution {
            status: "resolved".to_string(),
            guidance_status: "attached".to_string(),
            guidance_evaluated: true,
            guidance_recommended: true,
            guidance_found: true,
            guidance_attached: true,
            skill_need_count: prepared_context
                .preparation_needs
                .as_ref()
                .map(|needs| needs.skill_needs.len() as u32)
                .unwrap_or(0),
            selected_skill_count: 1,
            selected_skill_names: vec!["frontend-skill".to_string()],
            search_scope: "published_runtime_skills".to_string(),
            rationale: "The request benefits from frontend-skill guidance before authoring."
                .to_string(),
            failure_reason: None,
        });
    materialization.selected_skills = vec![ioi_api::chat::ChatArtifactSelectedSkill {
        skill_hash: "b".repeat(64),
        name: "frontend-skill".to_string(),
        description: "Distinctive frontend design guidance".to_string(),
        lifecycle_state: "published".to_string(),
        source_type: "filesystem".to_string(),
        reliability_bps: 9800,
        semantic_score_bps: 9200,
        adjusted_score_bps: 9500,
        relative_path: Some("skills/frontend-skill/SKILL.md".to_string()),
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![ioi_api::chat::ChatArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Matched visual art direction for the interactive explainer.".to_string(),
        guidance_markdown: Some("Use strong hierarchy and restrained motion.".to_string()),
    }];

    let steps = pipeline_steps_for_state(
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        &artifact_manifest_for_request(
            "Quantum explainer",
            &request,
            &[],
            None,
            None,
            ChatArtifactLifecycleState::Materializing,
        ),
        &materialization,
        ChatArtifactLifecycleState::Materializing,
        None,
        None,
    );
    let skill_discovery = steps
        .iter()
        .find(|step| step.id == "skill_discovery")
        .expect("skill discovery step");
    let skill_read = steps
        .iter()
        .find(|step| step.id == "skill_read")
        .expect("skill read step");
    let brief_step = steps
        .iter()
        .find(|step| step.id == "brief")
        .expect("brief step");

    assert_eq!(skill_discovery.status, "complete");
    assert!(skill_discovery
        .outputs
        .iter()
        .any(|output| output == "guidance_status:attached"));
    assert!(skill_discovery
        .outputs
        .iter()
        .any(|output| output == "guidance_attached:true"));
    assert_eq!(skill_read.status, "complete");
    assert_eq!(brief_step.status, "active");
    assert!(brief_step
        .outputs
        .iter()
        .any(|output| output == "brief:pending"));
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
