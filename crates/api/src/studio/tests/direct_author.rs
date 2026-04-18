use super::*;

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
        bundle.validation.classification,
        StudioArtifactValidationStatus::Pass
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
async fn local_html_materialization_inference_timeout_is_bounded() {
    #[derive(Debug, Clone)]
    struct HangingPlanExecuteMaterializationRuntime;

    #[async_trait]
    impl InferenceRuntime for HangingPlanExecuteMaterializationRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            if prompt.contains("typed artifact materializer") {
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Ok(b"{}".to_vec());
            }
            Err(VmError::HostError(format!(
                "unexpected prompt in hanging plan-execute runtime: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
            _token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            self.execute_inference([0u8; 32], input_context, InferenceOptions::default())
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

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture hanging plan-execute runtime".to_string(),
                model: Some("fixture-hanging-plan-execute".to_string()),
                endpoint: Some("fixture://hanging-plan-execute".to_string()),
            }
        }
    }

    let previous_timeout = std::env::var("AUTOPILOT_STUDIO_MATERIALIZATION_TIMEOUT_MS").ok();
    std::env::set_var("AUTOPILOT_STUDIO_MATERIALIZATION_TIMEOUT_MS", "50");

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let result = super::generation::materialize_studio_artifact_candidate_with_runtime_detailed(
        Arc::new(HangingPlanExecuteMaterializationRuntime),
        None,
        "Quantum computers",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        &brief,
        None,
        None,
        &[],
        &[],
        None,
        None,
        "candidate-plan-timeout",
        17,
        0.72,
        None,
    )
    .await;

    match previous_timeout {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_MATERIALIZATION_TIMEOUT_MS", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_MATERIALIZATION_TIMEOUT_MS"),
    }

    let error = result.expect_err("local html materialization should time out instead of hanging");
    assert!(error.message.contains(
        "Studio artifact materialization inference failed: Studio artifact materialization_inference timed out"
    ));
}

#[tokio::test]
async fn direct_author_stream_timeout_salvages_complete_partial_document() {
    #[derive(Debug, Clone)]
    struct HangingStreamingDirectAuthorRuntime;

    #[async_trait]
    impl InferenceRuntime for HangingStreamingDirectAuthorRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in hanging direct-author runtime: {prompt}"
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

            let complete_document = "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Quantum computers</title><style>body{margin:0;background:#020617;color:#e2e8f0;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:18px;}section{border:1px solid #334155;border-radius:18px;padding:20px;background:#0f172a;}button{background:#38bdf8;color:#082f49;border:none;border-radius:999px;padding:10px 16px;font:inherit;cursor:pointer;}#response-panel{margin-top:12px;padding:12px;border-radius:14px;background:#082f49;color:#e0f2fe;}</style></head><body><main><section><h1>Quantum computers explained</h1><p>Qubits use superposition and interference to explore a probability space before measurement collapses the result.</p></section><section><h2>State views</h2><p>Switch between concept and hardware framing to see how the explanation changes.</p><button type=\"button\" id=\"toggle-view\" aria-pressed=\"false\">Show hardware limits</button><div id=\"response-panel\">Concept view: superposition keeps multiple outcomes available until measurement.</div></section><section><h2>Why it matters</h2><p>Gate sequences reshape amplitudes so the final measurement distribution favors useful answers.</p></section></main><script>const button=document.getElementById('toggle-view');const panel=document.getElementById('response-panel');button.addEventListener('click',()=>{const next=button.getAttribute('aria-pressed')!=='true';button.setAttribute('aria-pressed',String(next));button.textContent=next?'Show concept view':'Show hardware limits';panel.textContent=next?'Hardware view: noisy qubits and error correction costs limit practical depth.':'Concept view: superposition keeps multiple outcomes available until measurement.';});</script></body></html>";
            if let Some(sender) = token_stream.as_ref() {
                sender
                    .send(complete_document.to_string())
                    .await
                    .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(complete_document.as_bytes().to_vec())
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
                label: "fixture hanging direct-author runtime".to_string(),
                model: Some("fixture-hanging-direct-author".to_string()),
                endpoint: Some("fixture://hanging-direct-author".to_string()),
            }
        }
    }

    let previous_timeout = std::env::var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_STREAM_TIMEOUT_MS").ok();
    std::env::set_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", "50");

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

    let payload_result = super::generation::materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
        Arc::new(HangingStreamingDirectAuthorRuntime),
        None,
        "Quantum computers",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        &brief,
        &[],
        None,
        "candidate-timeout",
        11,
        0.72,
        Some(live_preview_observer),
        None,
    )
    .await;

    match previous_timeout {
        Some(value) => std::env::set_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", value),
        None => std::env::remove_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_STREAM_TIMEOUT_MS"),
    }

    let payload = payload_result
        .expect("timed out direct-author stream should salvage the streamed document");
    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0]
        .body
        .contains("Quantum computers explained"));

    let preview_log = live_previews.lock().expect("live preview log");
    assert!(preview_log.iter().any(|preview| {
        preview.id == "candidate-timeout-live-output"
            && preview.status == "interrupted"
            && preview.content.contains("Quantum computers explained")
    }));
    let latest_preview = preview_log
        .iter()
        .rev()
        .find(|preview| preview.id == "candidate-timeout-live-output")
        .expect("recovered preview should be recorded");
    assert_eq!(latest_preview.status, "recovered");
    assert!(latest_preview.is_final);
}

#[tokio::test]
async fn direct_author_stream_timeout_salvages_truncated_but_normalizable_modal_first_html() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct NormalizableInterruptedDirectAuthorRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for NormalizableInterruptedDirectAuthorRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_studio_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                Err(VmError::HostError(format!(
                    "normalizable truncated stream should not require follow-up inference: {prompt}"
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
                let partial = "<!doctype html><html><body><main><section><h1>Mortgage estimator</h1><p>Adjust price, rate, and term to compare monthly payment.</p><input type=\"range\" id=\"home-price\" min=\"100000\" max=\"1000000\" value=\"300000\"></section><section><article><h2>Payment summary</h2><p id=\"monthly-payment\">$1,796</p></article><article><h2>Scenario comparison</h2><p>Longer terms reduce monthly payments but increase total interest.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Home price is selected by default.</p>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(partial.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Err(VmError::HostError(
                    "timed out while completing normalized mortgage estimator".to_string(),
                ))
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
                    label: "fixture normalizable interrupted runtime".to_string(),
                    model: Some("fixture-normalizable-interrupted".to_string()),
                    endpoint: Some("fixture://normalizable-interrupted".to_string()),
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
            Arc::new(NormalizableInterruptedDirectAuthorRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Mortgage estimator",
            "A mortgage calculator where I can adjust rate, term, and down payment",
            &request,
            &brief,
            &[],
            None,
            "candidate-normalized-timeout",
            29,
            0.72,
            None,
            None,
        )
        .await
        .expect("normalizable truncated modal-first html should recover without follow-up inference");

        let html_lower = payload.files[0].body.to_ascii_lowercase();
        assert!(html_lower.ends_with("</main></body></html>"));
        assert!(html_lower.contains("</aside>"));
        assert!(html_lower.matches("</section>").count() >= 2);
        assert!(payload.files[0].body.contains("monthly-payment"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert_eq!(prompt_log.len(), 1);
    })
    .await;
}

#[tokio::test]
async fn direct_author_stream_timeout_trims_incomplete_trailing_fragment_before_validation() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct TrailingFragmentInterruptedRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for TrailingFragmentInterruptedRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_studio_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                Err(VmError::HostError(format!(
                    "trailing-fragment stream should not require follow-up inference: {prompt}"
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
                let partial = "<!doctype html><html><body><main><section><h1>Mortgage estimator</h1><p>Adjust rate and term to inspect the monthly payment.</p><input type=\"range\" id=\"rate\" min=\"1\" max=\"10\" value=\"6\"></section><section><article><h2>Payment summary</h2><p id=\"monthly-payment\">$1,796</p></article><article><h2>Scenario comparison</h2><p>Longer terms reduce the monthly payment but raise total interest.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Rate is selected by default.</p></aside><script>document.getElementById('rate').addEventListener('input',()=>{document.getElementById('detail-copy').textContent='Rate updated.';});</script><div class=\"";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(partial.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Err(VmError::HostError(
                    "timed out after emitting an incomplete trailing fragment".to_string(),
                ))
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
                    label: "fixture trailing-fragment interrupted runtime".to_string(),
                    model: Some("fixture-trailing-fragment".to_string()),
                    endpoint: Some("fixture://trailing-fragment".to_string()),
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
            Arc::new(TrailingFragmentInterruptedRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Mortgage estimator",
            "A mortgage calculator where I can adjust rate, term, and down payment",
            &request,
            &brief,
            &[],
            None,
            "candidate-trailing-fragment-timeout",
            31,
            0.72,
            None,
            None,
        )
        .await
        .expect("trailing fragment should be trimmed before validation");

        let html_lower = payload.files[0].body.to_ascii_lowercase();
        assert!(html_lower.ends_with("</script></main></body></html>"));
        assert!(!html_lower.contains("<div class=\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert_eq!(prompt_log.len(), 1);
    })
    .await;
}

#[tokio::test]
async fn direct_author_follow_up_timeout_marks_preview_failed_after_interrupted_stream() {
    #[derive(Debug, Clone)]
    struct HangingContinuationDirectAuthorRuntime;

    #[async_trait]
    impl InferenceRuntime for HangingContinuationDirectAuthorRuntime {
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
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Ok(
                    "{\"mode\":\"suffix\",\"content\":\"</section></main></body></html>\"}"
                        .as_bytes()
                        .to_vec(),
                );
            }
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in hanging continuation runtime: {prompt}"
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
                label: "fixture hanging continuation runtime".to_string(),
                model: Some("fixture-hanging-continuation".to_string()),
                endpoint: Some("fixture://hanging-continuation".to_string()),
            }
        }
    }

    let previous_timeout = std::env::var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS").ok();
    std::env::set_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS", "50");

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

    let payload_result = super::generation::materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
        Arc::new(HangingContinuationDirectAuthorRuntime),
        None,
        "Quantum computers",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        &brief,
        &[],
        None,
        "candidate-follow-up-timeout",
        13,
        0.72,
        Some(live_preview_observer),
        None,
    )
    .await;

    match previous_timeout {
        Some(value) => {
            std::env::set_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS", value)
        }
        None => std::env::remove_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS"),
    }

    let error =
        payload_result.expect_err("hanging follow-up inference should fail instead of stalling");
    assert!(error
        .message
        .contains("continuation attempt 1 inference failed"));
    assert!(error.message.contains("timed out after 50ms"));

    let preview_log = live_previews.lock().expect("live preview log");
    assert!(preview_log.iter().any(|preview| {
        preview.id == "candidate-follow-up-timeout-live-output"
            && preview.status == "continuing"
            && !preview.is_final
    }));
    let latest_preview = preview_log
        .iter()
        .rev()
        .find(|preview| preview.id == "candidate-follow-up-timeout-live-output")
        .expect("failed preview should be recorded");
    assert_eq!(latest_preview.status, "failed");
    assert!(latest_preview.is_final);
}

#[tokio::test]
async fn direct_author_continuation_timeout_falls_through_to_repair() {
    #[derive(Debug, Clone)]
    struct TimeoutThenRepairDirectAuthorRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for TimeoutThenRepairDirectAuthorRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_studio_test_prompt(input_context);
            self.prompts
                .lock()
                .expect("prompt log")
                .push(prompt.clone());
            if prompt.contains("Continuation output schema")
                || prompt.contains("typed direct document continuation author")
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Ok(
                    "{\"mode\":\"suffix\",\"content\":\"</section></main></body></html>\"}"
                        .as_bytes()
                        .to_vec(),
                );
            }
            if prompt.contains("direct document repair author") {
                return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Mortgage Calculator</title><style>body{margin:0;background:#0b1220;color:#e5edf7;font-family:Georgia,serif;}main{max-width:980px;margin:0 auto;padding:28px;display:grid;gap:18px;}section,aside{background:#132033;border:1px solid #28405c;border-radius:18px;padding:18px;}label{display:grid;gap:8px;font-size:.92rem;color:#bfd0e4;}input[type=range]{width:100%;}button{border:1px solid #3b82f6;background:#1d4ed8;color:#eff6ff;border-radius:999px;padding:10px 14px;font:inherit;cursor:pointer;}dl{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;}dt{color:#8aa0bb;}dd{margin:0;font-weight:700;}ul{margin:0;padding-left:1.2rem;color:#bfd0e4;}small{color:#8aa0bb;}</style></head><body><main data-repaired=\\\"continuation-timeout\\\"><section><h1>Mortgage Calculator</h1><p>Adjust home price, down payment, rate, and term to compare monthly payment and total interest.</p><label>Home Price <input id=\\\"home-price\\\" type=\\\"range\\\" min=\\\"50000\\\" max=\\\"2000000\\\" step=\\\"5000\\\" value=\\\"300000\\\"></label><label>Down Payment <input id=\\\"down-payment\\\" type=\\\"range\\\" min=\\\"0\\\" max=\\\"100\\\" step=\\\"1\\\" value=\\\"20\\\"></label><label>Interest Rate <input id=\\\"interest-rate\\\" type=\\\"range\\\" min=\\\"1\\\" max=\\\"15\\\" step=\\\"0.01\\\" value=\\\"6.5\\\"></label><label>Loan Term <input id=\\\"loan-term\\\" type=\\\"range\\\" min=\\\"5\\\" max=\\\"40\\\" step=\\\"1\\\" value=\\\"30\\\"></label></section><section><h2>Payment Summary</h2><dl><dt>Monthly Payment</dt><dd id=\\\"monthly-payment\\\">$1,517</dd><dt>Total Interest</dt><dd id=\\\"total-interest\\\">$246,104</dd><dt>Loan Amount</dt><dd id=\\\"loan-amount\\\">$240,000</dd><dt>Total Paid</dt><dd id=\\\"total-paid\\\">$546,104</dd></dl></section><section><h2>Scenario Comparison</h2><ul><li id=\\\"fifteen-year\\\">15-year term raises monthly cost but lowers total interest.</li><li id=\\\"thirty-year\\\">30-year term lowers monthly cost but increases lifetime interest.</li><li id=\\\"equity-note\\\">Extra down payment reduces the financed amount immediately.</li></ul></section><aside><h2>Scenario note</h2><p id=\\\"detail-copy\\\">A 20% down payment lowers the financed amount and monthly payment.</p><small>Use the sliders to compare how price, rate, and term change the total cost.</small></aside></main><script>const fmtMoney=(value)=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(value);const fmtPayment=(value)=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(value);const inputs={price:document.getElementById('home-price'),down:document.getElementById('down-payment'),rate:document.getElementById('interest-rate'),term:document.getElementById('loan-term')};const outputIds={monthly:document.getElementById('monthly-payment'),interest:document.getElementById('total-interest'),loan:document.getElementById('loan-amount'),paid:document.getElementById('total-paid'),detail:document.getElementById('detail-copy')};const scenarioNotes={short:'15-year term raises monthly cost but lowers total interest.',long:'30-year term lowers monthly cost but increases lifetime interest.'};const recalc=()=>{const price=Number(inputs.price.value);const downPct=Number(inputs.down.value)/100;const rate=(Number(inputs.rate.value)/100)/12;const months=Number(inputs.term.value)*12;const loanAmount=price*(1-downPct);const payment=rate===0?loanAmount/months:(loanAmount*rate)/(1-Math.pow(1+rate,-months));const totalPaid=payment*months;const totalInterest=Math.max(totalPaid-loanAmount,0);outputIds.monthly.textContent=fmtPayment(payment);outputIds.interest.textContent=fmtMoney(totalInterest);outputIds.loan.textContent=fmtMoney(loanAmount);outputIds.paid.textContent=fmtMoney(totalPaid);outputIds.detail.textContent=`${inputs.term.value}-year term at ${Number(inputs.rate.value).toFixed(2)}% keeps the financed amount at ${fmtMoney(loanAmount)}. ${months<=180?scenarioNotes.short:scenarioNotes.long}`;};Object.values(inputs).forEach((input)=>input.addEventListener('input',recalc));recalc();</script></body></html>\"}".as_bytes().to_vec());
            }
            Err(VmError::HostError(format!(
                "unexpected prompt in timeout-then-repair runtime: {prompt}"
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
            self.prompts
                .lock()
                .expect("prompt log")
                .push(prompt.clone());
            if !prompt.contains("direct document author")
                && !prompt.contains("Return only one complete self-contained index.html.")
            {
                return self
                    .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await;
            }

            let partial_chunks = [
                "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>Mortgage Calculator</title><style>".to_string(),
                "body{margin:0;background:#0b1220;color:#e5edf7;font-family:Georgia,serif;}main{max-width:980px;margin:0 auto;padding:28px;display:grid;gap:18px;}section,aside{background:#132033;border:1px solid #28405c;border-radius:18px;padding:18px;}".to_string(),
                "</style></head><body><main><section><h1>Mortgage Calculator</h1><p>Explain how rate, down payment, and term change the monthly payment.</p><p>Comparison details are still loading.</p>".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &partial_chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }

            Err(VmError::HostError(
                "timed out while emitting calculator controls".to_string(),
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
                label: "fixture timeout-then-repair runtime".to_string(),
                model: Some("fixture-timeout-then-repair".to_string()),
                endpoint: Some("fixture://timeout-then-repair".to_string()),
            }
        }
    }

    let previous_timeout = std::env::var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS").ok();
    std::env::set_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS", "50");

    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
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

    let payload_result = super::generation::materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
        Arc::new(TimeoutThenRepairDirectAuthorRuntime {
            prompts: prompts.clone(),
        }),
        None,
        "Mortgage Calculator",
        "A mortgage calculator where I can adjust rate, term, and down payment",
        &request,
        &brief,
        &[],
        None,
        "candidate-repair-after-timeout",
        21,
        0.72,
        Some(live_preview_observer),
        None,
    )
    .await;

    match previous_timeout {
        Some(value) => {
            std::env::set_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS", value)
        }
        None => std::env::remove_var("AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS"),
    }

    let payload = payload_result.expect("repair should recover after continuation timeout");
    assert!(payload.files[0]
        .body
        .to_ascii_lowercase()
        .ends_with("</html>"));

    let prompt_log = prompts.lock().expect("prompt log");
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("typed direct document continuation author")));
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("direct document repair author")));

    let preview_log = live_previews.lock().expect("live preview log");
    let latest_preview = preview_log
        .iter()
        .rev()
        .find(|preview| preview.id == "candidate-repair-after-timeout-live-output")
        .expect("recovered preview should be recorded");
    assert_eq!(latest_preview.status, "recovered");
    assert!(latest_preview.is_final);
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

#[test]
fn direct_author_continuation_prompt_keeps_small_partial_document_context() {
    let request = request_for(
        StudioArtifactClass::InteractiveSingleFile,
        StudioRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let partial_document = format!(
        "<!doctype html><html><head><title>Mortgage Calculator</title></head><body><main>{}</main></body></html>",
        "A".repeat(4300)
    );
    let prompt = build_studio_artifact_direct_author_continuation_prompt_for_runtime(
        "Mortgage Calculator",
        "A mortgage calculator where I can adjust rate, term, and down payment",
        &request,
        &brief,
        &[],
        &partial_document,
        "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
        StudioRuntimeProvenanceKind::RealLocalRuntime,
    );
    let prompt_text = serde_json::to_string(&prompt).expect("continuation prompt text");
    assert!(prompt_text.contains(
        "<!doctype html><html><head><title>Mortgage Calculator</title></head><body><main>"
    ));
    assert!(prompt_text.contains(&"A".repeat(256)));
    assert!(!prompt_text.contains("[showing latest streamed output]"));
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
async fn direct_author_local_html_uses_fast_runtime_sanity_without_artifact_validation() {
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
            } else if prompt.contains("typed artifact validation") {
                "validation"
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
                "validation" if self.role == "acceptance" => serde_json::json!({
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
                "validation" => serde_json::json!({
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
                    "rationale": "producer runtime validated the draft"
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
        assert!(!recorded_calls.iter().any(|entry| entry == "production:validation"));
        assert!(!recorded_calls.iter().any(|entry| entry == "acceptance:validation"));
        assert!(bundle
            .validation
            .rationale
            .starts_with("Studio replaced slow acceptance with a fast runtime-sanity pass"));
        assert_eq!(
            bundle.validation.classification,
            StudioArtifactValidationStatus::Pass
        );
        assert_eq!(bundle.ux_lifecycle, StudioArtifactUxLifecycle::Validated);
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
            } else if prompt.contains("typed artifact validation") {
                "validation"
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
                "validation" => {
                    return Err(VmError::HostError(
                        "fast local html path should not call the acceptance validation".to_string(),
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
        assert!(!recorded_calls.iter().any(|entry| entry == "acceptance:validation"));
        assert_eq!(
            bundle.validation.classification,
            StudioArtifactValidationStatus::Pass
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
            } else if prompt.contains("typed artifact validation") {
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
