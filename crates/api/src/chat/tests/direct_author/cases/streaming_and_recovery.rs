#[tokio::test]
async fn direct_author_streams_token_preview_into_generation_progress() {
    #[derive(Debug, Clone)]
    struct StreamingDirectAuthorRuntime {
        provenance: ChatRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for StreamingDirectAuthorRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
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
            let prompt = decode_chat_test_prompt(input_context);
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            self.provenance.clone()
        }
    }

    let runtime: Arc<dyn InferenceRuntime> = Arc::new(StreamingDirectAuthorRuntime {
        provenance: ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture streaming direct-author runtime".to_string(),
            model: Some("fixture-streaming-direct-author".to_string()),
            endpoint: Some("fixture://streaming-direct-author".to_string()),
        },
    });
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let title = "Quantum computers overview";
    let intent = "Create a markdown artifact that explains quantum computers";
    let progress_log = Arc::new(Mutex::new(Vec::<ChatArtifactGenerationProgress>::new()));
    let progress_observer: ChatArtifactGenerationProgressObserver = {
        let progress_log = progress_log.clone();
        Arc::new(move |progress| {
            progress_log.lock().expect("progress log").push(progress);
        })
    };

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request,
        runtime.clone(),
        None,
        ChatArtifactRuntimePolicyProfile::FullyLocal,
    );
    let planning_context =
        planned_prepared_context_with_runtime_plan(&runtime_plan, title, intent, &request, None)
            .await;
    let bundle =
        generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
            runtime_plan,
            title,
            intent,
            &request,
            None,
            &planning_context,
            ChatExecutionStrategy::DirectAuthor,
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
            let prompt = decode_chat_test_prompt(input_context);
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
            let prompt = decode_chat_test_prompt(input_context);
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture interrupted direct-author runtime".to_string(),
                model: Some("fixture-interrupted-direct-author".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_simple_quantum_interactive_brief();
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

    let payload =
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(InterruptedStreamingDirectAuthorRuntime),
            None,
            "Quantum Explorer",
            "Create a simple interactive HTML artifact that explains qubits",
            &request,
            &brief,
            &[],
            None,
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
            let prompt = decode_chat_test_prompt(input_context);
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
            let prompt = decode_chat_test_prompt(input_context);
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture completed-but-invalid direct-author runtime".to_string(),
                model: Some("fixture-completed-invalid-direct-author".to_string()),
                endpoint: Some("fixture://completed-invalid-direct-author".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_simple_quantum_interactive_brief();
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
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(CompletedInvalidStreamingDirectAuthorRuntime),
            None,
            "Quantum computers",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
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
async fn direct_author_completed_incomplete_document_salvages_terminal_closure_without_follow_up() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct CompletedIncompleteDirectAuthorRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for CompletedIncompleteDirectAuthorRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in completed incomplete runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title><style>body{margin:0;background:#0f172a;color:#e2e8f0;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:18px;}section,aside{background:#111827;border:1px solid #334155;border-radius:18px;padding:20px;}button{border:1px solid #38bdf8;background:#082f49;color:#e0f2fe;border-radius:999px;padding:10px 14px;}</style></head><body><main><section><h1>Quantum Explorer</h1><p>Compare the basics of qubits and measurement.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Ok(raw.as_bytes().to_vec())
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

            fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
                ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture completed incomplete direct-author runtime".to_string(),
                    model: Some("fixture-completed-incomplete-direct-author".to_string()),
                    endpoint: Some("fixture://completed-incomplete-direct-author".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = ChatArtifactBrief {
            audience: "curious learners".to_string(),
            job_to_be_done: "browse staged quantum examples".to_string(),
            subject_domain: "quantum basics".to_string(),
            artifact_thesis: "Progress through staged explanations with visible step changes."
                .to_string(),
            required_concepts: vec!["superposition".to_string(), "measurement".to_string()],
            required_interactions: vec!["sequence browsing".to_string()],
            visual_tone: vec!["editorial".to_string()],
            factual_anchors: vec!["state examples".to_string()],
            style_directives: vec!["clear hierarchy".to_string()],
            reference_hints: vec!["staged explainer".to_string()],
            query_profile: Some(ChatArtifactQueryProfile {
                content_goals: vec![required_content_goal(
                    ChatArtifactContentGoalKind::Explain,
                    "Explain each stage clearly.",
                )],
                interaction_goals: vec![required_interaction_goal(
                    ChatArtifactInteractionGoalKind::SequenceBrowse,
                    "Progress through staged examples.",
                )],
                evidence_goals: vec![required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep the active stage visible.",
                )],
                presentation_constraints: vec![required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                )],
            }),
        };
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(CompletedIncompleteDirectAuthorRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-completed-incomplete",
            29,
            0.72,
            None,
            None,
        )
        .await
        .expect("completed document missing only terminal closers should recover locally");

        assert!(payload.files[0].body.ends_with("</body></html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(
            prompt_log.is_empty(),
            "local closure salvage should avoid continuation/repair prompts"
        );
    })
    .await;
}

#[tokio::test]
async fn direct_author_interrupted_closed_document_repairs_without_continuation() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct InterruptedClosedDocumentRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for InterruptedClosedDocumentRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                if prompt.contains("Repair output schema") {
                    return Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main></body></html>".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in interrupted closed document runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the stages to compare classical bits and qubits.</p></section><section><h2>Superposition</h2><p>Qubits can occupy superposition before they are measured.</p></section><section><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section></main></body>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Err(VmError::HostError(
                    "fixture interrupted after streaming closed body".to_string(),
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

            fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
                ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture interrupted closed document runtime".to_string(),
                    model: Some("fixture-interrupted-closed-document".to_string()),
                    endpoint: Some("fixture://interrupted-closed-document".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = ChatArtifactBrief {
            audience: "curious learners".to_string(),
            job_to_be_done: "browse staged quantum examples".to_string(),
            subject_domain: "quantum basics".to_string(),
            artifact_thesis: "Progress through staged explanations with visible step changes."
                .to_string(),
            required_concepts: vec!["superposition".to_string(), "measurement".to_string()],
            required_interactions: vec!["sequence browsing".to_string()],
            visual_tone: vec!["editorial".to_string()],
            factual_anchors: vec!["state examples".to_string()],
            style_directives: vec!["clear hierarchy".to_string()],
            reference_hints: vec!["staged explainer".to_string()],
            query_profile: Some(ChatArtifactQueryProfile {
                content_goals: vec![required_content_goal(
                    ChatArtifactContentGoalKind::Explain,
                    "Explain each stage clearly.",
                )],
                interaction_goals: vec![required_interaction_goal(
                    ChatArtifactInteractionGoalKind::SequenceBrowse,
                    "Progress through staged examples.",
                )],
                evidence_goals: vec![required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep the active stage visible.",
                )],
                presentation_constraints: vec![required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                )],
            }),
        };
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(InterruptedClosedDocumentRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-interrupted-closed",
            31,
            0.72,
            None,
            None,
        )
        .await
        .expect("closed interrupted document should go straight to repair without continuation");

        assert!(payload.files[0].body.contains("Measurement is selected."));
        assert!(payload.files[0].body.contains("data-view-panel=\"measurement\""));
        assert!(payload.files[0].body.ends_with("</html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Continuation output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_timed_out_underbuilt_closed_document_prefers_continuation_over_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct UnderbuiltClosedContinuationRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for UnderbuiltClosedContinuationRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                if prompt.contains("Continuation output schema")
                    || prompt.contains("typed direct document continuation author")
                {
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\" data-detail=\\\"Basics are selected by default.\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\" data-detail=\\\"Measurement collapses amplitudes into observable outcomes.\\\">Measurement</button><button type=\\\"button\\\" data-view=\\\"examples\\\" aria-selected=\\\"false\\\" data-detail=\\\"Examples highlight optimization and simulation workloads.\\\">Examples</button></div></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\\\"examples\\\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in underbuilt continuation runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the controls to compare classical bits and qubits.</p><div><button type=\"button\">Classical bits</button><button type=\"button\">Quantum qubits</button></div></section><section><h2>Bits</h2><p>Bits hold one state at a time.</p></section><section><h2>Qubits</h2><p>Qubits can occupy superposition before measurement.</p></section><aside><p id=\"detail-copy\">Choose a view to update this explanation.</p></aside></main></body></html>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Err(VmError::HostError(
                    "fixture timed out after emitting an underbuilt closed document".to_string(),
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

            fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
                ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture underbuilt closed continuation runtime".to_string(),
                    model: Some("fixture-underbuilt-closed-continuation".to_string()),
                    endpoint: Some("fixture://underbuilt-closed-continuation".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(UnderbuiltClosedContinuationRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-underbuilt-closed-continuation",
            31,
            0.72,
            None,
            None,
        )
        .await
        .expect("underbuilt closed document should continue before repair");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Continuation output schema")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_completed_underbuilt_document_prefers_continuation_over_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct UnderbuiltCompletedContinuationRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for UnderbuiltCompletedContinuationRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                if prompt.contains("Continuation output schema")
                    || prompt.contains("typed direct document continuation author")
                {
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\" data-detail=\\\"Basics are selected by default.\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\" data-detail=\\\"Measurement collapses amplitudes into observable outcomes.\\\">Measurement</button><button type=\\\"button\\\" data-view=\\\"examples\\\" aria-selected=\\\"false\\\" data-detail=\\\"Examples highlight optimization and simulation workloads.\\\">Examples</button></div></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\\\"examples\\\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in completed underbuilt continuation runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the controls to compare classical bits and qubits.</p><div><button type=\"button\">Classical bits</button><button type=\"button\">Quantum qubits</button></div></section><section><h2>Bits</h2><p>Bits hold one state at a time.</p></section><section><h2>Qubits</h2><p>Qubits can occupy superposition before measurement.</p></section><aside><p id=\"detail-copy\">Choose a view to update this explanation.</p></aside></main></body>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Ok(raw.as_bytes().to_vec())
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

            fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
                ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture completed underbuilt continuation runtime".to_string(),
                    model: Some("fixture-completed-underbuilt-continuation".to_string()),
                    endpoint: Some("fixture://completed-underbuilt-continuation".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(UnderbuiltCompletedContinuationRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-completed-underbuilt-continuation",
            37,
            0.72,
            None,
            None,
        )
        .await
        .expect("completed underbuilt document should continue before repair");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Continuation output schema")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_large_incomplete_document_prefers_continuation_over_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct LargeIncompleteContinuationRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for LargeIncompleteContinuationRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                if prompt.contains("Continuation output schema")
                    || prompt.contains("typed direct document continuation author")
                {
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\" data-detail=\\\"Basics are selected by default.\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\" data-detail=\\\"Measurement collapses amplitudes into observable outcomes.\\\">Measurement</button><button type=\\\"button\\\" data-view=\\\"examples\\\" aria-selected=\\\"false\\\" data-detail=\\\"Examples highlight optimization and simulation workloads.\\\">Examples</button></div></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\\\"examples\\\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in large incomplete continuation runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let mut raw = String::from(
                    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the controls to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\">Classical bits</button><button type=\"button\" data-view=\"measurement\">Quantum qubits</button><button type=\"button\" data-view=\"examples\">Examples</button></div></section>",
                );
                for idx in 0..24 {
                    raw.push_str(&format!(
                        "<section><h2>Concept {idx}</h2><p>Quantum detail block {idx} keeps the authored scaffold populated with factual explanation and interactive context for continuation.</p></section>"
                    ));
                }
                raw.push_str("<aside><p id=\"detail-copy\">Choose a view to update this explanation.</p></aside>");
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.clone())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Ok(raw.into_bytes())
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

            fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
                ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture large incomplete continuation runtime".to_string(),
                    model: Some("fixture-large-incomplete-continuation".to_string()),
                    endpoint: Some("fixture://large-incomplete-continuation".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload =
            super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
                Arc::new(LargeIncompleteContinuationRuntime {
                    prompts: prompts.clone(),
                }),
                None,
                "Quantum Explorer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                &brief,
                &[],
                None,
                None,
                "candidate-large-incomplete-continuation",
                31,
                0.72,
                None,
                None,
            )
            .await
            .expect("large incomplete document should continue before repair");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Continuation output schema")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_incomplete_empty_shell_sections_prefer_continuation_over_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct EmptyShellContinuationRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for EmptyShellContinuationRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                if prompt.contains("Continuation output schema")
                    || prompt.contains("typed direct document continuation author")
                {
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\" data-detail=\\\"Basics are selected by default.\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\" data-detail=\\\"Measurement collapses amplitudes into observable outcomes.\\\">Measurement</button><button type=\\\"button\\\" data-view=\\\"examples\\\" aria-selected=\\\"false\\\" data-detail=\\\"Examples highlight optimization and simulation workloads.\\\">Examples</button></div></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\\\"examples\\\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in empty shell continuation runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let mut raw = String::from(
                    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the controls to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\">Classical bits</button><button type=\"button\" data-view=\"measurement\">Quantum qubits</button><button type=\"button\" data-view=\"examples\">Examples</button></div></section>",
                );
                for idx in 0..18 {
                    raw.push_str(&format!(
                        "<section><h2>Concept {idx}</h2></section>"
                    ));
                }
                raw.push_str("<aside><p id=\"detail-copy\">Choose a view to update this explanation.</p></aside>");
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.clone())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Ok(raw.into_bytes())
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

            fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
                ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture empty shell continuation runtime".to_string(),
                    model: Some("fixture-empty-shell-continuation".to_string()),
                    endpoint: Some("fixture://empty-shell-continuation".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload =
            super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
                Arc::new(EmptyShellContinuationRuntime {
                    prompts: prompts.clone(),
                }),
                None,
                "Quantum Explorer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                &brief,
                &[],
                None,
                None,
                "candidate-empty-shell-continuation",
                31,
                0.72,
                None,
                None,
            )
            .await
            .expect("empty shell draft should continue before repair");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Continuation output schema")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

