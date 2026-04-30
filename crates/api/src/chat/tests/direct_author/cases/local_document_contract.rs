#[test]
fn local_direct_author_prompt_omits_materialization_json_scaffolding() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let selected_skills = vec![ChatArtifactSelectedSkill {
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
        matched_need_kinds: vec![ChatArtifactSkillNeedKind::VisualArtDirection],
        match_rationale:
            "Matched the request because the artifact needs strong editorial frontend direction."
                .to_string(),
        guidance_markdown: Some(
            "Before coding, understand the context and commit to a bold aesthetic direction."
                .to_string(),
        ),
    }];

    let payload = build_chat_artifact_direct_author_prompt_for_runtime(
        "Quantum explainer",
        "Create an interactive HTML artifact that explains quantum computers.",
        &request,
        &brief,
        &selected_skills,
        None,
        None,
        "candidate-1",
        7,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
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
fn local_direct_author_prompt_strips_codebase_context_envelope() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let payload = build_chat_artifact_direct_author_prompt_for_runtime(
        "[Codebase context]",
        "[Codebase context]\nWorkspace: .\n\n[User request]\nCreate an interactive HTML artifact that explains quantum computers.",
        &request,
        &brief,
        &[],
        None,
        None,
        "candidate-1",
        7,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        true,
    )
    .expect("direct author prompt");

    let prompt_text = serde_json::to_string(&payload).expect("prompt json");

    assert!(prompt_text
        .contains("Create an interactive HTML artifact that explains quantum computers."));
    assert!(!prompt_text.contains("Workspace: ."));
    assert!(!prompt_text.contains("[Codebase context]"));
}

#[tokio::test]
async fn direct_author_local_document_surfaces_provisional_snapshot_without_continuation() {
    #[derive(Debug, Clone)]
    struct ProvisionalSnapshotRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for ProvisionalSnapshotRuntime {
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
                "unexpected non-streaming prompt in provisional snapshot runtime: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
            token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main><section><h1>Quantum computing explained</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div><button type=\"button\">Core concepts</button></div></section><section><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside></main>";
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

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture provisional snapshot runtime".to_string(),
                model: Some("fixture-provisional-snapshot".to_string()),
                endpoint: Some("fixture://provisional-snapshot".to_string()),
            }
        }
    }

    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
    let brief = sample_quantum_explainer_brief();
    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

    let payload =
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(ProvisionalSnapshotRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Computing Explained",
            "Create an HTML file that explains quantum computers.",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-provisional-snapshot",
            11,
            0.0,
            None,
            None,
        )
        .await
        .expect("renderable streamed document should surface as a provisional candidate");

    assert!(payload.files[0].body.contains("<main>"));
    assert!(payload.files[0]
        .body
        .contains("Quantum computing explained"));

    let prompt_log = prompts.lock().expect("prompt log");
    assert!(prompt_log.is_empty(), "continuation/repair should not run");
}

#[tokio::test]
async fn direct_author_local_document_timeout_surfaces_provisional_candidate_without_continuation()
{
    #[derive(Debug, Clone)]
    struct ProvisionalTimeoutRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for ProvisionalTimeoutRuntime {
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
                "unexpected non-streaming prompt in provisional timeout runtime: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
            token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;} .shell{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:18px;} .card{background:#111827;border:1px solid #334155;border-radius:20px;padding:18px;} .facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;}</style></head><body><div class=\"shell\"><div class=\"card\"><h1>Quantum computing explained</h1><p>Quantum computers use qubits, superposition, and interference to model some problems in a way that differs from classical bits.</p><p>This document compares the classical bit with the quantum qubit and highlights where the speedups come from.</p></div><div class=\"card\"><h2>Classical vs quantum</h2><p>A bit is either zero or one, while a qubit can encode a probability amplitude over both states until measurement.</p><div class=\"facts\"><div><strong>Bit</strong><p>0 or 1</p></div><div><strong>Qubit</strong><p>0, 1, or both in superposition</p></div><div><strong>Measurement</strong><p>Collapses to a classical outcome</p></div></div></div><div class=\"card\"><h2>Why it matters</h2><p>Algorithms such as Shor's and Grover's matter because they can reshape an enormous search space before sampling an answer.</p><p>That does not make quantum computers universally faster, but it does change the structure of certain problems.</p></div></div></body>";
            if let Some(sender) = token_stream.as_ref() {
                sender
                    .send(raw.to_string())
                    .await
                    .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
            }
            Err(VmError::HostError(
                "fixture timeout after rich html draft".to_string(),
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
                label: "fixture provisional timeout runtime".to_string(),
                model: Some("fixture-provisional-timeout".to_string()),
                endpoint: Some("fixture://provisional-timeout".to_string()),
            }
        }
    }

    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
    let brief = sample_quantum_explainer_brief();
    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

    let payload =
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(ProvisionalTimeoutRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Computing Explained",
            "Create an HTML file that explains quantum computers.",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-provisional-timeout",
            17,
            0.0,
            None,
            None,
        )
        .await
        .expect("rich timed-out document should surface as a provisional candidate");

    assert!(payload.files[0].body.contains("<html"));
    assert!(payload.files[0]
        .body
        .contains("Quantum computing explained"));
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("provisional preview surfaced")));

    let prompt_log = prompts.lock().expect("prompt log");
    assert!(prompt_log.is_empty(), "continuation/repair should not run");
}

#[test]
fn local_document_direct_author_prompt_does_not_force_interactivity() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
    let brief = sample_quantum_explainer_brief();

    let payload = build_chat_artifact_direct_author_prompt_for_runtime(
        "Quantum explainer",
        "Create an HTML file that explains quantum computers.",
        &request,
        &brief,
        &[],
        None,
        None,
        "candidate-1",
        7,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        true,
    )
    .expect("direct author prompt");

    let prompt_text = serde_json::to_string(&payload).expect("prompt json");

    assert!(prompt_text.contains("Create an HTML file that explains quantum computers."));
    assert!(prompt_text.contains("Deliver one request-specific HTML document."));
    assert!(prompt_text.contains(
        "Only introduce JavaScript when it materially improves the document; do not force interactivity for document-class requests."
    ));
    assert!(prompt_text.contains(
        "Keep body copy, headings, supporting labels, and evidence text high-contrast against the background on first paint"
    ));
    assert!(prompt_text.contains("Keep text contrast clearly readable on first paint."));
    assert!(!prompt_text.contains("Deliver one request-specific interactive HTML document."));
    assert!(!prompt_text.contains(
        "Include one or more real interaction seams that change visible evidence or response context."
    ));
}

#[test]
fn direct_author_markdown_generation_uses_raw_document_contract() {
    #[derive(Debug, Clone)]
    struct DirectAuthorMarkdownRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
        json_modes: Arc<Mutex<Vec<bool>>>,
        provenance: ChatRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorMarkdownRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
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
                    "unexpected Chat prompt in markdown direct-author test runtime: {prompt}"
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            self.provenance.clone()
        }
    }

    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorMarkdownRuntime {
        prompts: prompts.clone(),
        json_modes: json_modes.clone(),
        provenance: ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture markdown direct-author runtime".to_string(),
            model: Some("fixture-direct-author-markdown".to_string()),
            endpoint: Some("fixture://direct-author-markdown".to_string()),
        },
    });
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let title = "Quantum computers brief";
    let intent = "Create a markdown artifact that explains quantum computers";

    let bundle = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let runtime_plan = resolve_chat_artifact_runtime_plan(
                &request,
                runtime.clone(),
                None,
                ChatArtifactRuntimePolicyProfile::FullyLocal,
            );
            let planning_context = planned_prepared_context_with_runtime_plan(
                &runtime_plan,
                title,
                intent,
                &request,
                None,
            )
            .await;
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::DirectAuthor,
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
        Some(ChatExecutionStrategy::DirectAuthor)
    );
}
