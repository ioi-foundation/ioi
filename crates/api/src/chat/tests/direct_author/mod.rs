use super::*;

fn sample_simple_quantum_interactive_brief() -> ChatArtifactBrief {
    let mut brief = sample_quantum_explainer_brief();
    brief.required_concepts = vec!["qubits".to_string(), "measurement".to_string()];
    brief.required_interactions = vec!["state switching".to_string()];
    brief.factual_anchors = vec!["measurement outcomes".to_string()];
    brief.reference_hints = Vec::new();
    brief.query_profile = None;
    brief
}

#[test]
fn direct_author_runtime_failure_reason_ignores_console_noise_after_passed_state_change() {
    let evaluation = ChatArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: true,
        captures: vec![],
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 4,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 4,
        overall_score: 18,
        findings: vec![ChatArtifactRenderFinding {
            code: "runtime_boot_clean".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Blocked,
            summary: "TypeError: stale stage helper failed".to_string(),
        }],
        acceptance_obligations: vec![ChatArtifactAcceptanceObligation {
            obligation_id: "runtime_boot_clean".to_string(),
            family: "boot_truth".to_string(),
            required: true,
            status: ChatArtifactAcceptanceObligationStatus::Failed,
            summary: "No runtime witness errors were observed while validating the artifact."
                .to_string(),
            detail: Some("TypeError: stale stage helper failed".to_string()),
            witness_ids: vec!["witness-1".to_string()],
        }],
        execution_witnesses: vec![ChatArtifactExecutionWitness {
            witness_id: "witness-1".to_string(),
            obligation_id: Some("controls_execute_cleanly".to_string()),
            action_kind: "click".to_string(),
            status: ChatArtifactExecutionWitnessStatus::Passed,
            summary: "The control updated the rendered explanation.".to_string(),
            detail: Some("The rescue script updated the shared detail panel.".to_string()),
            selector: Some("[data-ioi-affordance-id=\"aff-1\"]".to_string()),
            console_errors: vec!["TypeError: stale stage helper failed".to_string()],
            state_changed: true,
        }],
        summary: "The artifact rendered and interacted successfully.".to_string(),
        observation: None,
        acceptance_policy: None,
    };

    assert!(super::generation::direct_author_runtime_failure_reason(Some(&evaluation)).is_none());
}

#[test]
fn direct_author_runtime_failure_reason_ignores_boot_noise_after_observed_state_change() {
    let evaluation = ChatArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: true,
        captures: vec![],
        observation: Some(ChatArtifactRenderObservation {
            primary_region_present: true,
            first_paint_visible_text_chars: 1200,
            mobile_visible_text_chars: 980,
            semantic_region_count: 4,
            evidence_surface_count: 2,
            response_region_count: 1,
            actionable_affordance_count: 3,
            active_affordance_count: 1,
            runtime_error_count: 0,
            interaction_state_changed: true,
        }),
        acceptance_policy: None,
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 4,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 4,
        overall_score: 18,
        findings: vec![ChatArtifactRenderFinding {
            code: "runtime_boot_clean".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Blocked,
            summary: "TypeError: stale stage helper failed".to_string(),
        }],
        acceptance_obligations: vec![ChatArtifactAcceptanceObligation {
            obligation_id: "runtime_boot_clean".to_string(),
            family: "boot_truth".to_string(),
            required: true,
            status: ChatArtifactAcceptanceObligationStatus::Failed,
            summary: "No runtime witness errors were observed while validating the artifact."
                .to_string(),
            detail: Some("TypeError: stale stage helper failed".to_string()),
            witness_ids: vec![],
        }],
        execution_witnesses: vec![],
        summary: "The artifact rendered and interacted successfully.".to_string(),
    };

    assert!(super::generation::direct_author_runtime_failure_reason(Some(&evaluation)).is_none());
}

#[test]
fn direct_author_html_generation_preserves_raw_document_contract_after_planning_context() {
    #[derive(Debug, Clone)]
    struct DirectAuthorRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
        json_modes: Arc<Mutex<Vec<bool>>>,
        provenance: ChatRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorRuntime {
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
                    "unexpected Chat prompt in direct-author test runtime: {prompt}"
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
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorRuntime {
        prompts: prompts.clone(),
        json_modes: json_modes.clone(),
        provenance: ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture direct-author runtime".to_string(),
            model: Some("fixture-direct-author".to_string()),
            endpoint: Some("fixture://direct-author".to_string()),
        },
    });
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let title = "Product rollout explainer";
    let intent = "Create an interactive HTML artifact that explains a product rollout with charts";
    let evaluator = ChatPassingRenderEvaluator;

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
        Some(ChatExecutionStrategy::DirectAuthor)
    );
    assert!(bundle.blueprint.is_some());
    assert!(bundle.artifact_ir.is_some());
    assert!(bundle.selected_skills.is_empty());
    assert_eq!(bundle.winner.files[0].path, "index.html");
    assert_eq!(
        bundle.validation.classification,
        ChatArtifactValidationStatus::Pass
    );
}

#[test]
fn direct_author_local_html_document_prompt_does_not_force_interaction_scaffolding() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
    let brief = ChatArtifactBrief {
        audience: "general audience".to_string(),
        job_to_be_done: "understand quantum computing basics".to_string(),
        subject_domain: "quantum computers".to_string(),
        artifact_thesis: "Explain quantum computers clearly in a compact authored HTML document."
            .to_string(),
        required_concepts: vec![
            "qubits".to_string(),
            "superposition".to_string(),
            "entanglement".to_string(),
        ],
        required_interactions: Vec::new(),
        query_profile: Some(ChatArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    ChatArtifactContentGoalKind::Orient,
                    "Orient the reader to quantum computers quickly.",
                ),
                required_content_goal(
                    ChatArtifactContentGoalKind::Explain,
                    "Explain the core ideas clearly.",
                ),
            ],
            interaction_goals: Vec::new(),
            evidence_goals: vec![required_evidence_goal(
                ChatArtifactEvidenceGoalKind::PrimarySurface,
                "Keep one grounded evidence surface visible on first paint.",
            )],
            presentation_constraints: vec![required_presentation_constraint(
                ChatArtifactPresentationConstraintKind::SemanticStructure,
                "Use semantic structure so the primary surface is legible before enhancement.",
            )],
        }),
        visual_tone: vec!["technical explainer clarity".to_string()],
        factual_anchors: vec!["quantum computing basics".to_string()],
        style_directives: vec!["clear evidence framing".to_string()],
        reference_hints: vec!["introductory explainer".to_string()],
    };

    let payload = build_chat_artifact_direct_author_prompt_for_runtime(
        "Quantum computers",
        "Create an HTML file that explains quantum computers",
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
    .expect("document direct-author prompt");

    let prompt_text = serde_json::to_string(&payload).expect("prompt text");
    assert!(prompt_text.contains("Create an HTML file that explains quantum computers"));
    assert!(prompt_text.contains("Required interactions: None specified"));
    assert!(!prompt_text.contains("Put the first actionable controls"));
    assert!(!prompt_text.contains("After the first complete interactive flow lands"));
}

#[tokio::test]
async fn direct_author_local_html_document_skips_continuation_and_repairs_directly() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct DocumentRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for DocumentRepairRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema") {
                    return Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Computers</title></head><body><main><section><h1>Quantum Computers Explained</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p></section><section><h2>Core Ideas</h2><ul><li>Qubits can represent probability amplitudes.</li><li>Measurement collapses those amplitudes into classical outcomes.</li><li>Error correction remains one of the major engineering constraints.</li></ul></section><section><h2>Why They Matter</h2><p>They are promising for simulation, optimization, and some cryptography-adjacent workloads, but current hardware is still noisy and specialized.</p></section></main></body></html>".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in html document repair runtime: {prompt}"
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
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema")
                    || prompt.contains("Continuation output schema")
                {
                    return self
                        .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                        .await;
                }

                let initial = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Computers</title></head><body><main><section><h1>Quantum Computers Explained</h1><p>Quantum computing compares qubits, gates, and measurement.</p></section><section><h2>Comparison</h2><div id=\"chart-shell\"></div></section><section><h2>Implications</h2><p>Researchers are exploring chemistry simulation and optimization.</p></section></main></body></html>";
                if let Some(stream) = token_stream {
                    let _ = stream.send(initial.to_string()).await;
                }
                Ok(initial.as_bytes().to_vec())
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
                    label: "fixture html document repair runtime".to_string(),
                    model: Some("fixture-html-document".to_string()),
                    endpoint: Some("fixture://html-document".to_string()),
                }
            }
        }

        let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
        let brief = ChatArtifactBrief {
            audience: "general audience".to_string(),
            job_to_be_done: "understand quantum computing basics".to_string(),
            subject_domain: "quantum computers".to_string(),
            artifact_thesis:
                "Explain quantum computers through visible evidence and a clear authored HTML reading experience."
                    .to_string(),
            required_concepts: vec![
                "qubits".to_string(),
                "superposition".to_string(),
                "measurement".to_string(),
            ],
            required_interactions: Vec::new(),
            query_profile: Some(ChatArtifactQueryProfile {
                content_goals: vec![
                    required_content_goal(
                        ChatArtifactContentGoalKind::Orient,
                        "Orient the reader to quantum computers quickly.",
                    ),
                    required_content_goal(
                        ChatArtifactContentGoalKind::Explain,
                        "Explain the core ideas clearly.",
                    ),
                ],
                interaction_goals: Vec::new(),
                evidence_goals: vec![required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep one grounded evidence surface visible on first paint.",
                )],
                presentation_constraints: vec![required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::SemanticStructure,
                    "Use semantic structure so the primary surface is legible before enhancement.",
                )],
            }),
            visual_tone: vec!["technical explainer clarity".to_string()],
            factual_anchors: vec!["quantum computing basics".to_string()],
            style_directives: vec!["clear evidence framing".to_string()],
            reference_hints: vec!["quantum computers basics".to_string()],
        };
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(DocumentRepairRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Computers",
            "Create an HTML file that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-document-repair",
            19,
            0.73,
            None,
            None,
        )
        .await
        .expect("html document should jump straight to repair");

        assert!(payload.files[0].body.contains("<main>"));
        assert!(payload.files[0].body.contains("Quantum Computers Explained"));
        assert!(!payload.files[0].body.contains("chart-shell"));

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

#[test]
fn direct_author_local_html_follow_up_refinement_stays_on_raw_document_path() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "general audience".to_string(),
        job_to_be_done: "update the existing detail toggle".to_string(),
        subject_domain: "details toggle demo".to_string(),
        artifact_thesis:
            "Keep the existing detail explainer intact while applying the requested copy edits."
                .to_string(),
        required_concepts: vec![
            "detail toggle".to_string(),
            "continuity-preserving follow-up".to_string(),
            "updated artifact labels".to_string(),
        ],
        required_interactions: vec![
            "click to reveal the details paragraph".to_string(),
            "inspect the updated heading and toggle label".to_string(),
        ],
        query_profile: None,
        visual_tone: vec![
            "compact editorial clarity".to_string(),
            "request-shaped continuity".to_string(),
        ],
        factual_anchors: vec!["existing layout".to_string()],
        style_directives: vec!["preserve layout rhythm".to_string()],
        reference_hints: vec!["single-file html artifact".to_string()],
    };
    let refinement = ChatArtifactRefinementContext {
        artifact_id: Some("artifact-1".to_string()),
        revision_id: Some("revision-1".to_string()),
        title: "The Detail Toggle".to_string(),
        summary: "A tiny single-file HTML artifact with a heading and a details toggle."
            .to_string(),
        renderer: ChatRendererKind::HtmlIframe,
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>The Detail Toggle</title></head><body><main><section><h1>The Detail Toggle</h1><p>The original artifact explains one details-based interaction.</p></section><section><details><summary>Show details</summary><p id=\"detail-copy\">Original detail copy.</p></details></section><aside><p>Original continuity note.</p></aside></main></body></html>".to_string(),
        }],
        selected_targets: vec![ChatArtifactSelectionTarget {
            source_surface: "render".to_string(),
            path: Some("index.html".to_string()),
            label: "heading and details summary".to_string(),
            snippet: "<h1>The Detail Toggle</h1> ... <summary>Show details</summary>".to_string(),
        }],
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
    };
    let edit_intent = ChatArtifactEditIntent {
        mode: ChatArtifactEditMode::Patch,
        summary: "Rename the heading and the main toggle label while keeping the existing layout."
            .to_string(),
        patch_existing_artifact: true,
        preserve_structure: true,
        target_scope: "hero heading and primary toggle label".to_string(),
        target_paths: vec!["index.html".to_string()],
        requested_operations: vec![
            "change heading to Details demo".to_string(),
            "rename Show details button to Reveal details".to_string(),
        ],
        tone_directives: Vec::new(),
        selected_targets: vec![
            ChatArtifactSelectionTarget {
                source_surface: "render".to_string(),
                path: Some("index.html".to_string()),
                label: "main heading".to_string(),
                snippet: "<h1>The Detail Toggle</h1>".to_string(),
            },
            ChatArtifactSelectionTarget {
                source_surface: "render".to_string(),
                path: Some("index.html".to_string()),
                label: "toggle button".to_string(),
                snippet: "<summary>Show details</summary>".to_string(),
            },
        ],
        style_directives: Vec::new(),
        branch_requested: false,
    };

    let payload = build_chat_artifact_direct_author_prompt_for_runtime(
        "Details toggle",
        "Change the heading to Details demo and rename the button to Reveal details while keeping the layout.",
        &request,
        &brief,
        &[],
        Some(&edit_intent),
        Some(&refinement),
        "candidate-1",
        7,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        true,
    )
    .expect("follow-up direct-author prompt");

    let prompt_text = serde_json::to_string(&payload).expect("prompt text");
    assert!(prompt_text.contains("Follow-up edit intent:"));
    assert!(prompt_text.contains("Current renderable artifact (index.html):"));
    assert!(prompt_text.contains("The Detail Toggle"));
    assert!(prompt_text.contains("Show details"));
    assert!(prompt_text.contains("Preserve layout and authored structure"));
    assert!(!prompt_text.contains("Artifact request focus JSON:"));
    assert!(!prompt_text.contains("Return exactly one JSON object"));
}

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

#[tokio::test]
async fn direct_author_modal_first_dead_controls_local_rescue_avoids_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct DeadControlsRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for DeadControlsRepairRuntime {
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
                    "unexpected non-streaming prompt in dead controls repair runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside></main></body></html>";
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
                    label: "fixture dead controls repair runtime".to_string(),
                    model: Some("fixture-dead-controls-repair".to_string()),
                    endpoint: Some("fixture://dead-controls-repair".to_string()),
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
            Arc::new(DeadControlsRepairRuntime {
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
            "candidate-dead-controls",
            37,
            0.72,
            None,
            None,
        )
        .await
        .expect("dead controls should be rescued locally before repair is needed");

        assert!(payload.files[0].body.contains("addEventListener"));
        assert!(payload.files[0]
            .body
            .contains("querySelectorAll('[data-view-panel]')"));
        assert!(payload.files[0]
            .body
            .contains("data-ioi-local-rescue=\"view-switch\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_stage_navigation_local_rescue_avoids_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct StageNavigationLocalRescueRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for StageNavigationLocalRescueRuntime {
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
                    "unexpected non-streaming prompt in stage navigation local rescue runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section id=\"stage-0\"><h1>Quantum Explorer</h1><p>Move through the stages to compare classical bits and qubits.</p><div><button id=\"btn-q1\" type=\"button\">Quantum basics</button><button id=\"btn-q2\" type=\"button\">Comparison</button><button id=\"btn-q3\" type=\"button\">Examples</button></div><aside><p id=\"detail-copy\">Stage 0 is selected by default.</p></aside></section><section id=\"stage-1\" style=\"display:none;\"><h2>Quantum basics</h2><p>Qubits can occupy superposition before measurement.</p></section><section id=\"stage-2\" style=\"display:none;\"><h2>Comparison</h2><p>Classical bits hold one state while qubits keep amplitudes in play.</p></section><section id=\"stage-3\" style=\"display:none;\"><h2>Examples</h2><p>Optimization and simulation are common examples.</p></section></main></body></html>";
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
                    label: "fixture stage navigation local rescue runtime".to_string(),
                    model: Some("fixture-stage-navigation-local-rescue".to_string()),
                    endpoint: Some("fixture://stage-navigation-local-rescue".to_string()),
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
            Arc::new(StageNavigationLocalRescueRuntime {
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
            "candidate-stage-local-rescue",
            41,
            0.72,
            None,
            None,
        )
        .await
        .expect("stage navigation should be rescued locally before repair is needed");

        assert!(payload.files[0].body.contains("data-ioi-local-rescue=\"stage-nav\""));
        assert!(payload.files[0].body.contains("aria-pressed"));
        assert!(payload.files[0].body.contains("Stage 0 is selected by default."));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_stage_navigation_rescue_synthesizes_missing_controls() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct StageNavigationSynthesisRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for StageNavigationSynthesisRuntime {
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
                    "unexpected non-streaming prompt in stage navigation synthesis runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section id=\"stage-0\"><h1>Quantum Explorer</h1><p>Move through the stages to compare classical bits and qubits.</p></section><section id=\"stage-1\" style=\"display:none;\"><h2>Quantum basics</h2><p>Qubits can occupy superposition before measurement.</p></section><section id=\"stage-2\" style=\"display:none;\"><h2>Comparison</h2><p>Classical bits hold one state while qubits keep amplitudes in play.</p></section></main></body></html>";
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
                    label: "fixture stage navigation synthesis runtime".to_string(),
                    model: Some("fixture-stage-navigation-synthesis".to_string()),
                    endpoint: Some("fixture://stage-navigation-synthesis".to_string()),
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
            Arc::new(StageNavigationSynthesisRuntime {
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
            "candidate-stage-nav-synthesis",
            43,
            0.72,
            None,
            None,
        )
        .await
        .expect("stage navigation rescue should synthesize missing controls locally");

        assert!(payload.files[0].body.contains("data-ioi-local-rescue=\"stage-nav\""));
        assert!(payload.files[0]
            .body
            .contains("data-ioi-local-rescue-target=\"stage-controls\""));
        assert!(payload.files[0].body.contains("Select a stage to update this explanation."));
        assert!(payload.files[0].body.contains("data-stage-target=\"0\""));
        assert!(payload.files[0].body.contains("addEventListener('focus'"));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_form_response_rescue_falls_through_to_repair_when_first_paint_underbuilt() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct UnderbuiltQuantumRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for UnderbuiltQuantumRuntime {
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
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\" data-detail=\\\"Basics are selected by default.\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\" data-detail=\\\"Measurement collapses amplitudes into observable outcomes.\\\">Measurement</button><button type=\\\"button\\\" data-view=\\\"examples\\\" aria-selected=\\\"false\\\" data-detail=\\\"Examples highlight optimization and simulation workloads.\\\">Examples</button></div></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\\\"examples\\\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in underbuilt quantum runtime: {prompt}"
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
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Adjust the qubit probability to see how amplitudes shift.</p><label for=\"probabilitySlider\">Quantum Probability</label><input id=\"probabilitySlider\" type=\"range\" min=\"0\" max=\"100\" value=\"50\"><div id=\"resultBox\">Current State: alpha = 50%, beta = 50%</div><h3>Interactive Comparison</h3></section><section><h2>Observation</h2><p>Qubits remain probabilistic until measured.</p></section></main></body></html>";
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
                    label: "fixture underbuilt quantum runtime".to_string(),
                    model: Some("fixture-underbuilt-quantum".to_string()),
                    endpoint: Some("fixture://underbuilt-quantum".to_string()),
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
            Arc::new(UnderbuiltQuantumRuntime {
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
            "candidate-underbuilt-quantum",
            43,
            0.72,
            None,
            None,
        )
        .await
        .expect("underbuilt first paint should fall through to repair");

        assert!(payload.files[0].body.contains("data-view=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));
        assert!(!payload.files[0]
            .body
            .contains("data-ioi-local-rescue=\"form-response\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_form_response_rescue_keeps_single_goal_slider_without_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct SingleGoalSliderRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for SingleGoalSliderRuntime {
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
                    "unexpected non-streaming prompt in single-goal slider runtime: {prompt}"
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
                self.prompts
                    .lock()
                    .expect("prompt log")
                    .push(prompt.clone());
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Slider</title></head><body><main><section><h1>Quantum Slider</h1><p>Adjust the amplitude to see the default explanation update inline.</p><label for=\"probabilitySlider\">Quantum Probability</label><input id=\"probabilitySlider\" type=\"range\" min=\"0\" max=\"100\" value=\"50\"><div id=\"resultBox\">Current State: alpha = 50%, beta = 50%</div></section><section><h2>Interpretation</h2><p>Higher alpha increases the likelihood of measuring 0.</p></section><aside><p id=\"detail-copy\">Adjust a control to update this explanation.</p></aside></main></body></html>";
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
                    label: "fixture single-goal slider runtime".to_string(),
                    model: Some("fixture-single-goal-slider".to_string()),
                    endpoint: Some("fixture://single-goal-slider".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = ChatArtifactBrief {
            audience: "curious learners".to_string(),
            job_to_be_done: "adjust one visible quantum state control".to_string(),
            subject_domain: "quantum basics".to_string(),
            artifact_thesis: "Show one adjustable qubit state with immediate inline explanation."
                .to_string(),
            required_concepts: vec!["superposition".to_string()],
            required_interactions: vec!["state manipulation".to_string()],
            visual_tone: vec!["editorial".to_string()],
            factual_anchors: vec!["measurement outcomes".to_string()],
            style_directives: vec!["clear hierarchy".to_string()],
            reference_hints: vec!["state diagrams".to_string()],
            query_profile: Some(ChatArtifactQueryProfile {
                content_goals: vec![required_content_goal(
                    ChatArtifactContentGoalKind::Explain,
                    "Explain the selected quantum probability state.",
                )],
                interaction_goals: vec![required_interaction_goal(
                    ChatArtifactInteractionGoalKind::StateAdjust,
                    "Adjust one visible state control.",
                )],
                evidence_goals: vec![required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep the adjusted state visible.",
                )],
                presentation_constraints: vec![
                    required_presentation_constraint(
                        ChatArtifactPresentationConstraintKind::FirstPaintEvidence,
                        "Populate the first paint with working state evidence.",
                    ),
                    required_presentation_constraint(
                        ChatArtifactPresentationConstraintKind::ResponseRegion,
                        "Keep a visible response region on first paint.",
                    ),
                ],
            }),
        };
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(SingleGoalSliderRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Slider",
            "Create an interactive HTML artifact with one slider that explains a quantum probability state",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-single-goal-slider",
            59,
            0.72,
            None,
            None,
        )
        .await
        .expect("single-goal slider should be rescued locally without repair");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-local-rescue=\"form-response\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_mismatched_nesting_is_repaired_locally_before_follow_up() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct MismatchedNestingLocalRescueRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for MismatchedNestingLocalRescueRuntime {
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
                    "unexpected non-streaming prompt in mismatched nesting local rescue runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title><style>body{margin:0;background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;}main{max-width:920px;margin:0 auto;padding:24px;}section{background:#111827;border:1px solid #334155;border-radius:18px;padding:18px;}button{border:1px solid #38bdf8;background:#1e293b;color:#e2e8f0;border-radius:999px;padding:8px 12px;}</style></head><body><main><section><h1>Quantum Explorer</h1><p>Use the buttons to compare the stages of a quantum explanation.</p><div class=\"controls\"><button type=\"button\">Basics</button><button type=\"button\">Measurement</button></div><div class=\"detail\"><p id=\"detail-copy\">Basics are selected by default.</p></section>";
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
                    label: "fixture mismatched nesting local rescue runtime".to_string(),
                    model: Some("fixture-mismatched-nesting-local-rescue".to_string()),
                    endpoint: Some("fixture://mismatched-nesting-local-rescue".to_string()),
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
            Arc::new(MismatchedNestingLocalRescueRuntime {
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
            "candidate-mismatched-nesting-local-rescue",
            59,
            0.72,
            None,
            None,
        )
        .await
        .expect("mismatched nesting should be repaired locally before continuation or repair");

        assert!(payload.files[0].body.contains("data-ioi-local-rescue=\"button-response\""));
        assert!(payload.files[0].body.contains("<div class=\"detail\"><p id=\"detail-copy\">"));
        assert!(payload.files[0].body.contains("</main></body></html>"));
        assert!(payload.files[0].body.ends_with("</html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Continuation output schema")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[test]
fn local_html_interaction_truth_rescue_promotes_scroll_nav_buttons_into_stateful_controls() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Computers Explained</title></head><body><header><nav><button onclick=\"document.getElementById('intro').scrollIntoView({behavior:'smooth'})\">Introduction</button><button onclick=\"document.getElementById('scenario').scrollIntoView({behavior:'smooth'})\">Scenario Explorer</button></nav></header><main><section id=\"intro\"><h2>Intro</h2><p>Quantum computers use qubits.</p></section><section id=\"scenario\"><h2>Scenario Explorer</h2><div class=\"status\" id=\"scenario-status\">Initializing...</div></section></main></body></html>";
    let (rescued, strategy) = super::generation::try_local_html_interaction_truth_rescue_document(
        &request,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        raw,
        "Surfaced controls executed without runtime errors or no-op behavior. successfulWitnesses=0 failedWitnesses=4",
    )
    .expect("scroll-nav interaction truth rescue should trigger");

    assert_eq!(strategy, "scroll_nav");
    assert!(rescued.contains("data-ioi-local-rescue=\"scroll-nav\""));
    assert!(rescued.contains("scenario-status"));
    assert!(rescued.contains("aria-pressed"));
    assert!(rescued.contains("setAttribute('role','status')"));
}

#[tokio::test]
async fn direct_author_large_local_incomplete_html_prefers_raw_continuation_over_repair() {
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
                    return Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>".as_bytes().to_vec());
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
                let repeated = "Quantum computers keep amplitudes in flight until measurement collapses the state. ".repeat(70);
                let raw = format!(
                    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>{}</p></section><section><h2>Superposition</h2><p>{}</p></section><section><h2>Measurement</h2><p>{}</p></section>",
                    repeated,
                    repeated,
                    repeated
                );
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

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
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
            "candidate-large-incomplete",
            39,
            0.72,
            None,
            None,
        )
        .await
        .expect("large incomplete local html should prefer continuation over repair");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));
        assert!(payload.files[0].body.ends_with("</html>"));

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
async fn direct_author_broken_inline_handlers_are_stripped_before_local_rescue() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct BrokenInlineHandlersLocalRescueRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for BrokenInlineHandlersLocalRescueRuntime {
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
                    "unexpected non-streaming prompt in broken inline handler rescue runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare the basics of qubits and measurement.</p><div><button type=\"button\" onclick=\"showStage(1)\">Basics</button><button type=\"button\" onclick=\"showStage(2)\">Measurement</button></div></section><section><p id=\"detail-copy\">Basics are selected by default.</p><span id=\"progress-bar\">0%</span></section></main></body></html>";
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
                    label: "fixture broken inline handlers local rescue runtime".to_string(),
                    model: Some("fixture-broken-inline-handlers-local-rescue".to_string()),
                    endpoint: Some("fixture://broken-inline-handlers-local-rescue".to_string()),
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
            Arc::new(BrokenInlineHandlersLocalRescueRuntime {
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
            "candidate-inline-handler-local-rescue",
            53,
            0.72,
            None,
            None,
        )
        .await
        .expect("broken inline handlers should be stripped before local rescue");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-local-rescue=\"button-response\""));
        assert!(!payload.files[0].body.contains("onclick=\"showStage"));
        assert!(payload.files[0].body.contains("aria-pressed"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_generic_button_rescue_injects_fallback_detail_region() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct FallbackDetailRegionLocalRescueRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for FallbackDetailRegionLocalRescueRuntime {
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
                    "unexpected non-streaming prompt in fallback detail region rescue runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare the stages of a quantum algorithm.</p><div><button type=\"button\">Prepare state</button><button type=\"button\">Measure output</button></div></section><section><p class=\"explanation\">The first button should explain the prepared state, but it has no live region yet.</p></section></main></body></html>";
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
                    label: "fixture fallback detail region local rescue runtime".to_string(),
                    model: Some("fixture-fallback-detail-region-local-rescue".to_string()),
                    endpoint: Some("fixture://fallback-detail-region-local-rescue".to_string()),
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
            Arc::new(FallbackDetailRegionLocalRescueRuntime {
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
            "candidate-fallback-detail-region-local-rescue",
            67,
            0.72,
            None,
            None,
        )
        .await
        .expect("inert button controls should gain a fallback detail region before repair");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-local-rescue-target=\"detail-copy\""));
        assert!(payload.files[0]
            .body
            .contains("data-ioi-local-rescue=\"button-response\""));
        assert!(payload.files[0].body.contains("Select a control to update this explanation."));
        assert!(payload.files[0].body.contains("setAttribute('role','status')"));
        assert!(payload.files[0].body.contains("activate(buttons[0],0)"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_form_control_rescue_wires_inert_range_inputs() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct FormControlLocalRescueRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for FormControlLocalRescueRuntime {
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
                    "unexpected non-streaming prompt in form control rescue runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Move the slider to compare how quantum state counts grow.</p><label for=\"n-qubits\">Simulate Scaling</label><input type=\"range\" id=\"n-qubits\" min=\"1\" max=\"3\" value=\"1\"><span id=\"sim-result\">1 Qubit = 2 States</span></section></main></body></html>";
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
                    label: "fixture form control local rescue runtime".to_string(),
                    model: Some("fixture-form-control-local-rescue".to_string()),
                    endpoint: Some("fixture://form-control-local-rescue".to_string()),
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
            Arc::new(FormControlLocalRescueRuntime {
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
            "candidate-form-control-local-rescue",
            61,
            0.72,
            None,
            None,
        )
        .await
        .expect("inert range inputs should be rescued locally before repair is needed");

        assert!(payload.files[0].body.contains("data-ioi-local-rescue=\"form-response\""));
        assert!(payload.files[0].body.contains("aria-valuetext"));
        assert!(payload.files[0].body.contains("1 Qubit = 2 States"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_local_rescue_strips_broken_inline_script_blocks() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct BrokenInlineScriptLocalRescueRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for BrokenInlineScriptLocalRescueRuntime {
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
                    "unexpected non-streaming prompt in broken inline script rescue runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare the states of a quantum system.</p><div><button type=\"button\">Prepare state</button><button type=\"button\">Measure output</button></div></section><section><p>Use the buttons to update the explanation below.</p></section><script>const stage=document.getElementById('artifact-stage');stage.forEach(()=>{});</script></main></body></html>";
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
                    label: "fixture broken inline script local rescue runtime".to_string(),
                    model: Some("fixture-broken-inline-script-local-rescue".to_string()),
                    endpoint: Some("fixture://broken-inline-script-local-rescue".to_string()),
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
            Arc::new(BrokenInlineScriptLocalRescueRuntime {
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
            "candidate-broken-inline-script-local-rescue",
            71,
            0.72,
            None,
            None,
        )
        .await
        .expect("broken inline scripts should be stripped before local rescue");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-local-rescue=\"button-response\""));
        assert!(!payload.files[0]
            .body
            .contains("stage.forEach(()=>{})"));
        assert!(payload.files[0].body.contains("Select a control to update this explanation."));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_structurally_closed_partial_html_is_trimmed_locally_before_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct StructuralTrimLocalRescueRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for StructuralTrimLocalRescueRuntime {
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
                    "unexpected non-streaming prompt in structural trim local rescue runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the toggles to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script><section><h2>Broken tail</h2><div class=\"comparison\"><p>This trailing section should be trimmed before repair.</section></main></body></html>";
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
                    label: "fixture structural trim local rescue runtime".to_string(),
                    model: Some("fixture-structural-trim-local-rescue".to_string()),
                    endpoint: Some("fixture://structural-trim-local-rescue".to_string()),
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
            Arc::new(StructuralTrimLocalRescueRuntime {
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
            "candidate-structural-trim-local-rescue",
            59,
            0.72,
            None,
            None,
        )
        .await
        .expect("structurally broken trailing html should be trimmed locally before repair");

        assert!(payload.files[0].body.contains("Measurement is selected."));
        assert!(!payload.files[0]
            .body
            .contains("This trailing section should be trimmed before repair."));
        assert!(payload.files[0].body.ends_with("</html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Continuation output schema")));
    })
    .await;
}

#[tokio::test]
async fn local_html_hybrid_raw_document_timeout_is_bounded() {
    #[derive(Debug, Clone)]
    struct HangingHybridLocalHtmlRuntime;

    #[async_trait]
    impl InferenceRuntime for HangingHybridLocalHtmlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in hybrid local html timeout runtime: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
            _token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            if prompt.contains("direct document author")
                || prompt.contains("Return only one complete self-contained index.html.")
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Ok(b"<!doctype html><html><body><main><section>late</section></main></body></html>".to_vec());
            }
            Err(VmError::HostError(format!(
                "unexpected streaming prompt in hybrid local html timeout runtime: {prompt}"
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture hanging hybrid local html runtime".to_string(),
                model: Some("fixture-hanging-hybrid-local-html".to_string()),
                endpoint: Some("fixture://hanging-hybrid-local-html".to_string()),
            }
        }
    }

    let previous_timeout =
        std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS").ok();
    std::env::set_var(
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
        "50",
    );

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_simple_quantum_interactive_brief();
    let result = super::generation::materialize_chat_artifact_candidate_with_runtime_detailed(
        Arc::new(HangingHybridLocalHtmlRuntime),
        None,
        "Quantum Explorer",
        "Create a simple interactive HTML artifact that explains qubits",
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
        Some(value) => std::env::set_var(
            "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
            value,
        ),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS"),
    }

    let error =
        result.expect_err("hybrid local html materialization should time out instead of hanging");
    assert!(error.message.contains(
        "Chat direct-author artifact inference failed: Host function error: Chat direct-author artifact inference timed out"
    ));
}

#[tokio::test]
async fn local_html_hybrid_materialization_uses_raw_document_authoring_and_fast_finishes() {
    #[derive(Debug, Clone)]
    struct BoundaryAwareHybridLocalHtmlRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for BoundaryAwareHybridLocalHtmlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in boundary-aware hybrid runtime: {prompt}"
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
            self.prompts
                .lock()
                .expect("prompt log")
                .push(prompt.clone());
            if !prompt.contains("direct document author")
                && !prompt.contains("Return only one complete self-contained index.html.")
            {
                return Err(VmError::HostError(format!(
                    "unexpected streaming prompt in boundary-aware hybrid runtime: {prompt}"
                )));
            }

            let chunks = [
                "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main>".to_string(),
                "<section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div><button type=\"button\" data-view=\"concepts\" aria-selected=\"true\">Core concepts</button><button type=\"button\" data-view=\"hardware\" aria-selected=\"false\">Hardware limits</button></div></section>".to_string(),
                "<section data-view-panel=\"concepts\"><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><section data-view-panel=\"hardware\" hidden><h2>Hardware limits</h2><p>Error rates, cooling systems, and qubit connectivity are still major constraints.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.innerHTML=button.dataset.view==='concepts'?'Core concepts are selected by default.':'Hardware limits are selected.';}));</script></main></body></html>".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
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
                label: "fixture boundary-aware hybrid local html runtime".to_string(),
                model: Some("fixture-boundary-aware-hybrid-local-html".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_simple_quantum_interactive_brief();
    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let started_at = std::time::Instant::now();

    let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_detailed(
        Arc::new(BoundaryAwareHybridLocalHtmlRuntime {
            prompts: prompts.clone(),
        }),
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
        "candidate-hybrid-fast-finish",
        29,
        0.72,
        None,
    )
    .await
    .expect("hybrid local html materialization should finish from the streamed boundary");

    assert!(started_at.elapsed() < Duration::from_secs(3));
    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0].body.ends_with("</html>"));
    assert!(payload.files[0].body.contains("detail-copy"));

    let prompt_log = prompts.lock().expect("prompt log");
    assert!(prompt_log.iter().any(|prompt| {
        prompt.contains("direct document author")
            || prompt.contains("Return only one complete self-contained index.html.")
            || prompt.contains("Return only one complete self-contained HTML document.")
    }));
    assert!(!prompt_log
        .iter()
        .any(|prompt| prompt.contains("typed artifact materializer")));
}

#[tokio::test]
async fn local_html_hybrid_materialization_fast_finishes_when_body_closes() {
    #[derive(Debug, Clone)]
    struct BodyClosedHybridLocalHtmlRuntime;

    #[async_trait]
    impl InferenceRuntime for BodyClosedHybridLocalHtmlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in body-closed hybrid runtime: {prompt}"
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
                return Err(VmError::HostError(format!(
                    "unexpected streaming prompt in body-closed hybrid runtime: {prompt}"
                )));
            }

            let chunks = [
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main>".to_string(),
                "<section><h1>Quantum Explorer</h1><p>Use the toggles to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section>".to_string(),
                "<section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main></body>".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
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
                label: "fixture body-closed hybrid local html runtime".to_string(),
                model: Some("fixture-body-closed-hybrid-local-html".to_string()),
                endpoint: Some("fixture://body-closed-hybrid-local-html".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_simple_quantum_interactive_brief();
    let started_at = std::time::Instant::now();

    let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_detailed(
        Arc::new(BodyClosedHybridLocalHtmlRuntime),
        None,
        "Quantum Explorer",
        "Create a simple interactive HTML artifact that explains qubits",
        &request,
        &brief,
        None,
        None,
        &[],
        &[],
        None,
        None,
        "candidate-hybrid-body-fast-finish",
        31,
        0.72,
        None,
    )
    .await
    .expect("hybrid local html should finish when the stream settles at </body>");

    assert!(started_at.elapsed() < Duration::from_secs(3));
    assert!(payload.files[0].body.ends_with("</html>"));
    assert!(payload.files[0].body.contains("Measurement is selected."));
}

#[tokio::test]
async fn local_html_hybrid_materialization_fast_finishes_when_main_closes() {
    #[derive(Debug, Clone)]
    struct MainClosedHybridLocalHtmlRuntime;

    #[async_trait]
    impl InferenceRuntime for MainClosedHybridLocalHtmlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in main-closed hybrid runtime: {prompt}"
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
                return Err(VmError::HostError(format!(
                    "unexpected streaming prompt in main-closed hybrid runtime: {prompt}"
                )));
            }

            let chunks = [
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main>".to_string(),
                "<section><h1>Quantum Explorer</h1><p>Use the toggles to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section>".to_string(),
                "<section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main>".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
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
                label: "fixture main-closed hybrid local html runtime".to_string(),
                model: Some("fixture-main-closed-hybrid-local-html".to_string()),
                endpoint: Some("fixture://main-closed-hybrid-local-html".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_simple_quantum_interactive_brief();
    let started_at = std::time::Instant::now();

    let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_detailed(
        Arc::new(MainClosedHybridLocalHtmlRuntime),
        None,
        "Quantum Explorer",
        "Create a simple interactive HTML artifact that explains qubits",
        &request,
        &brief,
        None,
        None,
        &[],
        &[],
        None,
        None,
        "candidate-hybrid-main-finish",
        61,
        0.72,
        None,
    )
    .await
    .expect("hybrid local html materialization should finish from the streamed </main> boundary");

    assert!(started_at.elapsed() < Duration::from_secs(3));
    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0].body.ends_with("</html>"));
    assert!(payload.files[0].body.contains("Measurement is selected."));
}

#[tokio::test]
async fn local_html_hybrid_materialization_fast_finishes_from_stable_renderable_prefix_before_trailing_chatter(
) {
    #[derive(Debug, Clone)]
    struct StablePrefixHybridLocalHtmlRuntime;

    #[async_trait]
    impl InferenceRuntime for StablePrefixHybridLocalHtmlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            Err(VmError::HostError(format!(
                "unexpected non-streaming prompt in stable-prefix runtime: {prompt}"
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
                return Err(VmError::HostError(format!(
                    "unexpected streaming prompt in stable-prefix runtime: {prompt}"
                )));
            }

            let chunks = [
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main>".to_string(),
                "<section><h1>Quantum Explorer</h1><p>Use the toggles to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section>".to_string(),
                "<section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main>".to_string(),
                "\nAdditional notes that should not keep the renderable prefix alive forever.".to_string(),
                "\nThe local model keeps talking after the document is already good enough.".to_string(),
            ];
            if let Some(sender) = token_stream.as_ref() {
                for chunk in &chunks {
                    sender.send(chunk.clone()).await.map_err(|error| {
                        VmError::HostError(format!("stream send failed: {error}"))
                    })?;
                    tokio::time::sleep(Duration::from_millis(60)).await;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
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
                label: "fixture stable-prefix hybrid local html runtime".to_string(),
                model: Some("fixture-stable-prefix-hybrid-local-html".to_string()),
                endpoint: Some("fixture://stable-prefix-hybrid-local-html".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_simple_quantum_interactive_brief();
    let started_at = std::time::Instant::now();

    let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_detailed(
        Arc::new(StablePrefixHybridLocalHtmlRuntime),
        None,
        "Quantum Explorer",
        "Create a simple interactive HTML artifact that explains qubits",
        &request,
        &brief,
        None,
        None,
        &[],
        &[],
        None,
        None,
        "candidate-hybrid-stable-prefix-finish",
        71,
        0.72,
        None,
    )
    .await
    .expect("hybrid local html should fast-finish from the first stable renderable prefix");

    assert!(started_at.elapsed() < Duration::from_secs(3));
    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0].body.ends_with("</html>"));
    assert!(!payload.files[0]
        .body
        .contains("Additional notes that should not keep"));
    assert!(payload.files[0].body.contains("Measurement is selected."));
}

#[tokio::test]
async fn complex_local_html_materialization_prefers_plan_backed_direct_author_streaming() {
    #[derive(Debug, Clone)]
    struct ComplexLocalDirectAuthorRuntime {
        prompts: Arc<Mutex<Vec<String>>>,
        streaming_json_modes: Arc<Mutex<Vec<bool>>>,
        streaming_max_tokens: Arc<Mutex<Vec<u32>>>,
        streaming_stop_sequences: Arc<Mutex<Vec<Vec<String>>>>,
    }

    #[async_trait]
    impl InferenceRuntime for ComplexLocalDirectAuthorRuntime {
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
                "complex local html should stream a raw document instead of using non-streaming typed materialization: {prompt}"
            )))
        }

        async fn execute_inference_streaming(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
            _token_stream: Option<Sender<String>>,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            self.prompts
                .lock()
                .expect("prompt log")
                .push(prompt.clone());
            self.streaming_json_modes
                .lock()
                .expect("json mode log")
                .push(options.json_mode);
            self.streaming_max_tokens
                .lock()
                .expect("max tokens log")
                .push(options.max_tokens);
            self.streaming_stop_sequences
                .lock()
                .expect("stop sequences log")
                .push(options.stop_sequences.clone());
            if !prompt.contains("Return only one complete self-contained index.html.") {
                return Err(VmError::HostError(format!(
                    "expected direct-author prompt for complex local html materialization: {prompt}"
                )));
            }
            Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main><section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div><button type=\"button\" data-view=\"concepts\" aria-selected=\"true\">Core concepts</button><button type=\"button\" data-view=\"hardware\" aria-selected=\"false\">Hardware limits</button></div></section><section data-view-panel=\"concepts\"><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><section data-view-panel=\"hardware\" hidden><h2>Hardware limits</h2><p>Error rates, cooling systems, and qubit connectivity are still major constraints.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='concepts'?'Core concepts are selected by default.':'Hardware limits are selected.';}));</script></main></body></html>".as_bytes().to_vec())
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
                label: "fixture complex local direct-author runtime".to_string(),
                model: Some("fixture-complex-local-direct-author".to_string()),
                endpoint: Some("fixture://complex-local-direct-author".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let streaming_json_modes = Arc::new(Mutex::new(Vec::<bool>::new()));
    let streaming_max_tokens = Arc::new(Mutex::new(Vec::<u32>::new()));
    let streaming_stop_sequences = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));

    let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_detailed(
        Arc::new(ComplexLocalDirectAuthorRuntime {
            prompts: prompts.clone(),
            streaming_json_modes: streaming_json_modes.clone(),
            streaming_max_tokens: streaming_max_tokens.clone(),
            streaming_stop_sequences: streaming_stop_sequences.clone(),
        }),
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
        "candidate-complex-typed-path",
        73,
        0.72,
        None,
    )
    .await
    .expect("complex local html materialization should stay on the plan-backed direct-author path");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload.files[0]
        .body
        .contains("Quantum computers explained"));

    let prompt_log = prompts.lock().expect("prompt log");
    assert!(prompt_log
        .iter()
        .any(|prompt| prompt.contains("Return only one complete self-contained index.html.")));
    assert!(!prompt_log
        .iter()
        .any(|prompt| prompt.contains("typed artifact materializer")));
    assert_eq!(
        &*streaming_json_modes.lock().expect("json mode log"),
        &[false]
    );
    assert_eq!(
        &*streaming_max_tokens.lock().expect("max tokens log"),
        &[2400]
    );
    assert_eq!(
        &*streaming_stop_sequences.lock().expect("stop sequences log"),
        &[vec!["</html>".to_string()]]
    );
}

#[tokio::test]
async fn local_html_materialization_repairs_runtime_failure_before_surface() {
    #[derive(Debug, Clone)]
    struct PlanExecuteRuntimeRepairRuntime {
        calls: Arc<Mutex<Vec<String>>>,
        provenance: ChatRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for PlanExecuteRuntimeRepairRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact materialization repairer")
                || prompt.contains("typed direct document repair author")
                || prompt.contains("Repair output schema")
            {
                "repair"
            } else if prompt.contains("typed artifact materializer")
                || prompt.contains("direct document author")
                || prompt.contains("Return only one complete self-contained index.html.")
                || prompt.contains("Return only one complete self-contained HTML document.")
            {
                "materialize"
            } else {
                "unknown"
            };
            self.calls
                .lock()
                .expect("calls lock")
                .push(stage.to_string());

            let response = match stage {
                "materialize" => "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main><section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div><button type=\"button\" data-view=\"concepts\" aria-selected=\"true\">Core concepts</button><button type=\"button\" data-view=\"hardware\" aria-selected=\"false\">Hardware limits</button></div></section><section data-view-panel=\"concepts\"><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><section data-view-panel=\"hardware\" hidden><h2>Hardware limits</h2><p>Error rates, cooling systems, and qubit connectivity are still major constraints.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('missing-detail');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.innerHTML=button.dataset.view==='concepts'?'Core concepts are selected by default.':'Hardware limits are selected.';}));</script></main></body></html>".to_string(),
                "repair" => "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Quantum Computing Explained</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:960px;margin:0 auto;padding:32px;display:grid;gap:20px;}section,aside{background:#172033;border:1px solid #334155;border-radius:20px;padding:20px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 14px;}</style></head><body><main data-repaired=\"runtime-error\"><section><h1>Quantum computers explained through qubits, interference, and error correction</h1><p>Quantum computers use qubits, superposition, and interference to solve some classes of problems differently from classical machines.</p><div><button type=\"button\" data-view=\"concepts\" aria-selected=\"true\">Core concepts</button><button type=\"button\" data-view=\"hardware\" aria-selected=\"false\">Hardware limits</button></div></section><section data-view-panel=\"concepts\"><h2>Core concepts</h2><p>Qubits keep amplitudes in play, gates reshape those amplitudes, and measurement samples a classical answer.</p></section><section data-view-panel=\"hardware\" hidden><h2>Hardware limits</h2><p>Error rates, cooling systems, and qubit connectivity are still major constraints.</p></section><aside><p id=\"detail-copy\">Core concepts are selected by default.</p></aside><script>const buttons=[...document.querySelectorAll('button[data-view]')];const panels=[...document.querySelectorAll('[data-view-panel]')];const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.innerHTML=button.dataset.view==='concepts'?'Core concepts are selected by default.':'Hardware limits are selected.';}));</script></main></body></html>".to_string(),
                _ => {
                    return Err(VmError::HostError(format!(
                        "unexpected Chat prompt in plan-execute runtime repair test: {prompt}"
                    )))
                }
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            self.provenance.clone()
        }
    }

    #[derive(Default)]
    struct PlanExecuteRuntimeErrorEvaluator;

    #[async_trait]
    impl ChatArtifactRenderEvaluator for PlanExecuteRuntimeErrorEvaluator {
        async fn evaluate_candidate_render(
            &self,
            _request: &ChatOutcomeArtifactRequest,
            _brief: &ChatArtifactBrief,
            _blueprint: Option<&ChatArtifactBlueprint>,
            _artifact_ir: Option<&ChatArtifactIR>,
            _edit_intent: Option<&ChatArtifactEditIntent>,
            candidate: &ChatGeneratedArtifactPayload,
        ) -> Result<Option<ChatArtifactRenderEvaluation>, String> {
            let repaired = candidate
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .map(|file| file.body.contains("data-repaired=\"runtime-error\""))
                .unwrap_or(false);
            if repaired {
                return Ok(Some(chat_test_render_evaluation(
                    20,
                    true,
                    Vec::new(),
                    vec![
                        chat_test_render_capture(
                            ChatArtifactRenderCaptureViewport::Desktop,
                            84,
                            620,
                            4,
                        ),
                        chat_test_render_capture(
                            ChatArtifactRenderCaptureViewport::Mobile,
                            72,
                            540,
                            4,
                        ),
                    ],
                )));
            }

            Ok(Some(ChatArtifactRenderEvaluation {
                supported: true,
                first_paint_captured: true,
                interaction_capture_attempted: true,
                captures: vec![
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Desktop,
                        80,
                        580,
                        4,
                    ),
                    chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 68, 500, 4),
                ],
                layout_density_score: 3,
                spacing_alignment_score: 3,
                typography_contrast_score: 4,
                visual_hierarchy_score: 3,
                blueprint_consistency_score: 3,
                overall_score: 12,
                findings: vec![ChatArtifactRenderFinding {
                    code: "runtime_boot_clean".to_string(),
                    severity: ChatArtifactRenderFindingSeverity::Blocked,
                    summary: "TypeError: Cannot set properties of null (setting 'innerHTML')"
                        .to_string(),
                }],
                acceptance_obligations: vec![ChatArtifactAcceptanceObligation {
                    obligation_id: "runtime_boot_clean".to_string(),
                    family: "boot_truth".to_string(),
                    required: true,
                    status: ChatArtifactAcceptanceObligationStatus::Failed,
                    summary:
                        "No runtime witness errors were observed while validating the artifact."
                            .to_string(),
                    detail: Some(
                        "TypeError: Cannot set properties of null (setting 'innerHTML')"
                            .to_string(),
                    ),
                    witness_ids: vec!["witness-1".to_string()],
                }],
                execution_witnesses: vec![ChatArtifactExecutionWitness {
                    witness_id: "witness-1".to_string(),
                    obligation_id: Some("controls_execute_cleanly".to_string()),
                    action_kind: "click".to_string(),
                    status: ChatArtifactExecutionWitnessStatus::Failed,
                    summary: "'Core concepts' triggered a runtime error.".to_string(),
                    detail: Some(
                        "TypeError: Cannot set properties of null (setting 'innerHTML')"
                            .to_string(),
                    ),
                    selector: Some("[data-ioi-affordance-id=\"aff-1\"]".to_string()),
                    console_errors: vec![
                        "TypeError: Cannot set properties of null (setting 'innerHTML')"
                            .to_string(),
                    ],
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
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(PlanExecuteRuntimeRepairRuntime {
            calls: calls.clone(),
            provenance: ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture plan-execute producer".to_string(),
                model: Some("fixture-qwen-9b".to_string()),
                endpoint: Some("fixture://plan-execute".to_string()),
            },
        });
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let provenance = runtime.chat_runtime_provenance();
        let evaluator = PlanExecuteRuntimeErrorEvaluator;

        let (summary, payload) = super::generation::materialize_and_locally_validation_candidate(
            runtime.clone(),
            runtime.clone(),
            Some(&evaluator),
            "Quantum computing explainer",
            "Create an interactive HTML artifact that explains quantum computers.",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-runtime-repair",
            17,
            0.72,
            "request-grounded_html",
            ChatArtifactOutputOrigin::FixtureRuntime,
            "fixture-qwen-9b",
            &provenance,
            None,
        )
        .await
        .expect("plan-execute runtime repair should recover");

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|entry| entry == "materialize"));
        assert!(recorded_calls.iter().any(|entry| entry == "repair"));
        assert_eq!(
            summary.validation.classification,
            ChatArtifactValidationStatus::Pass
        );
        assert!(payload.files[0]
            .body
            .contains("data-repaired=\"runtime-error\""));
    })
    .await;
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
            let prompt = decode_chat_test_prompt(input_context);
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
            let prompt = decode_chat_test_prompt(input_context);
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture hanging direct-author runtime".to_string(),
                model: Some("fixture-hanging-direct-author".to_string()),
                endpoint: Some("fixture://hanging-direct-author".to_string()),
            }
        }
    }

    let previous_timeout =
        std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS").ok();
    std::env::set_var(
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
        "50",
    );

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
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

    let payload_result =
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(HangingStreamingDirectAuthorRuntime),
            None,
            "Quantum computers",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-timeout",
            11,
            0.72,
            Some(live_preview_observer),
            None,
        )
        .await;

    match previous_timeout {
        Some(value) => std::env::set_var(
            "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
            value,
        ),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS"),
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
async fn direct_author_stream_timeout_uses_follow_up_inference_for_truncated_modal_first_html() {
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
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Continuation output schema")
                    || prompt.contains("typed direct document continuation author")
                {
                    return Ok(
                        serde_json::json!({
                            "mode": "full_document",
                            "content": "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Adjust the controls to compare superposition and measurement.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement is selected.\">Measurement</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>button.addEventListener('click',()=>activate(button)));activate(buttons[0]);</script></main></body></html>"
                        })
                        .to_string()
                        .into_bytes(),
                    );
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in truncated modal-first runtime: {prompt}"
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
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if !prompt.contains("direct document author")
                    && !prompt.contains("Return only one complete self-contained index.html.")
                {
                    return self
                        .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                        .await;
                }
                let partial = "<!doctype html><html><body><main><section><h1>Quantum Explorer</h1><p>Adjust the controls to compare superposition and measurement.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\">Measurement</button></div></section><section><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><aside><h2>Detail</h2><p id=\"detail-copy\">Basics are selected by default.</p>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(partial.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Err(VmError::HostError(
                    "timed out while completing quantum explorer".to_string(),
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
                    label: "fixture normalizable interrupted runtime".to_string(),
                    model: Some("fixture-normalizable-interrupted".to_string()),
                    endpoint: Some("fixture://normalizable-interrupted".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_simple_quantum_interactive_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));

        let payload = super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(NormalizableInterruptedDirectAuthorRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Quantum Explorer",
            "Create a simple interactive HTML artifact that explains qubits",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-normalized-timeout",
            29,
            0.72,
            None,
            None,
        )
        .await
        .expect("truncated modal-first html should recover through follow-up inference");

        let html_lower = payload.files[0].body.to_ascii_lowercase();
        assert!(html_lower.ends_with("</main></body></html>"));
        assert!(html_lower.contains("</aside>"));
        assert!(html_lower.matches("</section>").count() >= 2);
        assert!(payload.files[0].body.contains("data-view-panel=\"measurement\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(
            prompt_log
                .iter()
                .any(|prompt| prompt.contains("Continuation output schema")
                    || prompt.contains("typed direct document continuation author"))
        );
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
                let prompt = decode_chat_test_prompt(input_context);
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
                let prompt = decode_chat_test_prompt(input_context);
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

            fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
                ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture trailing-fragment interrupted runtime".to_string(),
                    model: Some("fixture-trailing-fragment".to_string()),
                    endpoint: Some("fixture://trailing-fragment".to_string()),
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
async fn direct_author_idle_fast_finish_uses_stable_stream_snapshot() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct IdleSnapshotRuntime;

        #[async_trait]
        impl InferenceRuntime for IdleSnapshotRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in idle snapshot runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
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
                    label: "fixture idle snapshot runtime".to_string(),
                    model: Some("fixture-idle-snapshot".to_string()),
                    endpoint: Some("fixture://idle-snapshot".to_string()),
                }
            }
        }

        let previous_stream_timeout =
            std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS").ok();
        let previous_idle_timeout =
            std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS").ok();
        std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", "500");
        std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS", "50");

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let started = std::time::Instant::now();
        let payload_result =
            super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
                Arc::new(IdleSnapshotRuntime),
                None,
                "Quantum Explorer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                &brief,
                &[],
                None,
                None,
                "candidate-idle-fast-finish",
                41,
                0.72,
                None,
                None,
            )
            .await;

        match previous_stream_timeout {
            Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", value),
            None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS"),
        }
        match previous_idle_timeout {
            Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS", value),
            None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS"),
        }

        let payload =
            payload_result.expect("idle stream snapshot should finish without waiting for timeout");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(payload.files[0].body.contains("data-view-panel=\"measurement\""));
    })
    .await;
}

#[tokio::test]
async fn direct_author_idle_fast_finish_ignores_trailing_whitespace_dribble() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct IdleWhitespaceDribbleRuntime;

        #[async_trait]
        impl InferenceRuntime for IdleWhitespaceDribbleRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in idle whitespace runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(raw.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                    for chunk in [" ", "\n", "  ", "\n"] {
                        tokio::time::sleep(Duration::from_millis(35)).await;
                        sender
                            .send(chunk.to_string())
                            .await
                            .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(format!("{raw}  \n").into_bytes())
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
                    label: "fixture idle whitespace runtime".to_string(),
                    model: Some("fixture-idle-whitespace".to_string()),
                    endpoint: Some("fixture://idle-whitespace".to_string()),
                }
            }
        }

        let previous_stream_timeout =
            std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS").ok();
        let previous_idle_timeout =
            std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS").ok();
        std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", "500");
        std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS", "50");

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let started = std::time::Instant::now();
        let payload_result =
            super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
                Arc::new(IdleWhitespaceDribbleRuntime),
                None,
                "Quantum Explorer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                &brief,
                &[],
                None,
                None,
                "candidate-idle-whitespace-fast-finish",
                43,
                0.72,
                None,
                None,
            )
            .await;

        match previous_stream_timeout {
            Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", value),
            None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS"),
        }
        match previous_idle_timeout {
            Some(value) => std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS", value),
            None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS"),
        }

        let payload =
            payload_result.expect("whitespace-only trailing chunks should not prevent idle fast finish");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(payload.files[0].body.ends_with("</main></body></html>"));
    })
    .await;
}

#[tokio::test]
async fn direct_author_boundary_fast_finish_uses_completed_document_prefix() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct BoundaryPrefixRuntime;

        #[async_trait]
        impl InferenceRuntime for BoundaryPrefixRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in boundary prefix runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                _input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let complete = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></HTML>";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(format!("{complete}\n\n<!-- trailing junk after terminal boundary -->"))
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(format!("{complete}\n\n<!-- trailing junk after terminal boundary -->").into_bytes())
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
                    label: "fixture boundary prefix runtime".to_string(),
                    model: Some("fixture-boundary-prefix".to_string()),
                    endpoint: Some("fixture://boundary-prefix".to_string()),
                }
            }
        }

        let previous_stream_timeout =
            std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS").ok();
        let previous_boundary_timeout =
            std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS").ok();
        std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", "700");
        std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS", "50");

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let started_at = tokio::time::Instant::now();
        let payload =
            super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(BoundaryPrefixRuntime),
            None,
            "Quantum explorer",
            "Create a compact interactive explainer for quantum computing",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-boundary-prefix",
            47,
            0.42,
            None,
            None,
        )
            .await
            .expect("boundary prefix snapshot should fast-finish");

        if let Some(value) = previous_stream_timeout {
            std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS", value);
        } else {
            std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS");
        }
        if let Some(value) = previous_boundary_timeout {
            std::env::set_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS", value);
        } else {
            std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS");
        }

        assert!(
            started_at.elapsed() < Duration::from_millis(700),
            "completed document prefix should finish before the stream timeout"
        );
        let html_lower = payload.files[0].body.to_ascii_lowercase();
        assert!(html_lower.ends_with("</body></html>"));
        assert!(!html_lower.contains("trailing junk after terminal boundary"));
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
            let prompt = decode_chat_test_prompt(input_context);
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
                label: "fixture hanging continuation runtime".to_string(),
                model: Some("fixture-hanging-continuation".to_string()),
                endpoint: Some("fixture://hanging-continuation".to_string()),
            }
        }
    }

    let previous_timeout =
        std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS").ok();
    std::env::set_var(
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
        "50",
    );

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
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

    let payload_result =
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(HangingContinuationDirectAuthorRuntime),
            None,
            "Quantum computers",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-follow-up-timeout",
            13,
            0.72,
            Some(live_preview_observer),
            None,
        )
        .await;

    match previous_timeout {
        Some(value) => std::env::set_var(
            "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
            value,
        ),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS"),
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
            let prompt = decode_chat_test_prompt(input_context);
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
            let prompt = decode_chat_test_prompt(input_context);
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture timeout-then-repair runtime".to_string(),
                model: Some("fixture-timeout-then-repair".to_string()),
                endpoint: Some("fixture://timeout-then-repair".to_string()),
            }
        }
    }

    let previous_timeout =
        std::env::var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS").ok();
    std::env::set_var(
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
        "50",
    );

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
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

    let payload_result =
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
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
            None,
            "candidate-repair-after-timeout",
            21,
            0.72,
            Some(live_preview_observer),
            None,
        )
        .await;

    match previous_timeout {
        Some(value) => std::env::set_var(
            "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
            value,
        ),
        None => std::env::remove_var("AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS"),
    }

    let payload = payload_result.expect("repair should recover after continuation timeout");
    assert!(payload.files[0]
        .body
        .to_ascii_lowercase()
        .ends_with("</html>"));

    let prompt_log = prompts.lock().expect("prompt log");
    assert!(
        prompt_log.len() >= 2,
        "expected at least one follow-up prompt after the interrupted stream"
    );

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
            let prompt = decode_chat_test_prompt(input_context);
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
            let prompt = decode_chat_test_prompt(input_context);
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture whitespace-sensitive interrupted runtime".to_string(),
                model: Some("fixture-whitespace-sensitive".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }
        }
    }

    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();

    let payload =
        super::generation::materialize_chat_artifact_candidate_with_runtime_direct_author_detailed(
            Arc::new(WhitespaceSensitiveInterruptedRuntime),
            None,
            "Quantum computers",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
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
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let partial_document = format!(
        "<!doctype html><html><head><title>Mortgage Calculator</title></head><body><main>{}</main></body></html>",
        "A".repeat(4300)
    );
    let prompt = build_chat_artifact_direct_author_continuation_prompt_for_runtime(
        "Mortgage Calculator",
        "A mortgage calculator where I can adjust rate, term, and down payment",
        &request,
        &brief,
        &[],
        &partial_document,
        "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
        ChatRuntimeProvenanceKind::RealLocalRuntime,
    );
    let prompt_text = serde_json::to_string(&prompt).expect("continuation prompt text");
    assert!(prompt_text.contains(
        "<!doctype html><html><head><title>Mortgage Calculator</title></head><body><main>"
    ));
    assert!(prompt_text.contains(&"A".repeat(256)));
    assert!(!prompt_text.contains("[showing latest streamed output]"));
    assert!(prompt_text.contains("Return only document text"));
    assert!(!prompt_text.contains("Return JSON only"));
}

#[test]
fn direct_author_continuation_prompt_requires_full_document_for_semantic_underbuild() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_quantum_explainer_brief();
    let partial_document = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits.</p><div><button type=\"button\">Basics</button><button type=\"button\">Measurement</button></div></section><section><h2>Basics</h2><p>Qubits can occupy superposition.</p></section><section><h2>Measurement</h2><p>Measurement collapses amplitudes.</p></section></main></body></html>";
    let prompt = build_chat_artifact_direct_author_continuation_prompt_for_runtime(
        "Quantum Explorer",
        "Create an interactive HTML artifact that explains quantum computers",
        &request,
        &brief,
        &[],
        partial_document,
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only surface inert controls.",
        ChatRuntimeProvenanceKind::RealLocalRuntime,
    );
    let prompt_text = serde_json::to_string(&prompt).expect("continuation prompt text");
    assert!(prompt_text.contains(
        "Return one full corrected self-contained HTML document; do not return only a suffix."
    ));
    assert!(prompt_text.contains(
        "Return one complete corrected self-contained HTML document that preserves the strongest authored structure while fixing the invalid interactive behavior."
    ));
    assert!(!prompt_text.contains("Prefer returning only the missing tail when possible."));
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
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema") {
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
                let _ = token_stream;
                self.execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await
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
                    label: "fixture structurally broken direct-author runtime".to_string(),
                    model: Some("fixture-structurally-broken".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
        let candidate = ChatGeneratedArtifactPayload {
            summary: "Quantum Explorer".to_string(),
            notes: vec!["Broken direct-author output".to_string()],
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><button type=\"button\" data-view=\"basics\">Basics</button><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></main></body></html>".to_string(),
            }],
        };

        let payload = super::generation::repair_direct_author_generated_candidate_with_runtime_error(
            Arc::new(StructurallyBrokenDirectAuthorRuntime {
                prompts: prompts.clone(),
            }),
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-1",
            19,
            &candidate,
            "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
            None,
        )
        .await
        .expect("structurally broken direct-author output should be repaired");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));
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
async fn direct_author_repair_accepts_raw_html_without_json_envelope() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct RawHtmlRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for RawHtmlRepairRuntime {
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
                    return Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in raw-html repair runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let _ = token_stream;
                self.execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await
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
                    label: "fixture raw-html repair runtime".to_string(),
                    model: Some("fixture-raw-html-repair".to_string()),
                    endpoint: Some("fixture://raw-html-repair".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
        let candidate = ChatGeneratedArtifactPayload {
            summary: "Quantum Explorer".to_string(),
            notes: vec!["Broken direct-author output".to_string()],
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><button type=\"button\" data-view=\"basics\">Basics</button><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></main></body></html>".to_string(),
            }],
        };

        let payload = super::generation::repair_direct_author_generated_candidate_with_runtime_error(
            Arc::new(RawHtmlRepairRuntime {
                prompts: prompts.clone(),
            }),
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-raw-html-repair",
            41,
            &candidate,
            "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
            None,
        )
        .await
        .expect("raw html repair output should be accepted without a JSON envelope");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));
        assert!(payload.files[0].body.ends_with("</html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Return only document text")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_runtime_repair_accepts_raw_html_with_preamble_as_full_document() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct PreambleHtmlRepairRuntime;

        #[async_trait]
        impl InferenceRuntime for PreambleHtmlRepairRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                if prompt.contains("Repair output schema") {
                    return Ok("Here is the corrected HTML document:\n<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in preamble-html repair runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let _ = token_stream;
                self.execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await
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
                    label: "fixture preamble-html repair runtime".to_string(),
                    model: Some("fixture-preamble-html-repair".to_string()),
                    endpoint: Some("fixture://preamble-html-repair".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let candidate = ChatGeneratedArtifactPayload {
            summary: "Quantum Explorer".to_string(),
            notes: vec!["Broken direct-author output".to_string()],
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits.</p><div><button type=\"button\">Basics</button><button type=\"button\">Measurement</button></div></section><section><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section></main></body></html>".to_string(),
            }],
        };

        let payload = super::generation::repair_direct_author_generated_candidate_with_runtime_error(
            Arc::new(PreambleHtmlRepairRuntime),
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-preamble-html-repair",
            44,
            &candidate,
            "Interactive HTML iframe artifacts must update on-page state or shared detail, not only surface inert controls.",
            None,
        )
        .await
        .expect("raw html repair output with a preamble should still be treated as a full document");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("activate(buttons[0])"));
        assert!(payload.files[0].body.starts_with("<!doctype html>"));
        assert!(payload.files[0].body.ends_with("</html>"));
    })
    .await;
}

#[tokio::test]
async fn direct_author_runtime_repair_trims_raw_html_trailing_fragment_to_renderable_prefix() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct TrailingFragmentRepairRuntime;

        #[async_trait]
        impl InferenceRuntime for TrailingFragmentRepairRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                if prompt.contains("Repair output schema") {
                    return Ok("Here is the corrected HTML document:\n<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits with authored state changes.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body><scr".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in trailing-fragment repair runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let _ = token_stream;
                self.execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await
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
                    label: "fixture trailing-fragment repair runtime".to_string(),
                    model: Some("fixture-trailing-fragment".to_string()),
                    endpoint: Some("fixture://trailing-fragment".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let candidate = ChatGeneratedArtifactPayload {
            summary: "Quantum Explorer".to_string(),
            notes: vec!["Broken direct-author output".to_string()],
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Compare classical bits and qubits.</p><div><button type=\"button\">Basics</button><button type=\"button\">Measurement</button></div></section><section><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section></main></body></html>".to_string(),
            }],
        };

        let payload = super::generation::repair_direct_author_generated_candidate_with_runtime_error(
            Arc::new(TrailingFragmentRepairRuntime),
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-trailing-fragment-repair",
            46,
            &candidate,
            "HTML sectioning regions are empty shells on first paint.",
            None,
        )
        .await
        .expect("repair output with a trailing fragment should be trimmed back to the last renderable HTML prefix");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));
        assert!(!payload.files[0].body.ends_with("<scr"));
    })
    .await;
}

#[tokio::test]
async fn direct_author_semantic_underbuild_skips_continuation_and_repairs_directly() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct SemanticUnderbuildRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for SemanticUnderbuildRepairRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema") {
                    return Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the controls to compare quantum concepts.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before measurement.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in semantic-underbuild repair runtime: {prompt}"
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
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema")
                    || prompt.contains("Continuation output schema")
                {
                    return self
                        .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                        .await;
                }
                let initial = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the controls to compare quantum concepts.</p><div><button type=\"button\">Basics</button><button type=\"button\">Measurement</button><button type=\"button\">Examples</button></div></section><section><h2>Basics</h2><p>Qubits can occupy superposition before measurement.</p></section><section><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Choose a control to inspect the concept.</p></aside></main></body>";
                if let Some(stream) = token_stream {
                    let _ = stream.send(initial.to_string()).await;
                }
                Ok(initial.as_bytes().to_vec())
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
                    label: "fixture semantic-underbuild repair runtime".to_string(),
                    model: Some("fixture-semantic-underbuild".to_string()),
                    endpoint: Some("fixture://semantic-underbuild".to_string()),
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
            Arc::new(SemanticUnderbuildRepairRuntime {
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
            "candidate-semantic-underbuild",
            45,
            0.73,
            None,
            None,
        )
        .await
        .expect("semantic underbuild should jump straight to repair");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));

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
async fn direct_author_missing_controls_skips_continuation_and_repairs_directly() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct MissingControlsRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for MissingControlsRepairRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema") {
                    return Ok("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the controls to compare quantum concepts.</p><div><button type=\"button\" data-view=\"basics\" aria-selected=\"true\" data-detail=\"Basics are selected by default.\">Basics</button><button type=\"button\" data-view=\"measurement\" aria-selected=\"false\" data-detail=\"Measurement collapses amplitudes into observable outcomes.\">Measurement</button><button type=\"button\" data-view=\"examples\" aria-selected=\"false\" data-detail=\"Examples highlight optimization and simulation workloads.\">Examples</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before measurement.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\"examples\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in missing-controls repair runtime: {prompt}"
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
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema")
                    || prompt.contains("Continuation output schema")
                {
                    return self
                        .execute_inference([0u8; 32], input_context, InferenceOptions::default())
                        .await;
                }
                let initial = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Quantum computers can occupy superposition before measurement.</p></section><section><h2>Basics</h2><p>Qubits can represent multiple amplitudes.</p></section><section><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section></main></body>";
                if let Some(stream) = token_stream {
                    let _ = stream.send(initial.to_string()).await;
                }
                Ok(initial.as_bytes().to_vec())
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
                    label: "fixture missing-controls repair runtime".to_string(),
                    model: Some("fixture-missing-controls".to_string()),
                    endpoint: Some("fixture://missing-controls".to_string()),
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
            Arc::new(MissingControlsRepairRuntime {
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
            "candidate-missing-controls",
            47,
            0.74,
            None,
            None,
        )
        .await
        .expect("missing controls should jump straight to repair");

        assert!(payload.files[0].body.contains("data-view-panel=\"examples\""));
        assert!(payload.files[0].body.contains("addEventListener('mouseenter'"));

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
async fn direct_author_repair_accepts_suffix_mode_when_merged_document_validates() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct SuffixModeRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for SuffixModeRepairRuntime {
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
                    return Ok("{\"mode\":\"suffix\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\">Measurement</button></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in suffix-mode repair runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let _ = token_stream;
                self.execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await
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
                    label: "fixture suffix-mode repair runtime".to_string(),
                    model: Some("fixture-suffix-mode-repair".to_string()),
                    endpoint: Some("fixture://suffix-mode-repair".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
        let candidate = ChatGeneratedArtifactPayload {
            summary: "Quantum Explorer".to_string(),
            notes: vec!["Broken direct-author output".to_string()],
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p></section><section><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section></main></body></html>".to_string(),
            }],
        };

        let payload = super::generation::repair_direct_author_generated_candidate_with_runtime_error(
            Arc::new(SuffixModeRepairRuntime {
                prompts: prompts.clone(),
            }),
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-suffix-mode-repair",
            43,
            &candidate,
            "Interactive HTML iframe artifacts must contain real interactive controls or handlers.",
            None,
        )
        .await
        .expect("suffix-mode repair should be accepted when the merged document validates");

        assert!(payload.files[0].body.contains("Measurement is selected."));
        assert!(payload.files[0].body.ends_with("</html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_local_html_repair_stays_within_compact_follow_up_budget() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct LengthSensitiveRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
            repair_prompt_bytes: Arc<Mutex<Vec<usize>>>,
            repair_max_tokens: Arc<Mutex<Vec<u32>>>,
        }

        #[async_trait]
        impl InferenceRuntime for LengthSensitiveRepairRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("Repair output schema") {
                    self.repair_prompt_bytes
                        .lock()
                        .expect("repair prompt byte log")
                        .push(input_context.len());
                    self.repair_max_tokens
                        .lock()
                        .expect("repair max token log")
                        .push(options.max_tokens);
                    if input_context.len() > 3900 || options.max_tokens > 2400 {
                        return Err(VmError::HostError(
                            "LLM_REFUSAL: Empty content (reason: length)".to_string(),
                        ));
                    }
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the toggles to compare classical bits and qubits.</p><div><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\">Measurement</button></div></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main></body></html>\"}".as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming prompt in length-sensitive repair runtime: {prompt}"
                )))
            }

            async fn execute_inference_streaming(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
                token_stream: Option<Sender<String>>,
            ) -> Result<Vec<u8>, VmError> {
                let _ = token_stream;
                self.execute_inference([0u8; 32], input_context, InferenceOptions::default())
                    .await
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
                    label: "fixture length-sensitive repair runtime".to_string(),
                    model: Some("fixture-length-sensitive-repair".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                }
            }
        }

        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
        let repair_prompt_bytes = Arc::new(Mutex::new(Vec::<usize>::new()));
        let repair_max_tokens = Arc::new(Mutex::new(Vec::<u32>::new()));
        let candidate = ChatGeneratedArtifactPayload {
            summary: "Quantum Explorer".to_string(),
            notes: vec!["Broken direct-author output".to_string()],
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Explorer</title><style>body{margin:0;background:#111827;color:#f8fafc;font-family:Georgia,serif;}main{max-width:920px;margin:0 auto;padding:24px;display:grid;gap:18px;}section,aside{background:#172033;border:1px solid #334155;border-radius:18px;padding:18px;}button{border:1px solid #475569;background:#1e293b;color:#f8fafc;border-radius:999px;padding:8px 12px;}</style></head><body><main><section><h1>Quantum Explorer</h1><p>Use the toggles to compare classical bits and qubits.</p><div><button type=\"button\" data-view=\"basics\">Basics</button><button type=\"button\" data-view=\"measurement\">Measurement</button></div></section><section data-view-panel=\"basics\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p><aside><p id=\"detail-copy\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='basics'?'Basics are selected by default.':'Measurement is selected.';}));</script></main></body></html>".to_string(),
            }],
        };

        let payload = super::generation::repair_direct_author_generated_candidate_with_runtime_error(
            Arc::new(LengthSensitiveRepairRuntime {
                prompts: prompts.clone(),
                repair_prompt_bytes: repair_prompt_bytes.clone(),
                repair_max_tokens: repair_max_tokens.clone(),
            }),
            "Quantum Explorer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-compact-repair",
            23,
            &candidate,
            "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
            None,
        )
        .await
        .expect("compact local repair should recover instead of triggering a length refusal");

        assert!(payload.files[0].body.contains("Measurement is selected."));
        assert!(payload.files[0].body.ends_with("</html>"));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));

        let prompt_bytes = repair_prompt_bytes.lock().expect("repair prompt byte log");
        assert_eq!(prompt_bytes.len(), 1);
        assert!(prompt_bytes[0] <= 3900);

        let max_tokens = repair_max_tokens.lock().expect("repair max token log");
        assert_eq!(max_tokens.len(), 1);
        assert_eq!(max_tokens[0], 2400);
    })
    .await;
}

#[tokio::test]
async fn direct_author_local_document_html_skips_artifact_validation_roundtrip() {
    #[derive(Debug, Clone)]
    struct DirectAuthorAcceptanceRuntime {
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        provenance: ChatRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorAcceptanceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
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
                        "unexpected Chat prompt in direct-author acceptance test runtime: {prompt}"
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            self.provenance.clone()
        }
    }

    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let evaluator = ChatPassingRenderEvaluator;
        let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorAcceptanceRuntime {
            role: "production",
            calls: calls.clone(),
            provenance: ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture direct-author producer".to_string(),
                model: Some("fixture-qwen-9b".to_string()),
                endpoint: Some("fixture://producer".to_string()),
            },
        });
        let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(DirectAuthorAcceptanceRuntime {
            role: "acceptance",
            calls: calls.clone(),
            provenance: ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "fixture direct-author acceptance".to_string(),
                model: Some("fixture-qwen-8b".to_string()),
                endpoint: Some("fixture://acceptance".to_string()),
            },
        });
        let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
        let title = "Quantum computing explainer";
        let intent = "Create an HTML file that explains quantum computers.";
        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
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
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::DirectAuthor,
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
        assert_eq!(
            bundle.validation.classification,
            ChatArtifactValidationStatus::Pass
        );
        assert_eq!(bundle.ux_lifecycle, ChatArtifactUxLifecycle::Validated);
        assert!(
            bundle
                .winner
                .files
                .iter()
                .any(|artifact| artifact.path == "index.html")
        );
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
        provenance: ChatRuntimeProvenance,
    }

    #[async_trait]
    impl InferenceRuntime for DirectAuthorRuntimeRepairRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
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
                        "unexpected Chat prompt in direct-author runtime repair test: {prompt}"
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

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            self.provenance.clone()
        }
    }

    #[derive(Default)]
    struct DirectAuthorRuntimeErrorEvaluator;

    #[async_trait]
    impl ChatArtifactRenderEvaluator for DirectAuthorRuntimeErrorEvaluator {
        async fn evaluate_candidate_render(
            &self,
            _request: &ChatOutcomeArtifactRequest,
            _brief: &ChatArtifactBrief,
            _blueprint: Option<&ChatArtifactBlueprint>,
            _artifact_ir: Option<&ChatArtifactIR>,
            _edit_intent: Option<&ChatArtifactEditIntent>,
            candidate: &ChatGeneratedArtifactPayload,
        ) -> Result<Option<ChatArtifactRenderEvaluation>, String> {
            let repaired = candidate
                .files
                .iter()
                .find(|file| file.path == "index.html")
                .map(|file| file.body.contains("data-repaired=\"runtime-error\""))
                .unwrap_or(false);
            if repaired {
                return Ok(Some(chat_test_render_evaluation(
                    20,
                    true,
                    Vec::new(),
                    vec![
                        chat_test_render_capture(
                            ChatArtifactRenderCaptureViewport::Desktop,
                            84,
                            620,
                            4,
                        ),
                        chat_test_render_capture(
                            ChatArtifactRenderCaptureViewport::Mobile,
                            72,
                            540,
                            4,
                        ),
                    ],
                )));
            }

            Ok(Some(ChatArtifactRenderEvaluation {
                supported: true,
                first_paint_captured: true,
                interaction_capture_attempted: true,
                captures: vec![
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Desktop,
                        80,
                        580,
                        4,
                    ),
                    chat_test_render_capture(ChatArtifactRenderCaptureViewport::Mobile, 68, 500, 4),
                ],
                layout_density_score: 3,
                spacing_alignment_score: 3,
                typography_contrast_score: 4,
                visual_hierarchy_score: 3,
                blueprint_consistency_score: 3,
                overall_score: 12,
                findings: vec![ChatArtifactRenderFinding {
                    code: "runtime_boot_clean".to_string(),
                    severity: ChatArtifactRenderFindingSeverity::Blocked,
                    summary: "TypeError: stage.forEach is not a function".to_string(),
                }],
                acceptance_obligations: vec![ChatArtifactAcceptanceObligation {
                    obligation_id: "runtime_boot_clean".to_string(),
                    family: "boot_truth".to_string(),
                    required: true,
                    status: ChatArtifactAcceptanceObligationStatus::Failed,
                    summary:
                        "No runtime witness errors were observed while validating the artifact."
                            .to_string(),
                    detail: Some("TypeError: stage.forEach is not a function".to_string()),
                    witness_ids: vec!["witness-1".to_string()],
                }],
                execution_witnesses: vec![ChatArtifactExecutionWitness {
                    witness_id: "witness-1".to_string(),
                    obligation_id: Some("controls_execute_cleanly".to_string()),
                    action_kind: "click".to_string(),
                    status: ChatArtifactExecutionWitnessStatus::Failed,
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
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture direct-author producer".to_string(),
                    model: Some("fixture-qwen-9b".to_string()),
                    endpoint: Some("fixture://producer".to_string()),
                },
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(DirectAuthorRuntimeRepairRuntime {
                role: "acceptance",
                calls: calls.clone(),
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "fixture direct-author acceptance".to_string(),
                    model: Some("fixture-qwen-8b".to_string()),
                    endpoint: Some("fixture://acceptance".to_string()),
                },
            });
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let title = "Quantum computing explainer";
        let intent = "Create an interactive HTML artifact that explains quantum computers.";
        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
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
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                title,
                intent,
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::DirectAuthor,
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
            ChatArtifactValidationStatus::Pass
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
