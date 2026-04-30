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
            detail: Some(
                "The deterministic_repair script updated the shared detail panel.".to_string(),
            ),
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

