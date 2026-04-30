#[tokio::test]
async fn direct_author_modal_first_dead_controls_deterministic_repair_avoids_repair() {
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
        .expect("dead controls should be repaired locally before repair is needed");

        assert!(payload.files[0].body.contains("addEventListener"));
        assert!(payload.files[0]
            .body
            .contains("querySelectorAll('[data-view-panel]')"));
        assert!(payload.files[0]
            .body
            .contains("data-ioi-deterministic-repair=\"view-switch\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(!prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_stage_navigation_deterministic_repair_avoids_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct StageNavigationDeterministicRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for StageNavigationDeterministicRepairRuntime {
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
                    "unexpected non-streaming prompt in stage navigation deterministic repair runtime: {prompt}"
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
                    label: "fixture stage navigation deterministic repair runtime".to_string(),
                    model: Some("fixture-stage-navigation-deterministic-repair".to_string()),
                    endpoint: Some("fixture://stage-navigation-deterministic-repair".to_string()),
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
            Arc::new(StageNavigationDeterministicRepairRuntime {
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
            "candidate-stage-deterministic-repair",
            41,
            0.72,
            None,
            None,
        )
        .await
        .expect("stage navigation should be repaired locally before repair is needed");

        assert!(payload.files[0].body.contains("data-ioi-deterministic-repair=\"stage-nav\""));
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
async fn direct_author_stage_navigation_deterministic_repair_synthesizes_missing_controls() {
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
        .expect("stage navigation deterministic_repair should synthesize missing controls locally");

        assert!(payload.files[0].body.contains("data-ioi-deterministic-repair=\"stage-nav\""));
        assert!(payload.files[0]
            .body
            .contains("data-ioi-deterministic-repair-target=\"stage-controls\""));
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
async fn direct_author_form_response_deterministic_repair_falls_through_to_repair_when_first_paint_underbuilt(
) {
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
            .contains("data-ioi-deterministic-repair=\"form-response\""));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(prompt_log
            .iter()
            .any(|prompt| prompt.contains("Repair output schema")));
    })
    .await;
}

#[tokio::test]
async fn direct_author_form_response_deterministic_repair_keeps_single_goal_slider_without_repair()
{
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
        .expect("single-goal slider should be repaired locally without repair");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-deterministic-repair=\"form-response\""));

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
        struct MismatchedNestingDeterministicRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for MismatchedNestingDeterministicRepairRuntime {
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
                    "unexpected non-streaming prompt in mismatched nesting deterministic repair runtime: {prompt}"
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
                    label: "fixture mismatched nesting deterministic repair runtime".to_string(),
                    model: Some("fixture-mismatched-nesting-deterministic-repair".to_string()),
                    endpoint: Some("fixture://mismatched-nesting-deterministic-repair".to_string()),
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
            Arc::new(MismatchedNestingDeterministicRepairRuntime {
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
            "candidate-mismatched-nesting-deterministic-repair",
            59,
            0.72,
            None,
            None,
        )
        .await
        .expect("mismatched nesting should be repaired locally before continuation or repair");

        assert!(payload.files[0].body.contains("data-ioi-deterministic-repair=\"button-response\""));
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
fn local_html_interaction_truth_repair_promotes_scroll_nav_buttons_into_stateful_controls() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let raw = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Quantum Computers Explained</title></head><body><header><nav><button onclick=\"document.getElementById('intro').scrollIntoView({behavior:'smooth'})\">Introduction</button><button onclick=\"document.getElementById('scenario').scrollIntoView({behavior:'smooth'})\">Scenario Explorer</button></nav></header><main><section id=\"intro\"><h2>Intro</h2><p>Quantum computers use qubits.</p></section><section id=\"scenario\"><h2>Scenario Explorer</h2><div class=\"status\" id=\"scenario-status\">Initializing...</div></section></main></body></html>";
    let (repaired, strategy) = super::generation::try_local_html_interaction_truth_repair_document(
        &request,
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        raw,
        "Surfaced controls executed without runtime errors or no-op behavior. successfulWitnesses=0 failedWitnesses=4",
    )
    .expect("scroll-nav interaction truth deterministic_repair should trigger");

    assert_eq!(strategy, "scroll_nav");
    assert!(repaired.contains("data-ioi-deterministic-repair=\"scroll-nav\""));
    assert!(repaired.contains("scenario-status"));
    assert!(repaired.contains("aria-pressed"));
    assert!(repaired.contains("setAttribute('role','status')"));
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
async fn direct_author_broken_inline_handlers_are_stripped_before_deterministic_repair() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct BrokenInlineHandlersDeterministicRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for BrokenInlineHandlersDeterministicRepairRuntime {
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
                    "unexpected non-streaming prompt in broken inline handler deterministic_repair runtime: {prompt}"
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
                    label: "fixture broken inline handlers deterministic repair runtime".to_string(),
                    model: Some("fixture-broken-inline-handlers-deterministic-repair".to_string()),
                    endpoint: Some("fixture://broken-inline-handlers-deterministic-repair".to_string()),
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
            Arc::new(BrokenInlineHandlersDeterministicRepairRuntime {
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
            "candidate-inline-handler-deterministic-repair",
            53,
            0.72,
            None,
            None,
        )
        .await
        .expect("broken inline handlers should be stripped before deterministic repair");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-deterministic-repair=\"button-response\""));
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
async fn direct_author_generic_button_deterministic_repair_injects_fallback_detail_region() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct FallbackDetailRegionDeterministicRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for FallbackDetailRegionDeterministicRepairRuntime {
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
                    "unexpected non-streaming prompt in fallback detail region deterministic_repair runtime: {prompt}"
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
                    label: "fixture fallback detail region deterministic repair runtime".to_string(),
                    model: Some("fixture-fallback-detail-region-deterministic-repair".to_string()),
                    endpoint: Some("fixture://fallback-detail-region-deterministic-repair".to_string()),
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
            Arc::new(FallbackDetailRegionDeterministicRepairRuntime {
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
            "candidate-fallback-detail-region-deterministic-repair",
            67,
            0.72,
            None,
            None,
        )
        .await
        .expect("inert button controls should gain a fallback detail region before repair");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-deterministic-repair-target=\"detail-copy\""));
        assert!(payload.files[0]
            .body
            .contains("data-ioi-deterministic-repair=\"button-response\""));
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
async fn direct_author_form_control_deterministic_repair_wires_inert_range_inputs() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct FormControlDeterministicRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for FormControlDeterministicRepairRuntime {
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
                    "unexpected non-streaming prompt in form control deterministic_repair runtime: {prompt}"
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
                    label: "fixture form control deterministic repair runtime".to_string(),
                    model: Some("fixture-form-control-deterministic-repair".to_string()),
                    endpoint: Some("fixture://form-control-deterministic-repair".to_string()),
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
            Arc::new(FormControlDeterministicRepairRuntime {
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
            "candidate-form-control-deterministic-repair",
            61,
            0.72,
            None,
            None,
        )
        .await
        .expect("inert range inputs should be repaired locally before repair is needed");

        assert!(payload.files[0].body.contains("data-ioi-deterministic-repair=\"form-response\""));
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
async fn direct_author_deterministic_repair_strips_broken_inline_script_blocks() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct BrokenInlineScriptDeterministicRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for BrokenInlineScriptDeterministicRepairRuntime {
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
                    "unexpected non-streaming prompt in broken inline script deterministic_repair runtime: {prompt}"
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
                    label: "fixture broken inline script deterministic repair runtime".to_string(),
                    model: Some("fixture-broken-inline-script-deterministic-repair".to_string()),
                    endpoint: Some("fixture://broken-inline-script-deterministic-repair".to_string()),
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
            Arc::new(BrokenInlineScriptDeterministicRepairRuntime {
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
            "candidate-broken-inline-script-deterministic-repair",
            71,
            0.72,
            None,
            None,
        )
        .await
        .expect("broken inline scripts should be stripped before deterministic repair");

        assert!(payload.files[0]
            .body
            .contains("data-ioi-deterministic-repair=\"button-response\""));
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
        struct StructuralTrimDeterministicRepairRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for StructuralTrimDeterministicRepairRuntime {
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
                    "unexpected non-streaming prompt in structural trim deterministic repair runtime: {prompt}"
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
                    label: "fixture structural trim deterministic repair runtime".to_string(),
                    model: Some("fixture-structural-trim-deterministic-repair".to_string()),
                    endpoint: Some("fixture://structural-trim-deterministic-repair".to_string()),
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
            Arc::new(StructuralTrimDeterministicRepairRuntime {
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
            "candidate-structural-trim-deterministic-repair",
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

