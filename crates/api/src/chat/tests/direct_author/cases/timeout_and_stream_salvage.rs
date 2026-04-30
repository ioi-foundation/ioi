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
async fn direct_author_incomplete_raw_html_remediates_before_terminal_failure() {
    with_modal_first_html_env_async(|| async {
        #[derive(Debug, Clone)]
        struct IncompleteRawHtmlRuntime {
            prompts: Arc<Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl InferenceRuntime for IncompleteRawHtmlRuntime {
            async fn execute_inference(
                &self,
                _model_hash: [u8; 32],
                input_context: &[u8],
                _options: InferenceOptions,
            ) -> Result<Vec<u8>, VmError> {
                let prompt = decode_chat_test_prompt(input_context);
                self.prompts.lock().expect("prompt log").push(prompt.clone());
                if prompt.contains("typed direct document continuation author")
                    || prompt.contains("Continuation output schema")
                {
                    return Ok("</script></main></body></html>".as_bytes().to_vec());
                }
                if prompt.contains("typed direct document repair author")
                    || prompt.contains("Repair output schema")
                {
                    let repaired = "<!doctype html><html><body><main><section><h1>Mortgage estimator</h1><p>Adjust loan amount, rate, and term to inspect the monthly payment.</p><label for=\"loan\">Loan amount</label><input id=\"loan\" type=\"range\" min=\"200000\" max=\"900000\" value=\"550000\"></section><section><h2>Payment summary</h2><p id=\"monthly-payment\">$3,154</p><p>The default loan amount is $550,000 with an adjustable scenario control.</p></section><aside><h2>Scenario detail</h2><p id=\"detail-copy\">Loan amount is $550,000 by default.</p></aside><script>const loan=document.getElementById('loan');const detail=document.getElementById('detail-copy');loan.addEventListener('input',()=>{detail.textContent='Loan amount changed to $'+Number(loan.value).toLocaleString();});</script></main></body></html>";
                    return Ok(repaired.as_bytes().to_vec());
                }
                Err(VmError::HostError(format!(
                    "unexpected non-streaming direct-author prompt: {prompt}"
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
                let partial = "<!doctype html><html><body><main><section><h1>Mortgage estimator</h1><p>Adjust loan amount, rate, and term to inspect the monthly payment.</p><label for=\"loan\">Loan amount</label><input id=\"loan\" type=\"range\" min=\"200000\" max=\"900000\" value=\"550000\"></section><section><h2>Payment summary</h2><p id=\"monthly-payment\">$3,154</p><p>The default loan amount is $550,000 with an adjustable scenario control.</p></section><aside><h2>Scenario detail</h2><p id=\"detail-copy\">Loan amount is $550,000 by default.</p></aside><script>const loan=document.getElementById('loan');const detail=document.getElementById('detail-copy');loan.addEventListener('input',()=>{detail.textContent='Loan amount changed to $'+Number(loan.value).toLocaleString();});";
                if let Some(sender) = token_stream.as_ref() {
                    sender
                        .send(partial.to_string())
                        .await
                        .map_err(|error| VmError::HostError(format!("stream send failed: {error}")))?;
                }
                Ok(partial.as_bytes().to_vec())
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
                    label: "fixture incomplete raw html runtime".to_string(),
                    model: Some("fixture-incomplete-raw-html".to_string()),
                    endpoint: Some("fixture://incomplete-raw-html".to_string()),
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
            Arc::new(IncompleteRawHtmlRuntime {
                prompts: prompts.clone(),
            }),
            None,
            "Mortgage estimator",
            "For the calculator you just made, update the default loan amount to $550,000.",
            &request,
            &brief,
            &[],
            None,
            None,
            "candidate-incomplete-raw-html",
            37,
            0.72,
            None,
            None,
        )
        .await
        .expect("incomplete raw HTML should create a typed remediation attempt before failing terminally");

        let html = payload.files[0].body.as_str();
        assert!(html.ends_with("</script></main></body></html>"));
        assert!(html.contains("550000"));
        assert!(html.contains("Loan amount is $550,000 by default."));

        let prompt_log = prompts.lock().expect("prompt log");
        assert!(
            prompt_log.iter().any(|prompt| prompt
                .contains("typed direct document continuation author")
                || prompt.contains("typed direct document repair author")),
            "raw structural failure should route through typed remediation instead of terminalizing"
        );
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

