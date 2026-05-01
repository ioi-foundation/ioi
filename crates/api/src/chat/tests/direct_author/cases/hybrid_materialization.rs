#[tokio::test]
async fn local_html_hybrid_raw_document_timeout_is_bounded() {
    super::generation::with_direct_author_timeout_overrides_async(
        Some(Duration::from_millis(50)),
        None,
        None,
        || async {
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

    let error =
        result.expect_err("hybrid local html materialization should time out instead of hanging");
    assert!(error.message.contains(
        "Chat direct-author artifact inference failed: Host function error: Chat direct-author artifact inference timed out"
    ));
        },
    )
    .await;
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
        &[2200]
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
