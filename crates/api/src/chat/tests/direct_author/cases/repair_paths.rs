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
                    return Ok("{\"mode\":\"full_document\",\"content\":\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Quantum Explorer</title></head><body><main><section><h1>Quantum Explorer</h1><p>Use the tabs to compare classical bits and qubits.</p><button type=\\\"button\\\" data-view=\\\"basics\\\" aria-selected=\\\"true\\\" data-detail=\\\"Basics are selected by default.\\\">Basics</button><button type=\\\"button\\\" data-view=\\\"measurement\\\" aria-selected=\\\"false\\\" data-detail=\\\"Measurement collapses amplitudes into observable outcomes.\\\">Measurement</button><button type=\\\"button\\\" data-view=\\\"examples\\\" aria-selected=\\\"false\\\" data-detail=\\\"Examples highlight optimization and simulation workloads.\\\">Examples</button></section><section data-view-panel=\\\"basics\\\"><h2>Basics</h2><p>Qubits can occupy superposition before they are measured.</p></section><section data-view-panel=\\\"measurement\\\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><section data-view-panel=\\\"examples\\\" hidden><h2>Examples</h2><p>Optimization and simulation are common early workloads.</p></section><aside><p id=\\\"detail-copy\\\">Basics are selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const inspect=(button)=>{detail.textContent=button.getAttribute('data-detail')||`${button.textContent.trim()} selected.`;};const activate=(button)=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});inspect(button);};buttons.forEach((button)=>{button.addEventListener('click',()=>activate(button));button.addEventListener('focus',()=>inspect(button));button.addEventListener('mouseenter',()=>inspect(button));});activate(buttons[0]);</script></main></body></html>\"}".as_bytes().to_vec());
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
