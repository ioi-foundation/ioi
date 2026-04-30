#[tokio::test]
async fn local_runtime_download_card_materialization_falls_back_after_local_refusal() {
    struct EmptyDownloadRuntime;

    #[async_trait]
    impl InferenceRuntime for EmptyDownloadRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError(
                "LLM_REFUSAL: Empty content (reason: length)".to_string(),
            ))
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "local".to_string(),
                model: Some("local-test".to_string()),
                endpoint: Some("local".to_string()),
            }
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    let request = request_for(
        ChatArtifactClass::DownloadableFile,
        ChatRendererKind::DownloadCard,
    );
    let brief = ChatArtifactBrief {
        audience: "finance team".to_string(),
        job_to_be_done: "prepare a budget spreadsheet".to_string(),
        subject_domain: "budget spreadsheet".to_string(),
        artifact_thesis: "Create a budget spreadsheet with formulas and a summary chart."
            .to_string(),
        required_concepts: vec![
            "income categories".to_string(),
            "expense categories".to_string(),
            "summary chart".to_string(),
        ],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: Vec::new(),
        factual_anchors: vec![
            "SUM formulas".to_string(),
            "conditional formatting".to_string(),
        ],
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };

    let payload = materialize_chat_artifact_candidate_with_runtime(
        Arc::new(EmptyDownloadRuntime),
        "Budget spreadsheet",
        "Create a budget spreadsheet with income and expense categories, monthly columns, SUM formulas for totals, conditional formatting for overages, and a summary chart",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        1,
        0.0,
    )
    .await
    .expect("download-card materialization should fall back to a deterministic bundle");

    assert!(payload
        .files
        .iter()
        .any(|file| file.path.ends_with(".xlsx")));
    assert!(payload.files.iter().any(|file| file.path == "README.md"));
}

#[tokio::test]
async fn local_runtime_bundle_manifest_materialization_falls_back_after_non_json_output() {
    struct PlaintextBundleRuntime;

    #[async_trait]
    impl InferenceRuntime for PlaintextBundleRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(b"release artifact summary without json".to_vec())
        }

        fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
            ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                label: "local".to_string(),
                model: Some("local-test".to_string()),
                endpoint: Some("local".to_string()),
            }
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    let request = request_for(
        ChatArtifactClass::ReportBundle,
        ChatRendererKind::BundleManifest,
    );
    let brief = ChatArtifactBrief {
        audience: "release team".to_string(),
        job_to_be_done: "ship a concise release artifact".to_string(),
        subject_domain: "release operations".to_string(),
        artifact_thesis: "Summarize release state with supporting notes.".to_string(),
        required_concepts: vec!["status".to_string(), "risks".to_string()],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: Vec::new(),
        factual_anchors: vec!["release checklist".to_string()],
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };

    let payload = materialize_chat_artifact_candidate_with_runtime(
        Arc::new(PlaintextBundleRuntime),
        "Release artifact",
        "Create a release artifact",
        &request,
        &brief,
        None,
        None,
        "candidate-1",
        1,
        0.0,
    )
    .await
    .expect("bundle-manifest materialization should fall back to a deterministic bundle");

    assert!(payload
        .files
        .iter()
        .any(|file| file.path == "bundle-manifest.json"));
    assert!(payload
        .files
        .iter()
        .any(|file| file.path == "artifact-summary.md"));
    assert!(payload.files.iter().any(|file| file.path == "README.md"));
    validate_generated_artifact_payload(&payload, &request)
        .expect("fallback bundle payload should satisfy the bundle-manifest contract");
}

#[test]
fn accepts_html_payloads_with_negated_placeholder_wording_and_no_comments() {
    let payload = ChatGeneratedArtifactPayload {
            summary: "Prepared HTML artifact".to_string(),
            notes: Vec::new(),
            files: vec![ChatGeneratedArtifactFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>No placeholders or TODOs appear in this launch brief; the page starts with real copy and evidence.</p><div class=\"control-bar\"><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"signals\" aria-controls=\"signals-panel\">Signals</button></div></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Adoption view</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Adoption by workflow\"><rect x=\"20\" y=\"44\" width=\"40\" height=\"56\" data-detail=\"Drafting copilots lead adoption\" tabindex=\"0\"></rect><rect x=\"88\" y=\"30\" width=\"40\" height=\"70\" data-detail=\"Research copilots show the strongest trust lift\" tabindex=\"0\"></rect><text x=\"20\" y=\"114\">Drafting</text><text x=\"88\" y=\"114\">Research</text></svg></article></section><section id=\"signals-panel\" data-view-panel=\"signals\" hidden><article><h2>Signal rail</h2><ul><li>Fact-check coverage rose across launch week.</li><li>Editorial confidence improved after revisions.</li><li>Operator guidance stayed visible on first paint.</li></ul></article></section><aside id=\"detail-panel\"><h2>Shared detail</h2><p id=\"detail-copy\">Drafting copilots lead adoption by default.</p></aside><footer><p>Use the control bar to compare the launch evidence and update the shared detail panel.</p></footer></main><script>const buttons=Array.from(document.querySelectorAll('[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');const marks=Array.from(document.querySelectorAll('[data-detail]'));buttons.forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{const active=panel.dataset.viewPanel===button.dataset.view;panel.hidden=!active;});}));marks.forEach((mark)=>{const syncDetail=()=>{detail.textContent=mark.dataset.detail||'';};mark.addEventListener('mouseenter',syncDetail);mark.addEventListener('focus',syncDetail);});</script></body></html>".to_string(),
            }],
        };

    validate_generated_artifact_payload(
        &payload,
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
    )
    .expect("negated placeholder wording without comments should stay valid");
}

#[test]
fn parse_and_validate_preserves_authored_controls_without_injecting_disclosure() {
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout artifact",
            "notes": ["authored inline response interaction"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><button id=\"proof-button\" type=\"button\">Show proof</button></section><article><h2>Channel evidence</h2><ul><li>Retail adoption 48%</li><li>Subscription adoption 36%</li></ul></article><aside aria-live=\"polite\"><p id=\"proof-copy\">Retail adoption is leading the launch.</p></aside><footer><p>Operators can inspect the rollout plan inline.</p></footer><script>const proof=document.getElementById('proof-copy');document.getElementById('proof-button').addEventListener('click',()=>{proof.textContent='Subscription adoption accelerated during week two.';});</script></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
    )
    .expect("authored inline response HTML should remain valid without disclosure injection");

    let html = &payload.files[0].body;
    assert!(!html.to_ascii_lowercase().contains("alert("));
    assert!(html.contains("<button"));
    assert!(!html.contains("data-chat-interaction=\"true\""));
}

#[test]
fn parse_and_validate_rejects_static_interactive_html_without_real_controls() {
    let raw = serde_json::json!({
            "summary": "Instacart rollout artifact",
            "notes": ["static html draft"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Instacart MCP rollout</h1><p>Launch sequencing and channel metrics are visible.</p></section><article><p>Adoption by channel is summarized inline.</p></article><footer><p>Operators can review readiness.</p></footer></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
    );

    let error = payload.expect_err(
        "static interactive HTML should be rejected instead of gaining a synthetic disclosure",
    );
    assert!(error.contains("must contain real interactive controls or handlers"));
}

#[test]
fn validate_generated_html_accepts_data_view_controls_mapped_to_panel_ids() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "AI tools editors".to_string(),
        job_to_be_done: "review the launch evidence".to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "show the launch evidence clearly".to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "interactive HTML".to_string(),
        ],
        required_interactions: vec![
            "click to explore AI tools".to_string(),
            "hover to inspect editorial highlights".to_string(),
        ],
        visual_tone: vec!["modern".to_string()],
        factual_anchors: vec!["AI tools editorial launch page".to_string()],
        style_directives: vec!["responsive design".to_string()],
        reference_hints: vec!["HTML iframe integration".to_string()],
        query_profile: Some(ChatArtifactQueryProfile {
            content_goals: Vec::new(),
            interaction_goals: vec![
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::StateSwitch,
                    "Switch between authored evidence views.",
                ),
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::DetailInspect,
                    "Inspect focused editorial highlights in a visible response region.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Show the primary AI tools evidence view.",
                ),
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::ComparisonSurface,
                    "Provide a comparison evidence view for launch planning.",
                ),
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::DetailSurface,
                    "Keep a detail surface visible during interaction.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::SemanticStructure,
                    "Use semantic sections for first-paint structure.",
                ),
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Keep authored evidence visible on first paint.",
                ),
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a populated response region visible on first paint.",
                ),
            ],
        }),
    };
    let raw = serde_json::json!({
        "summary": "AI tools editorial launch",
        "notes": ["data-view buttons map directly to panel ids"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Switch between the evidence views.</p><button data-view=\"tools\">AI Tools</button><button data-view=\"comparison\">Tool Comparison</button></section><section id=\"tools\"><article><h2>AI tools</h2><ul><li tabindex=\"0\" data-detail=\"Content generator adoption grew 22% week over week.\">Content generator adoption grew 22% week over week.</li><li tabindex=\"0\" data-detail=\"Grammar checker retention held at 91% across pilot accounts.\">Grammar checker retention held at 91% across pilot accounts.</li><li tabindex=\"0\" data-detail=\"Fact checker review time dropped to 6 minutes per story.\">Fact checker review time dropped to 6 minutes per story.</li></ul></article></section><section id=\"comparison\" hidden><article><h2>Comparison</h2><dl><dt>Editors</dt><dd>Saved 14 minutes per draft on average.</dd><dt>Publishers</dt><dd>Improved throughput by 11% across launch week.</dd><dt>Reviewers</dt><dd>Reduced factual follow-up loops by 3 per story.</dd></dl></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">AI tools is selected by default.</p></aside><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('#tools, #comparison');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.id!==button.dataset.view;});detail.textContent=button.textContent;}));document.querySelectorAll('[data-detail]').forEach((mark)=>{mark.addEventListener('mouseenter',()=>{detail.textContent=mark.dataset.detail;});mark.addEventListener('focus',()=>{detail.textContent=mark.dataset.detail;});});</script></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("data-view controls should normalize into mapped panels");
    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("data-view to id panel mapping should satisfy visible mapped panel validation");

    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(html.contains("data-view=\"tools\""));
    assert!(html.contains("id=\"tools\""));
    assert!(html.contains("id=\"detail-copy\""));
}

#[test]
fn ensure_minimum_html_sectioning_elements_groups_consecutive_controls_and_marks() {
    let html = "<!doctype html><html><body><main><header><h1>AI Tools Editorial Launch</h1><p>Explore the future of AI tools with interactive features and demos.</p></header><button data-view=\"overview\">Overview</button><button data-view=\"features\">Features</button><button data-view=\"demos\">Demos</button><div class=\"evidence\" data-view-panel=\"overview\"><h3>Overview</h3><p>Overview evidence stays visible on first paint.</p></div><div class=\"evidence\" data-view-panel=\"features\" hidden><h3>Features</h3><ul><li>Real-time content generation</li><li>Collaborative editing tools</li></ul></div><h3>Demos</h3><p>Hover or click the following to preview tool demos:</p><div class=\"data-detail\" data-detail=\"demo1\">Demo 1: Content Generation</div><div class=\"data-detail\" data-detail=\"demo2\">Demo 2: Analytics Dashboard</div><div class=\"data-detail\" data-detail=\"demo3\">Demo 3: Collaborative Editing</div><div class=\"shared-detail\"><h4>Shared Detail</h4><p>Default detail copy stays visible.</p></div></main></body></html>";

    let normalized = ensure_minimum_html_sectioning_elements(html);
    let lower = normalized.to_ascii_lowercase();

    assert!(count_html_sectioning_elements(&lower) >= 3);
    assert!(!lower.contains(
        "</button></section><section data-chat-normalized=\"true\"><button data-view=\"features\""
    ));
    assert!(!lower.contains(
        "</p></section><section data-chat-normalized=\"true\"><div class=\"data-detail\" data-detail=\"demo1\">"
    ));
}

#[test]
fn renderer_contract_allows_near_pass_html_after_normalization_repairs() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "AI tools editors and publishers".to_string(),
        job_to_be_done: "launch an AI tools editorial with an interactive HTML artifact"
            .to_string(),
        subject_domain: "AI tools editorial launch".to_string(),
        artifact_thesis: "an interactive HTML artifact that showcases AI tools for editorial use"
            .to_string(),
        required_concepts: vec![
            "AI tools".to_string(),
            "editorial launch".to_string(),
            "interactive HTML".to_string(),
        ],
        required_interactions: vec![
            "click to explore AI tools".to_string(),
            "hover to view tool features".to_string(),
        ],
        visual_tone: vec![
            "modern".to_string(),
            "clean".to_string(),
            "professional".to_string(),
        ],
        factual_anchors: vec!["AI tools editorial launch page".to_string()],
        style_directives: vec![
            "responsive design".to_string(),
            "user-friendly interface".to_string(),
        ],
        reference_hints: vec!["HTML iframe integration".to_string()],
        query_profile: None,
    };
    let payload = parse_and_validate_generated_artifact_payload(
        include_str!("../../../test_fixtures/qwen3_editorial_trace8_near_pass.html"),
        &request,
    )
    .expect("fixture should parse and normalize");

    validate_generated_artifact_payload_against_brief(&payload, &request, &brief)
        .expect("fixture should stay above the first-paint contract");

    let validation = ChatArtifactValidationResult {
        classification: ChatArtifactValidationStatus::Pass,
        request_faithfulness: 5,
        concept_coverage: 5,
        interaction_relevance: 4,
        layout_coherence: 4,
        visual_hierarchy: 4,
        completeness: 4,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: true,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        score_total: 30,
        proof_kind: "test_fixture".to_string(),
        primary_view_cleared: true,
        validated_paths: vec!["index.html".to_string()],
        issue_codes: vec!["first-paint evidence density could be higher".to_string()],
        issue_classes: vec!["first-paint evidence density could be higher".to_string()],
        repair_hints: vec!["add more populated evidence surfaces".to_string()],
        strengths: vec![
            "interactive control bar with active state styling".to_string(),
            "responsive design".to_string(),
        ],
        blocked_reasons: Vec::new(),
        file_findings: Vec::new(),
        aesthetic_verdict: "Clean and modern visual tone.".to_string(),
        interaction_verdict: "Interaction contract is satisfied.".to_string(),
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some("accept".to_string()),
        strongest_contradiction: None,
        summary: "The fixture clears the renderer contract.".to_string(),
        rationale: "Complies with the interaction contract and stays request-faithful.".to_string(),
    };

    let result = enforce_renderer_validation_contract(&request, &brief, &payload, validation);

    assert_eq!(result.classification, ChatArtifactValidationStatus::Pass);
    assert!(!result.trivial_shell_detected);
    assert!(result.blocked_reasons.is_empty());
    assert_eq!(result.strongest_contradiction, None);
}

#[test]
fn enrich_generated_svg_payload_adds_brief_grounded_title_and_desc() {
    let mut payload = ChatGeneratedArtifactPayload {
            summary: "Prepared SVG artifact".to_string(),
            notes: Vec::new(),
            files: vec![ChatGeneratedArtifactFile {
                path: "hero-concept.svg".to_string(),
                mime: "image/svg+xml".to_string(),
                role: ChatArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: "<svg width='1200' height='630' viewBox='0 0 1200 630' xmlns='http://www.w3.org/2000/svg'><text x='80' y='120'>AI</text><text x='80' y='220'>Tools</text></svg>".to_string(),
            }],
        };
    let brief = ChatArtifactBrief {
            audience: "AI tools brand stakeholders".to_string(),
            job_to_be_done: "Create a shareable hero concept.".to_string(),
            subject_domain: "AI technology and software solutions".to_string(),
            artifact_thesis: "Design a visually compelling SVG hero concept that encapsulates the essence of AI tools brand storytelling.".to_string(),
            required_concepts: vec!["AI".to_string(), "tools".to_string(), "brand".to_string()],
            required_interactions: Vec::new(),
            visual_tone: vec!["modern".to_string()],
            factual_anchors: vec!["automation".to_string()],
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
            query_profile: None,
        };

    enrich_generated_artifact_payload(
        &mut payload,
        &request_for(ChatArtifactClass::Visual, ChatRendererKind::Svg),
        &brief,
    );

    let svg = &payload.files[0].body;
    assert!(svg.contains(
        "<title>AI tools brand stakeholders - AI technology and software solutions</title>"
    ));
    assert!(svg.contains("<desc>"));
    assert!(svg.to_ascii_lowercase().contains("brand"));
}

#[test]
fn normalize_generated_artifact_payload_unwraps_nested_html_json_envelopes() {
    let nested_payload = serde_json::json!({
        "summary": "Nested HTML payload",
        "notes": ["wrapped once"],
        "files": [{
            "path": "index.html",
            "mime": "text/html",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Explore the launch.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\" aria-selected=\"true\">Overview</button><button type=\"button\" data-view=\"features\" aria-controls=\"features-panel\" aria-selected=\"false\">Features</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Overview evidence is visible on first paint.</p></article></section><section id=\"features-panel\" data-view-panel=\"features\" hidden><article><h2>Features</h2><p>Feature evidence remains pre-rendered.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside></main><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-view-panel]').forEach((panel)=>{panel.hidden=panel.id!==button.getAttribute('aria-controls');});document.getElementById('detail-copy').textContent=`${button.dataset.view} selected`; }));</script></body></html>"
        }]
    })
    .to_string();
    let mut payload = ChatGeneratedArtifactPayload {
        summary: "Prepared HTML artifact".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: nested_payload,
        }],
    };
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );

    normalize_generated_artifact_payload(&mut payload, &request);

    let body = payload.files[0].body.trim();
    assert!(body.to_ascii_lowercase().starts_with("<!doctype html>"));
    assert!(!body.starts_with('{'));
    assert!(!body.contains("\"files\""));
    assert!(body.contains("data-view-panel"));
    assert!(validate_generated_artifact_payload(&payload, &request).is_ok());
}

#[test]
fn normalize_generated_artifact_payload_decodes_json_escaped_html_bodies() {
    let mut payload = ChatGeneratedArtifactPayload {
        summary: "Prepared HTML artifact".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html>\\n<html lang=\\\"en\\\"><body><main><section><h1>Quantum states</h1><p>Inspect superposition without leaving the scene.</p></section><section><button type=\\\"button\\\" data-view=\\\"overview\\\" aria-controls=\\\"overview-panel\\\">Overview</button><button type=\\\"button\\\" data-view=\\\"interference\\\" aria-controls=\\\"interference-panel\\\">Interference</button></section><section id=\\\"overview-panel\\\" data-view-panel=\\\"overview\\\"><p>Default overview state.</p></section><section id=\\\"interference-panel\\\" data-view-panel=\\\"interference\\\" hidden><p>Interference details.</p></section></main><script>document.querySelectorAll('[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-view-panel]').forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});}));</script></body></html>".to_string(),
        }],
    };
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );

    normalize_generated_artifact_payload(&mut payload, &request);

    let body = payload.files[0].body.as_str();
    assert!(body.to_ascii_lowercase().starts_with("<!doctype html>"));
    assert!(!body.contains("\\n"));
    assert!(!body.contains("\\\""));
    assert!(body.contains("<main>"));
    assert!(validate_generated_artifact_payload(&payload, &request).is_ok());
}

#[test]
fn parse_and_validate_normalizes_external_chart_runtime_into_inline_svg_fallback() {
    let raw = serde_json::json!({
            "summary": "Dog shampoo rollout artifact",
            "notes": ["external chart runtime"],
            "files": [{
                "path": "index.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><head><script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script></head><body><main><section><h1>Dog shampoo rollout</h1><button type=\"button\">Inspect rollout</button></section><article><canvas id=\"chart\"></canvas></article><footer><script>const chart = new Chart(document.getElementById('chart'), {type:'bar'});</script></footer></main></body></html>"
            }]
        })
        .to_string();

    let payload = parse_and_validate_generated_artifact_payload(
        &raw,
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
    )
    .expect("external chart runtime should normalize into inline SVG fallback");

    let html = &payload.files[0].body;
    let lower = html.to_ascii_lowercase();
    assert!(!lower.contains("<script src="));
    assert!(!lower.contains("new chart("));
    assert!(lower.contains("inline chart fallback"));
    assert!(lower.contains("<svg"));
}
