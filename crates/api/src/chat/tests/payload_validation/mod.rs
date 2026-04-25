use super::*;

#[test]
fn materialization_repair_prompt_handles_missing_json_payload_for_html() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let repair_prompt = build_chat_artifact_materialization_repair_prompt(
        "Dog shampoo rollout",
        "Make it feel more enterprise",
        &request,
        &brief,
        None,
        None,
        "candidate-3",
        21,
        "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1></section></main></body></html>",
        "Failed to parse Chat artifact materialization payload: Chat artifact materialization output missing JSON payload",
    )
    .expect("repair prompt");
    let repair_text = serde_json::to_string(&repair_prompt).expect("repair prompt text");

    assert!(repair_text.contains("exact JSON schema"));
    assert!(repair_text.contains("do not answer with raw HTML"));
    assert!(repair_text.contains("files[0].body"));
}

#[test]
fn parse_and_validate_normalizes_html_mime_parameters_and_paths() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let raw = serde_json::json!({
        "summary": "Dog shampoo rollout artifact",
        "notes": [],
        "files": [{
            "path": "/files/interactive_single_file.html",
            "mime": "text/html; charset=UTF-8",
            "role": "primary",
            "renderable": true,
            "downloadable": false,
            "encoding": "utf8",
            "body": "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><button type=\"button\" data-view=\"launch\">Launch</button><button type=\"button\" data-view=\"sales\">Sales</button></section><section data-view-panel=\"launch\"><article><h2>Launch</h2><p>March regional launch.</p></article></section><section data-view-panel=\"sales\" hidden><article><h2>Sales</h2><p>Projected first-month sales.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Launch is selected by default.</p></aside></main></body></html>"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("normalization should canonicalize mime parameters");

    assert_eq!(payload.files[0].path, "files/interactive_single_file.html");
    assert_eq!(payload.files[0].mime, "text/html");
}

#[test]
fn rollover_failure_directives_require_focusable_detail_marks() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = chat_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe artifacts that wire focus-based detail behavior must make their data-detail marks keyboard-focusable.",
    );

    assert!(directives.contains("keep the current <main>"));
    assert!(directives.contains("querySelectorAll('[data-detail]')"));
    assert!(directives.contains("tabindex=\"0\""));
    assert!(directives.contains("[data-view-panel]"));
    assert!(directives.contains("detailCopy.textContent = mark.dataset.detail"));
}

#[test]
fn view_switching_failure_directives_require_panel_scaffold() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = chat_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe briefs that call for clickable view switching must map at least two controls to pre-rendered view panels with explicit static selectors.",
    );

    assert!(directives.contains("buttons[data-view]"));
    assert!(directives.contains("data-view-panel=\"customer-feedback\""));
    assert!(directives.contains("class=\"data-view-panel\""));
    assert!(directives.contains("class=\"overview-panel\""));
    assert!(directives.contains("id=\"customer-feedback-panel\""));
    assert!(directives.contains("panel.dataset.viewPanel !== button.dataset.view"));
    assert!(directives.contains("not directly at an SVG"));
    assert!(directives.contains("Keep exactly one mapped panel visibly selected"));
    assert!(directives.contains("Do not point every button at the shared detail panel"));
}

#[test]
fn main_region_failure_directives_require_markup_first_scaffold() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = chat_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe artifacts must contain a <main> region.",
    );

    assert!(directives.contains("<!doctype html><html><body><main>"));
    assert!(directives.contains("script>...interactive wiring"));
    assert!(directives.contains("before the script tag"));
}

#[test]
fn charted_evidence_failure_directives_require_visible_secondary_surface() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = sample_html_brief();

    let directives = chat_artifact_materialization_failure_directives(
        &request,
        &brief,
        "HTML iframe briefs with charted evidence must surface at least two populated evidence views on first paint.",
    );

    assert!(directives.contains("Empty mount divs like <div id=\"usage-chart\"></div>"));
    assert!(directives.contains("single sentence paragraph"));
    assert!(directives.contains("customer feedback"));
}

#[test]
fn pdf_parse_failure_directives_require_json_wrapping() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::PdfEmbed);
    let brief = ChatArtifactBrief {
        audience: "launch stakeholders".to_string(),
        job_to_be_done: "review the brief".to_string(),
        subject_domain: "launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a compact PDF.".to_string(),
        required_concepts: vec!["launch".to_string(), "brief".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };

    let directives = chat_artifact_materialization_failure_directives(
        &request,
        &brief,
        "Failed to parse Chat artifact materialization payload: Chat artifact materialization output missing JSON payload",
    );

    assert!(directives.contains("exact JSON schema"));
    assert!(directives.contains("raw document text"));
    assert!(directives.contains("files[0].body"));
}

#[test]
fn pdf_structure_failure_directives_require_visible_section_breaks() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::PdfEmbed);
    let brief = ChatArtifactBrief {
        audience: "launch stakeholders".to_string(),
        job_to_be_done: "review the brief".to_string(),
        subject_domain: "launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a compact PDF.".to_string(),
        required_concepts: vec!["launch".to_string(), "brief".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };

    let directives = chat_artifact_materialization_failure_directives(
        &request,
        &brief,
        "PDF source content needs clearer sections before it can lead the artifact stage.",
    );

    assert!(directives.contains("five short standalone section headings"));
    assert!(directives.contains("separated by blank lines"));
    assert!(directives.contains("Executive Summary"));
}

#[test]
fn pdf_placeholder_failure_directives_require_concrete_copy() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::PdfEmbed);
    let brief = ChatArtifactBrief {
        audience: "launch stakeholders".to_string(),
        job_to_be_done: "review the brief".to_string(),
        subject_domain: "launch planning".to_string(),
        artifact_thesis: "Summarize the launch brief in a compact PDF.".to_string(),
        required_concepts: vec!["launch".to_string(), "brief".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["professional".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };

    let directives = chat_artifact_materialization_failure_directives(
        &request,
        &brief,
        "PDF source content must not contain bracketed placeholder copy.",
    );

    assert!(directives.contains("bracketed template token"));
    assert!(directives.contains("request-grounded bullets"));
}

#[test]
fn modal_first_html_local_runtime_candidate_generation_uses_single_candidate() {
    with_modal_first_html_env(|| {
        let (count, temperature, strategy) = candidate_generation_config(
            ChatRendererKind::HtmlIframe,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        );
        assert_eq!(count, 1);
        assert!(temperature >= 0.68);
        assert_eq!(strategy, "request-grounded_html");
    });
}

#[test]
fn modal_first_html_local_runtime_materialization_token_budget_expands_completion_room() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::generation::materialization_max_tokens_for_runtime(
                ChatRendererKind::HtmlIframe,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            2800
        );
    });
}

#[test]
fn local_html_direct_author_budget_matches_local_materialization_budget() {
    super::with_chat_modal_first_html_override(false, || {
        assert_eq!(
            super::generation::materialization_max_tokens_for_execution_strategy(
                ChatRendererKind::HtmlIframe,
                ChatExecutionStrategy::DirectAuthor,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            super::generation::materialization_max_tokens_for_runtime(
                ChatRendererKind::HtmlIframe,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
        );
    });
}

#[test]
fn modal_first_html_direct_author_budget_stays_bounded_for_local_gpu_runs() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::generation::materialization_max_tokens_for_execution_strategy(
                ChatRendererKind::HtmlIframe,
                ChatExecutionStrategy::DirectAuthor,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            2400
        );
    });
}

#[test]
fn simple_local_runtime_renderers_use_single_candidate_budgets() {
    for (renderer, expected_temperature, expected_strategy) in [
        (ChatRendererKind::Markdown, 0.22, "outline-first_markdown"),
        (ChatRendererKind::Mermaid, 0.18, "pipeline-first_mermaid"),
        (ChatRendererKind::PdfEmbed, 0.2, "brief-first_pdf"),
        (
            ChatRendererKind::DownloadCard,
            0.12,
            "bundle-first_download",
        ),
        (
            ChatRendererKind::BundleManifest,
            0.12,
            "bundle-first_download",
        ),
    ] {
        let (count, temperature, strategy) =
            candidate_generation_config(renderer, ChatRuntimeProvenanceKind::RealLocalRuntime);
        assert_eq!(count, 1);
        assert!((temperature - expected_temperature).abs() < f32::EPSILON);
        assert_eq!(strategy, expected_strategy);
    }
}

#[test]
fn modal_first_html_local_runtime_refinement_budget_allows_one_pass() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::validation::semantic_refinement_pass_limit(
                ChatRendererKind::HtmlIframe,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            1
        );
    });
}

#[test]
fn modal_first_quantum_html_budget_stays_user_viable() {
    with_modal_first_html_env(|| {
        let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
        let brief = sample_quantum_explainer_brief();
        let blueprint = derive_chat_artifact_blueprint(&request, &brief);
        let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);

        let budget = super::generation::derive_chat_adaptive_search_budget(
            &request,
            &brief,
            Some(&blueprint),
            Some(&artifact_ir),
            &[],
            &[],
            None,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            ChatArtifactRuntimePolicyProfile::FullyLocal,
            false,
        );

        assert_eq!(budget.initial_candidate_count, 1);
        assert_eq!(budget.max_candidate_count, 1);
        assert_eq!(budget.shortlist_limit, 1);
        assert_eq!(budget.max_semantic_refinement_passes, 1);
        assert!(budget
            .signals
            .contains(&ChatAdaptiveSearchSignal::LocalGenerationConstraint));
    });
}

#[test]
fn modal_first_quantum_html_budget_reopens_for_validation_backed_runtime_profile() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let blueprint = derive_chat_artifact_blueprint(&request, &brief);
        let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);

        let budget = super::generation::derive_chat_adaptive_search_budget(
            &request,
            &brief,
            Some(&blueprint),
            Some(&artifact_ir),
            &[],
            &[],
            None,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
            false,
        );

        assert_eq!(budget.initial_candidate_count, 1);
        assert!(budget.max_candidate_count >= 3);
        assert!(budget.shortlist_limit >= 3);
        assert_eq!(budget.max_semantic_refinement_passes, 3);
        assert!(budget
            .signals
            .contains(&ChatAdaptiveSearchSignal::LocalGenerationConstraint));
    });
}

#[test]
fn modal_first_local_html_prompt_pushes_authored_interactive_explainers() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();

        let prompt = build_chat_artifact_materialization_prompt_for_runtime(
            "Quantum computing explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-1",
            42,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        )
        .expect("modal-first local prompt");

        let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
        let prompt_text = decode_chat_test_prompt(&prompt_bytes);

        assert!(prompt_text.contains(
            "prefer a living model, scenario walkthrough, inspectable diagram, or guided comparison"
        ));
        assert!(prompt_text
            .contains("one isolated button or slider does not satisfy an interactive artifact"));
        assert!(prompt_text.contains("avoid default browser-white document styling"));
    });
}

#[test]
fn modal_first_local_html_materialization_prompt_stays_compact_for_landing_pages() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = ChatArtifactBrief {
            audience: "SaaS teams evaluating collaboration tooling".to_string(),
            job_to_be_done:
                "understand CloudSync pricing, features, and reasons to switch".to_string(),
            subject_domain: "B2B SaaS landing page".to_string(),
            artifact_thesis:
                "Present CloudSync as a polished landing page with pricing comparison and feature proof."
                    .to_string(),
            required_concepts: vec![
                "CloudSync".to_string(),
                "pricing tiers".to_string(),
                "feature proof".to_string(),
                "team collaboration".to_string(),
            ],
            required_interactions: vec![
                "plan switching".to_string(),
                "feature inspection".to_string(),
            ],
            visual_tone: vec!["editorial".to_string(), "confident".to_string()],
            factual_anchors: vec!["pricing comparison".to_string()],
            style_directives: vec!["bold product storytelling".to_string()],
            reference_hints: vec!["hero, proof, pricing, footer".to_string()],
            query_profile: None,
        };

        let remote_prompt = build_chat_artifact_materialization_prompt_for_runtime(
            "CloudSync landing page",
            "Build a beautiful landing page for a SaaS product called CloudSync with a hero section, feature cards, pricing table, and a footer",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-1",
            7,
            ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
        )
        .expect("remote modal-first prompt");
        let local_prompt = build_chat_artifact_materialization_prompt_for_runtime(
            "CloudSync landing page",
            "Build a beautiful landing page for a SaaS product called CloudSync with a hero section, feature cards, pricing table, and a footer",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-1",
            7,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        )
        .expect("local modal-first prompt");

        let remote_prompt_bytes = serde_json::to_vec(&remote_prompt).expect("remote prompt bytes");
        let local_prompt_bytes = serde_json::to_vec(&local_prompt).expect("local prompt bytes");
        let local_prompt_text = decode_chat_test_prompt(&local_prompt_bytes);

        assert!(local_prompt_bytes.len() < remote_prompt_bytes.len());
        assert!(local_prompt_bytes.len() < 11_000);
        assert!(local_prompt_text.contains(
            "Keep CSS and JS concise enough to finish the full document in one local-model pass."
        ));
        assert!(local_prompt_text.contains(
            "Ship one self-contained .html file with inline CSS/JS, <main>, and meaningful surfaced structure."
        ));
        assert!(!local_prompt_text.contains("Build the first paint around this section blueprint:"));
    });
}

#[test]
fn shortlist_widens_for_near_tied_primary_view_candidates() {
    let mut budget = ChatAdaptiveSearchBudget {
        initial_candidate_count: 2,
        max_candidate_count: 3,
        shortlist_limit: 1,
        max_semantic_refinement_passes: 1,
        plateau_limit: 1,
        min_score_delta: 1,
        target_validation_score_for_early_stop: 356,
        expansion_score_margin: 12,
        signals: Vec::new(),
    };
    let candidate_summaries = vec![
        chat_test_candidate_summary(
            "candidate-1",
            chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 5, 5, 5),
        ),
        chat_test_candidate_summary(
            "candidate-2",
            chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 5, 5, 4),
        ),
        chat_test_candidate_summary(
            "candidate-3",
            chat_test_validation(
                ChatArtifactValidationStatus::Repairable,
                false,
                3,
                3,
                3,
                3,
                3,
                3,
            ),
        ),
    ];
    let ranked = super::generation::ranked_candidate_indices_by_score(&candidate_summaries);
    let shortlist = super::generation::shortlisted_candidate_indices_for_budget(
        &mut budget,
        &ranked,
        &candidate_summaries,
    );

    assert_eq!(shortlist, vec![0, 1]);
    assert_eq!(budget.shortlist_limit, 2);
    assert!(budget
        .signals
        .contains(&ChatAdaptiveSearchSignal::LowCandidateVariance));
}

#[test]
fn html_local_runtime_materialization_repair_budget_limits_to_single_pass() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            ChatRendererKind::HtmlIframe,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        ),
        1
    );
}

#[test]
fn html_remote_runtime_materialization_repair_budget_allows_three_passes() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            ChatRendererKind::HtmlIframe,
            ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
        ),
        3
    );
}

#[test]
fn pdf_materialization_repair_budget_allows_three_passes() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            ChatRendererKind::PdfEmbed,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        ),
        3
    );
}

#[test]
fn validates_generated_markdown_payload() {
    let payload = ChatGeneratedArtifactPayload {
        summary: "Prepared markdown artifact".to_string(),
        notes: vec!["Verified structure".to_string()],
        files: vec![ChatGeneratedArtifactFile {
            path: "brief.md".to_string(),
            mime: "text/markdown".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: "# Brief".to_string(),
        }],
    };
    validate_generated_artifact_payload(
        &payload,
        &request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown),
    )
    .expect("payload should validate");
}

#[test]
fn rejects_generated_pdf_payload_when_source_is_too_short() {
    let payload = ChatGeneratedArtifactPayload {
        summary: "Launch brief".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "brief.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: "Executive Summary\n\nThis launch brief is short.\n\nProject Scope\n\nA limited regional rollout.\n\nNext Steps\n\nFinalize owner review.".to_string(),
        }],
    };

    let error = validate_generated_artifact_payload(
        &payload,
        &request_for(ChatArtifactClass::Document, ChatRendererKind::PdfEmbed),
    )
    .expect_err("short PDF source should fail validation");

    assert!(error.contains("PDF source content is too short"));
}

#[test]
fn parse_generated_payload_tolerates_duplicate_json_fields() {
    let raw = r#"{
        "summary": "Dog shampoo rollout",
        "notes": [],
        "files": [
            {
                "path": "dog-shampoo-rollout.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "downloadable": false,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><main><section><h1>Dog shampoo</h1><button type=\"button\" data-view=\"overview\">Overview</button></section><article data-view-panel=\"overview\"><p>Metrics</p></article><aside><p id=\"detail-copy\">Overview selected.</p></aside><footer>Done</footer><script>const detail=document.getElementById('detail-copy');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=`${button.dataset.view} selected.`;}));</script></main></body></html>"
            }
        ]
    }"#;

    let payload =
        parse_chat_generated_artifact_payload(raw).expect("duplicate fields should collapse");

    assert_eq!(payload.files.len(), 1);
    assert!(!payload.files[0].downloadable);
    validate_generated_artifact_payload(
        &payload,
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
    )
    .expect("normalized payload should still validate");
}

#[test]
fn parse_and_validate_recovers_raw_html_payloads_and_normalizes_custom_fonts() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let raw = "<!doctype html><html><head><style>:root{--display-font:'Newsreader',serif;}body{font-family:'Newsreader',serif;background:#f8fafc;color:#0f172a;}main{display:grid;gap:1rem;}section,aside,footer{padding:1rem;border:1px solid #cbd5e1;border-radius:12px;}button{font-family:'Instrument Sans',sans-serif;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics.</p><button type=\"button\" data-view=\"overview\" aria-controls=\"overview-panel\">Overview</button><button type=\"button\" data-view=\"metrics\" aria-controls=\"metrics-panel\">Metrics</button></section><section id=\"overview-panel\" data-view-panel=\"overview\"><article><h2>Overview</h2><p>Readiness evidence stays visible here.</p></article></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><article><h2>Metrics</h2><p>Metrics evidence stays pre-rendered.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer><script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script></main></body></html>";

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("raw html payloads should be recoverable for html iframe artifacts");

    assert_eq!(payload.files[0].path, "index.html");
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("normalized from raw html document output")));
    let html = payload.files[0].body.to_ascii_lowercase();
    assert!(!html.contains("font-family:'newsreader'"));
    assert!(!html.contains("font-family:'instrument sans'"));
    assert!(html.contains("ui-serif, serif"));
    assert!(html.contains("system-ui, sans-serif"));
}

#[test]
fn parse_and_validate_recovers_raw_markdown_payloads() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let raw = "```markdown\n# Quantum computers\n\n## Core idea\nQuantum computers use qubits, interference, and measurement to solve specific classes of problems differently from classical systems.\n\n## What changes in practice\nTeams still need algorithm fit, hardware realism, and error mitigation.\n```";

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("raw markdown payloads should be recoverable for direct document artifacts");

    assert_eq!(payload.files[0].path, "artifact.md");
    assert_eq!(payload.files[0].mime, "text/markdown");
    assert!(payload.files[0].body.starts_with("# Quantum computers"));
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("normalized from raw markdown document output")));
}

#[test]
fn parse_and_validate_recovers_raw_svg_payloads() {
    let request = request_for(ChatArtifactClass::Visual, ChatRendererKind::Svg);
    let raw = "Here is the document:\n<svg viewBox=\"0 0 240 140\" xmlns=\"http://www.w3.org/2000/svg\"><title>Quantum comparison</title><desc>Compares classical and quantum states.</desc><rect x=\"16\" y=\"58\" width=\"42\" height=\"54\" /><rect x=\"84\" y=\"34\" width=\"42\" height=\"78\" /><rect x=\"152\" y=\"20\" width=\"42\" height=\"92\" /><text x=\"16\" y=\"130\">Bit</text><text x=\"84\" y=\"130\">Qubit</text><text x=\"152\" y=\"130\">Measure</text></svg>\nThanks.";

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("raw svg payloads should be recoverable for direct document artifacts");

    assert_eq!(payload.files[0].path, "artifact.svg");
    assert_eq!(payload.files[0].mime, "image/svg+xml");
    assert!(payload.files[0].body.starts_with("<svg"));
    assert!(payload.files[0].body.ends_with("</svg>"));
    assert!(payload
        .notes
        .iter()
        .any(|note| note.contains("normalized from raw svg document output")));
}

#[test]
fn modal_first_html_requires_real_interaction_instead_of_injected_disclosure() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let raw = serde_json::json!({
            "summary": "Quantum computing explainer",
            "notes": ["model emitted a static page shell"],
            "files": [{
                "path": "quantum-explainer.html",
                "mime": "text/html",
                "role": "primary",
                "renderable": true,
                "downloadable": true,
                "encoding": "utf8",
                "body": "<!doctype html><html><body><header><h1>Quantum computing explained</h1><p>Understand superposition, entanglement, and measurement through concise sections.</p></header><section><h2>Superposition</h2><p>Qubits carry probability amplitudes before observation.</p></section><section><h2>Entanglement</h2><p>Entangled systems share state relationships across distance.</p></section><section><h2>Measurement</h2><p>Measurement collapses the quantum state into a classical outcome.</p></section></body></html>"
            }]
        })
        .to_string();

        let error = parse_and_validate_generated_artifact_payload(&raw, &request).expect_err(
            "modal-first html should require authored interaction instead of injecting one",
        );

        assert!(error.contains("must contain real interactive controls or handlers"));
    });
}

#[test]
fn modal_first_html_validation_rejects_truncated_documents() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let raw = "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button></section><section><article><h2>Quantum circuit</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Quantum circuit\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Gate</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Superposition is selected by default.</p></aside><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.getElementById('detail-copy').textContent=button.dataset.view;}));</script><div class=\"";

        let error = parse_and_validate_generated_artifact_payload(raw, &request)
            .expect_err("truncated modal-first html should be rejected before promotion");

        assert!(!error.trim().is_empty());
    });
}

#[test]
fn modal_first_html_validation_accepts_browser_complete_documents_without_terminal_html_closers() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let raw = "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button><button type=\"button\" data-view=\"measurement\">Measurement</button></section><section data-view-panel=\"superposition\"><h2>Superposition</h2><p>Qubits can exist in overlapping amplitudes before observation.</p></section><section data-view-panel=\"measurement\" hidden><h2>Measurement</h2><p>Measurement collapses amplitudes into observable outcomes.</p></section><aside><p id=\"detail-copy\">Superposition is selected by default.</p></aside><script>const buttons=Array.from(document.querySelectorAll('button[data-view]'));const panels=Array.from(document.querySelectorAll('[data-view-panel]'));const detail=document.getElementById('detail-copy');buttons.forEach((button)=>button.addEventListener('click',()=>{buttons.forEach((entry)=>entry.setAttribute('aria-selected',String(entry===button)));panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view==='superposition'?'Superposition is selected by default.':'Measurement is selected.';}));</script></main>";

        let payload = parse_and_validate_generated_artifact_payload(raw, &request)
            .expect("browser-complete html without terminal html closers should validate");

        let html = payload.files[0].body.to_ascii_lowercase();
        assert!(html.ends_with("</main></body></html>"));
        assert!(html.contains("measurement is selected."));
    });
}

#[test]
fn modal_first_html_normalization_closes_unclosed_inner_elements_before_terminal_html_closer() {
    with_modal_first_html_env(|| {
        let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
        let raw = "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button><section><article><h2>Quantum circuit</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Quantum circuit\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Gate</text></svg></article></section></main></body></html>";

        let payload = parse_and_validate_generated_artifact_payload(raw, &request)
            .expect("terminal html closer should allow normalization of missing inner elements");

        let html = payload.files[0].body.to_ascii_lowercase();
        assert!(html.contains("</section></main></body></html>"));
        assert!(html.contains("</article></section>"));
        validate_generated_artifact_payload(&payload, &request)
            .expect("normalized terminally closed html should validate");
    });
}

#[test]
fn modal_first_html_normalization_closes_missing_terminal_suffix() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let raw = "<!doctype html><html><body><main><section><h1>Quantum computing explained</h1><p>Inspect qubits, entanglement, and measurement through a request-specific explainer.</p><button type=\"button\" data-view=\"superposition\">Superposition</button></section><section><article><h2>Quantum circuit</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Quantum circuit\"><rect x=\"24\" y=\"54\" width=\"42\" height=\"62\"></rect><text x=\"24\" y=\"132\">Gate</text></svg></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Superposition is selected by default.</p></aside><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{document.getElementById('detail-copy').textContent=button.dataset.view;}));</script>";

        let payload = parse_and_validate_generated_artifact_payload(raw, &request)
            .expect("modal-first normalization should close a missing terminal html suffix");

        let html = payload.files[0].body.to_ascii_lowercase();
        assert!(html.ends_with("</main></body></html>"));
        validate_generated_artifact_payload(&payload, &request)
            .expect("the normalized html suffix should validate");
    });
}

#[test]
fn modal_first_html_normalization_closes_unclosed_inner_elements_when_stream_cut_short() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let raw = "<!doctype html><html><body><main><section><h1>Mortgage estimator</h1><p>Adjust the inputs to inspect the payment.</p><input type=\"range\" id=\"rate\" min=\"1\" max=\"10\" value=\"6\"></section><section><article><h2>Payment summary</h2><p id=\"monthly\">$1,750</p></article><article><h2>Scenario comparison</h2><p>Higher down payments reduce the financed amount.</p></article></section><aside><h2>Detail</h2><p id=\"detail-copy\">Rate is selected by default.</p>";

        let payload = parse_and_validate_generated_artifact_payload(raw, &request)
            .expect("stream-cut modal-first html should normalize missing inner closures");

        let html = payload.files[0].body.to_ascii_lowercase();
        assert!(html.ends_with("</main></body></html>"));
        assert!(html.contains("</aside>"));
        assert!(html.matches("</section>").count() >= 2);
        validate_generated_artifact_payload(&payload, &request)
            .expect("normalized streamed html should validate");
    });
}

#[test]
fn parse_and_validate_rejects_structurally_truncated_svg_even_with_terminal_closer() {
    let request = request_for(ChatArtifactClass::Visual, ChatRendererKind::Svg);
    let raw = "<svg viewBox=\"0 0 240 140\" xmlns=\"http://www.w3.org/2000/svg\"><g><rect x=\"16\" y=\"58\" width=\"42\" height=\"54\" /></svg>";

    let error = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect_err("terminally closed but structurally truncated svg should be rejected");

    assert!(error.contains("must not close the document while SVG elements remain unclosed"));
}

#[test]
fn parse_and_validate_extracts_html_from_mixed_json_and_html_output() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let raw = concat!(
        "{\"summary\":\"Interactive HTML artifact\",\"notes\":[\"model spilled both formats\"],",
        "\"files\":[{\"path\":\"artifact.html\",\"mime\":\"text/html\",\"role\":\"primary\",",
        "\"renderable\":true,\"downloadable\":false,\"encoding\":\"utf8\",\"body\":\"truncated\"}]}",
        "\n<!doctype html><html><body><main><section><h1>Quantum computers explained</h1>",
        "<p>Inspect qubits, superposition, and entanglement through authored states.</p>",
        "<button type=\"button\" data-view=\"qubits\" aria-controls=\"qubits-panel\">Qubits</button>",
        "<button type=\"button\" data-view=\"entanglement\" aria-controls=\"entanglement-panel\">Entanglement</button>",
        "</section><section id=\"qubits-panel\" data-view-panel=\"qubits\"><article><h2>Qubits</h2>",
        "<p>Qubits encode amplitudes instead of a fixed binary state.</p></article></section>",
        "<section id=\"entanglement-panel\" data-view-panel=\"entanglement\" hidden><article><h2>Entanglement</h2>",
        "<p>Entangled pairs preserve correlated outcomes across distance.</p></article></section>",
        "<aside><h2>Detail</h2><p id=\"detail-copy\">Qubits are selected by default.</p></aside>",
        "<script>const detail=document.getElementById('detail-copy');const panels=document.querySelectorAll('[data-view-panel]');document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected.';}));</script>",
        "</main></body></html>\ntrailing prose that should be discarded"
    );

    let payload = parse_and_validate_generated_artifact_payload(raw, &request)
        .expect("mixed json/html output should salvage the authored html document");

    assert_eq!(payload.files[0].path, "artifact.html");
    assert!(payload.files[0].body.starts_with("<!doctype html>"));
    assert!(payload.files[0]
        .body
        .contains("Quantum computers explained"));
    assert!(!payload.files[0].body.contains("\"summary\":"));
    assert!(!payload.files[0]
        .body
        .contains("trailing prose that should be discarded"));
}

#[test]
fn parse_and_validate_accepts_file_content_aliases_for_download_cards() {
    let request = request_for(
        ChatArtifactClass::DownloadableFile,
        ChatRendererKind::DownloadCard,
    );
    let raw = serde_json::json!({
        "summary": "Download bundle",
        "notes": ["local-runtime alias payload"],
        "files": [{
            "path": "README.md",
            "mime": "text/markdown",
            "role": "supporting",
            "renderable": false,
            "downloadable": true,
            "encoding": "utf8",
            "content": "# Bundle\n\nUse the CSV export for launch review."
        }, {
            "path": "exports/launch-metrics.csv",
            "mime": "text/csv",
            "role": "export",
            "renderable": false,
            "downloadable": true,
            "encoding": "utf8",
            "text": "lane,metric,value\npilot,coverage,72\nlaunch,readiness,81\n"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("content aliases should normalize into generated file bodies");

    assert_eq!(payload.files.len(), 2);
    assert_eq!(
        payload.files[0].body,
        "# Bundle\n\nUse the CSV export for launch review."
    );
    assert_eq!(
        payload.files[1].body,
        "lane,metric,value\npilot,coverage,72\nlaunch,readiness,81\n"
    );
}

#[test]
fn parse_and_validate_recovers_download_card_missing_readme_and_placeholder_csv() {
    let request = request_for(
        ChatArtifactClass::DownloadableFile,
        ChatRendererKind::DownloadCard,
    );
    let raw = serde_json::json!({
        "summary": "A downloadable artifact bundle with a CSV and README",
        "notes": [
            "The artifact includes a non-empty README.md file explaining the bundle contents.",
            "The CSV export has at least two data rows with request-grounded values."
        ],
        "files": [{
            "path": "README.md",
            "mime": "text/markdown",
            "role": "primary",
            "renderable": true,
            "downloadable": true,
            "encoding": null
        }, {
            "path": "data.csv",
            "mime": "text/csv",
            "role": "export",
            "renderable": false,
            "downloadable": true,
            "body": "CSV export with at least two data rows"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("download card salvage should recover missing README and CSV bodies");

    assert_eq!(payload.files.len(), 2);
    assert!(payload.files.iter().all(|file| !file.renderable));
    let readme = payload
        .files
        .iter()
        .find(|file| file.path == "README.md")
        .expect("README file");
    let csv = payload
        .files
        .iter()
        .find(|file| file.path == "data.csv")
        .expect("CSV file");
    assert!(readme.body.contains("## Files"));
    assert!(readme.body.contains("## CSV columns"));
    assert!(csv.body.starts_with("record,detail"));
    assert!(csv.body.lines().count() >= 4);
}

#[test]
fn parse_and_validate_recovers_missing_docx_body_for_download_cards() {
    let request = request_for(
        ChatArtifactClass::DownloadableFile,
        ChatRendererKind::DownloadCard,
    );
    let raw = serde_json::json!({
        "summary": "Quarterly performance Word document",
        "notes": [
            "Create a Word document with a cover page, table of contents, headers and footers, and three sections of body text."
        ],
        "files": [{
            "path": "exports/quarterly-performance.docx",
            "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "role": "export",
            "renderable": false,
            "downloadable": true,
            "encoding": "utf8"
        }]
    })
    .to_string();

    let payload = parse_and_validate_generated_artifact_payload(&raw, &request)
        .expect("download card normalization should synthesize usable docx bodies");

    let export = payload
        .files
        .iter()
        .find(|file| file.path.ends_with(".docx"))
        .expect("docx export");
    assert_eq!(export.encoding, Some(ChatGeneratedArtifactEncoding::Base64));
    let entry_names = zip_entry_names_from_base64_body(&export.body);
    assert!(entry_names
        .iter()
        .any(|entry| entry == "[Content_Types].xml"));
    assert!(entry_names.iter().any(|entry| entry == "_rels/.rels"));
    assert!(entry_names.iter().any(|entry| entry == "word/document.xml"));
    let document_xml = zip_entry_text_from_base64_body(&export.body, "word/document.xml");
    assert!(document_xml.contains("Cover Page"));
    assert!(document_xml.contains("Table of Contents"));
    assert!(payload.files.iter().all(|file| !file.renderable));
}

#[test]
fn parse_and_validate_adds_missing_spreadsheet_export_for_download_cards() {
    let request = request_for(
        ChatArtifactClass::DownloadableFile,
        ChatRendererKind::DownloadCard,
    );
    let mut payload = ChatGeneratedArtifactPayload {
        summary: "Budget spreadsheet bundle".to_string(),
        notes: vec![
            "Create a budget spreadsheet with income and expense categories, monthly columns, SUM formulas for totals, conditional formatting for overages, and a summary chart.".to_string(),
        ],
        files: vec![ChatGeneratedArtifactFile {
            path: "README.md".to_string(),
            mime: "text/markdown".to_string(),
            role: ChatArtifactFileRole::Supporting,
            renderable: false,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: "# Budget spreadsheet bundle\n\nA source preview accompanies the export."
                .to_string(),
        }],
    };

    normalize_generated_artifact_payload(&mut payload, &request);

    let export = payload
        .files
        .iter()
        .find(|file| file.path.ends_with(".xlsx"))
        .expect("xlsx export");
    assert_eq!(export.encoding, Some(ChatGeneratedArtifactEncoding::Base64));
    let entry_names = zip_entry_names_from_base64_body(&export.body);
    assert!(entry_names
        .iter()
        .any(|entry| entry == "[Content_Types].xml"));
    assert!(entry_names.iter().any(|entry| entry == "xl/workbook.xml"));
    assert!(entry_names
        .iter()
        .any(|entry| entry == "xl/worksheets/sheet1.xml"));
    assert!(entry_names
        .iter()
        .any(|entry| entry == "xl/worksheets/sheet2.xml"));
    let sheet_xml = zip_entry_text_from_base64_body(&export.body, "xl/worksheets/sheet1.xml");
    assert!(sheet_xml.contains("Budget"));
    assert!(sheet_xml.contains("SUM(B2:E2)"));
}

#[test]
fn local_download_bundle_candidate_prevalidation_accepts_docx_exports() {
    let request = request_for(
        ChatArtifactClass::DownloadableFile,
        ChatRendererKind::DownloadCard,
    );
    let brief = ChatArtifactBrief {
        audience: "leadership".to_string(),
        job_to_be_done: "summarize quarterly performance".to_string(),
        subject_domain: "quarterly performance".to_string(),
        artifact_thesis: "Create a Word document with structured sections.".to_string(),
        required_concepts: vec![
            "executive summary".to_string(),
            "operational performance".to_string(),
            "next steps".to_string(),
        ],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: Vec::new(),
        factual_anchors: vec!["headers and footers".to_string()],
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    };
    let payload = crate::chat::payload::synthesize_download_bundle_payload(
        "Create a Word document with a cover page, table of contents, headers and footers, and three sections of body text about our quarterly performance",
        &brief,
    );

    let validation = super::generation::local_download_bundle_candidate_prevalidation(
        &request, &brief, &payload,
    );
    assert_eq!(
        validation.classification,
        ChatArtifactValidationStatus::Pass
    );
    assert!(validation
        .strengths
        .iter()
        .any(|strength| strength.contains("Word document export")));
}

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
        include_str!("../../test_fixtures/qwen3_editorial_trace8_near_pass.html"),
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

#[derive(Clone)]
struct ChatTestRuntime {
    provenance: ChatRuntimeProvenance,
    role: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
}

impl ChatTestRuntime {
    fn new(
        kind: ChatRuntimeProvenanceKind,
        label: &str,
        model: &str,
        endpoint: &str,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            provenance: ChatRuntimeProvenance {
                kind,
                label: label.to_string(),
                model: Some(model.to_string()),
                endpoint: Some(endpoint.to_string()),
            },
            role,
            calls,
        }
    }
}

#[async_trait]
impl InferenceRuntime for ChatTestRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = decode_chat_test_prompt(input_context);
        let stage = if prompt.contains("typed artifact brief planner") {
            "brief"
        } else if prompt.contains("typed artifact materializer") {
            "materialize"
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
            "brief" => serde_json::json!({
                "audience": "operators",
                "jobToBeDone": "explain the rollout",
                "subjectDomain": "rollout planning",
                "artifactThesis": "show the launch plan clearly",
                "requiredConcepts": ["rollout timeline", "launch owners", "readiness checkpoints"],
                "requiredInteractions": ["chart toggle", "detail comparison"],
                "visualTone": ["confident"],
                "factualAnchors": ["launch checkpoint review"],
                "styleDirectives": [],
                "referenceHints": []
            }),
            "materialize" => {
                if prompt.contains("\"renderer\": \"markdown\"")
                    || prompt.contains("\"renderer\":\"markdown\"")
                {
                    serde_json::json!({
                        "summary": "Prepared a rollout artifact",
                        "notes": ["request-grounded candidate"],
                        "files": [{
                            "path": "release-checklist.md",
                            "mime": "text/markdown",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "# Release checklist\n\n- Finalize branch\n- Run QA\n- Tag release"
                        }]
                    })
                } else {
                    serde_json::json!({
                        "summary": "Prepared a rollout artifact",
                        "notes": ["request-grounded candidate"],
                        "files": [{
                            "path": "index.html",
                            "mime": "text/html",
                            "role": "primary",
                            "renderable": true,
                            "downloadable": true,
                            "encoding": "utf8",
                            "body": "<!doctype html><html><body><main><section><h1>Rollout</h1></section><article><p>Timeline and owners.</p></article><footer>Ready for review.</footer></main></body></html>"
                        }]
                    })
                }
            }
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
                "patchedExistingArtifact": null,
                "continuityRevisionUx": null,
                "strongestContradiction": null,
                "rationale": format!("validated by {}", self.role)
            }),
            _ => return Err(VmError::HostError("unexpected Chat prompt".to_string())),
        };
        Ok(response.to_string().into_bytes())
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

#[test]
fn local_generation_remote_acceptance_policy_falls_back_truthfully_when_acceptance_is_unavailable()
{
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let unavailable_acceptance: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::InferenceUnavailable,
        "acceptance unavailable",
        "unavailable",
        "unavailable://acceptance",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        production_runtime,
        Some(unavailable_acceptance),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    assert_eq!(
        runtime_plan.policy.profile,
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
    );
    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("acceptance_runtime_unavailable")
    );
    assert_eq!(acceptance_binding.provenance.label, "local producer");
    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert!(!planning_binding.fallback_applied);
    assert_eq!(planning_binding.provenance.label, "local producer");
}

#[test]
fn local_generation_remote_acceptance_prefers_local_specialist_for_markdown_generation_and_acceptance(
) {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown),
        production_runtime,
        Some(acceptance_runtime),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert_eq!(planning_binding.provenance.label, "local specialist");
    assert!(!planning_binding.fallback_applied);

    let generation_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::CandidateGeneration)
        .expect("generation binding");
    assert_eq!(generation_binding.provenance.label, "local specialist");
    assert!(!generation_binding.fallback_applied);

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("compact_local_specialist_acceptance")
    );
}

#[test]
fn local_generation_remote_acceptance_prefers_local_specialist_for_download_bundle_acceptance() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(
            ChatArtifactClass::DownloadableFile,
            ChatRendererKind::DownloadCard,
        ),
        production_runtime,
        Some(acceptance_runtime),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.fallback_reason.as_deref(),
        Some("compact_local_specialist_acceptance")
    );
}

#[test]
fn local_generation_remote_acceptance_keeps_html_generation_on_primary_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        production_runtime,
        Some(acceptance_runtime),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let generation_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::CandidateGeneration)
        .expect("generation binding");
    assert_eq!(generation_binding.provenance.label, "local producer");
    assert!(!generation_binding.fallback_applied);

    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert_eq!(planning_binding.provenance.label, "local producer");
    assert!(!planning_binding.fallback_applied);

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(!acceptance_binding.fallback_applied);

    let repair_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::RepairPlanning)
        .expect("repair binding");
    assert_eq!(repair_binding.provenance.label, "local specialist");
    assert!(!repair_binding.fallback_applied);
}

#[test]
fn modal_first_local_generation_remote_acceptance_keeps_html_generation_on_primary_runtime() {
    with_modal_first_html_env(|| {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            "local producer",
            "qwen2.5:14b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
        let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            "local specialist",
            "qwen3.5:9b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "acceptance",
            calls,
        ));

        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request_for(
                ChatArtifactClass::InteractiveSingleFile,
                ChatRendererKind::HtmlIframe,
            ),
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
        );

        let planning_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
            .expect("planning binding");
        assert_eq!(planning_binding.provenance.label, "local producer");
        assert!(!planning_binding.fallback_applied);

        let generation_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::CandidateGeneration)
            .expect("generation binding");
        assert_eq!(generation_binding.provenance.label, "local producer");
        assert!(!generation_binding.fallback_applied);

        let acceptance_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
            .expect("acceptance binding");
        assert_eq!(acceptance_binding.provenance.label, "local specialist");
        assert!(!acceptance_binding.fallback_applied);

        let repair_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::RepairPlanning)
            .expect("repair binding");
        assert_eq!(repair_binding.provenance.label, "local specialist");
        assert!(!repair_binding.fallback_applied);
    });
}

#[test]
fn local_html_materialization_repair_prefers_local_specialist_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let repair_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "repair",
        calls,
    ));

    let selected_runtime = super::generation::materialization_repair_runtime_for_request(
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        &production_runtime,
        Some(&repair_runtime),
    );

    assert_eq!(
        selected_runtime.chat_runtime_provenance().label,
        "local specialist"
    );
}

#[tokio::test]
async fn local_html_swarm_strategy_repairs_and_passes_quantum_artifact_regression() {
    #[derive(Clone)]
    struct QuantumSwarmRegressionRuntime {
        provenance: ChatRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InferenceRuntime for QuantumSwarmRegressionRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief"
            } else if prompt.contains("typed swarm Skeleton worker") {
                "skeleton"
            } else if prompt.contains("typed swarm SectionContent worker") {
                "section"
            } else if prompt.contains("typed swarm StyleSystem worker") {
                "style"
            } else if prompt.contains("typed swarm Interaction worker") {
                "interaction"
            } else if prompt.contains("typed swarm Repair worker") {
                "repair"
            } else if prompt.contains("typed swarm Integrator worker") {
                "integrator"
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
                "brief" => {
                    serde_json::to_value(sample_quantum_explainer_brief()).expect("quantum brief")
                }
                "skeleton" => serde_json::json!({
                    "summary": "Quantum computers interactive draft",
                    "notes": ["Created the bounded quantum explainer skeleton."],
                    "operations": [{
                        "kind": "create_file",
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><meta charset=\"utf-8\"><title>Quantum computers interactive explainer</title></head><body><main><section><h1>Quantum computers, step by step</h1><p>Compare classical bits with quantum states, then inspect how measurement changes the outcome.</p><div class=\"mode-switch\"><button type=\"button\" data-mode=\"classical\" aria-selected=\"true\">Classical Bit</button><button type=\"button\" data-mode=\"quantum\" aria-selected=\"false\">Quantum State</button></div></section><section><article><h2>State comparison</h2><p id=\"mode-summary\">Classical bits stay in one definite state at a time.</p></article></section><aside><h2>Inspector</h2><p id=\"detail-copy\">Select a mode to inspect the difference.</p></aside></main></body></html>"
                    }]
                }),
                "section" => serde_json::json!({
                    "summary": "Extended the bounded quantum section.",
                    "notes": ["Added a scoped comparison section patch."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<section class=\"comparison-band\"><article><h2>Probability intuition</h2><p>Quantum systems distribute likelihood across outcomes before measurement.</p></article></section>"
                    }]
                }),
                "style" => serde_json::json!({
                    "summary": "Applied the slate quantum style system.",
                    "notes": ["Added restrained slate styling for the explainer."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<style>:root{color-scheme:dark;--bg:#13171d;--panel:#1b222c;--panel-border:#2b3644;--text:#e6ebf2;--muted:#97a5b8;--accent:#7dd3fc;}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);}main{display:grid;gap:18px;padding:24px;max-width:960px;margin:0 auto;}section,aside{background:var(--panel);border:1px solid var(--panel-border);border-radius:18px;padding:18px;}button{border:1px solid #36506a;background:#1d2a38;color:var(--text);border-radius:999px;padding:10px 14px;cursor:pointer;}button[aria-selected=\"true\"]{border-color:var(--accent);box-shadow:0 0 0 1px rgba(125,211,252,.35) inset;}p{color:var(--muted);}h1,h2{margin:0 0 10px;}svg{width:100%;height:auto;display:block;}</style>"
                    }]
                }),
                "interaction" => serde_json::json!({
                    "summary": "Wired the bounded quantum interaction loop.",
                    "notes": ["Added button-driven explanation updates."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<script>const summary=document.getElementById('mode-summary');const detail=document.getElementById('detail-copy');const controls=document.querySelectorAll('[data-mode]');controls.forEach((button)=>button.addEventListener('click',()=>{controls.forEach((control)=>control.setAttribute('aria-selected', String(control===button)));if(button.dataset.mode==='quantum'){summary.textContent='Quantum states can spread amplitude across multiple outcomes before measurement.';detail.textContent='Quantum state selected. Inspect how probabilities differ from a classical bit.';}else{summary.textContent='Classical bits stay in one definite state at a time.';detail.textContent='Classical mode selected. A bit resolves to one state immediately.';}}));</script>"
                    }]
                }),
                "repair" => serde_json::json!({
                    "summary": "Repair completed with a stronger quantum comparison.",
                    "notes": ["Added the missing qubit-focused comparison module."],
                    "operations": [{
                        "kind": "replace_file",
                        "path": "index.html",
                        "body": "<section data-verified-repair=\"quantum-state-compare\"><article><h2>Measurement comparison</h2><p>Quantum Qubit views show a weighted set of possible outcomes before measurement collapses the state.</p><div class=\"repair-switch\"><button type=\"button\">Classical Bit</button><button type=\"button\">Quantum Qubit</button></div><svg viewBox=\"0 0 320 160\" role=\"img\" aria-label=\"Classical versus quantum measurement distribution\"><rect x=\"34\" y=\"42\" width=\"54\" height=\"88\"></rect><rect x=\"132\" y=\"64\" width=\"54\" height=\"66\"></rect><rect x=\"230\" y=\"28\" width=\"54\" height=\"102\"></rect><text x=\"28\" y=\"148\">0</text><text x=\"126\" y=\"148\">0 / 1</text><text x=\"224\" y=\"148\">1</text></svg></article></section>"
                    }]
                }),
                "integrator" => serde_json::json!({
                    "summary": "No extra integrator pass was required.",
                    "notes": ["The local HTML swarm keeps the integrator in reserve."],
                    "operations": []
                }),
                "validation" => {
                    if prompt.contains("Repair completed with a stronger quantum comparison.")
                        || prompt.contains("qubit-focused comparison module")
                        || (prompt.contains("Measurement comparison")
                            && prompt.contains("Quantum Qubit"))
                    {
                        serde_json::json!({
                            "classification": "pass",
                            "requestFaithfulness": 5,
                            "conceptCoverage": 5,
                            "interactionRelevance": 5,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 5,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": null,
                            "rationale": "Acceptance cleared the repaired quantum explainer."
                        })
                    } else {
                        serde_json::json!({
                            "classification": "repairable",
                            "requestFaithfulness": 4,
                            "conceptCoverage": 4,
                            "interactionRelevance": 4,
                            "layoutCoherence": 4,
                            "visualHierarchy": 4,
                            "completeness": 3,
                            "genericShellDetected": false,
                            "trivialShellDetected": false,
                            "deservesPrimaryArtifactView": true,
                            "patchedExistingArtifact": null,
                            "continuityRevisionUx": null,
                            "strongestContradiction": "The explainer still needs a visible qubit measurement comparison.",
                            "rationale": "Acceptance wants a stronger qubit-focused comparison before primary view."
                        })
                    }
                }
                _ => return Err(VmError::HostError("unexpected Chat prompt".to_string())),
            };

            Ok(response.to_string().into_bytes())
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
    struct QuantumSwarmRegressionRenderEvaluator;

    #[async_trait]
    impl ChatArtifactRenderEvaluator for QuantumSwarmRegressionRenderEvaluator {
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
                .map(|file| {
                    file.body
                        .contains("data-verified-repair=\"quantum-state-compare\"")
                })
                .unwrap_or(false);

            Ok(Some(chat_test_render_evaluation(
                if repaired { 24 } else { 17 },
                true,
                if repaired {
                    Vec::new()
                } else {
                    vec![ChatArtifactRenderFinding {
                        code: "comparison_depth_thin".to_string(),
                        severity: ChatArtifactRenderFindingSeverity::Warning,
                        summary: "The first render still needs a stronger qubit comparison module."
                            .to_string(),
                    }]
                },
                vec![
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Desktop,
                        if repaired { 46 } else { 28 },
                        if repaired { 540 } else { 320 },
                        if repaired { 7 } else { 4 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Mobile,
                        if repaired { 42 } else { 24 },
                        if repaired { 482 } else { 274 },
                        if repaired { 7 } else { 4 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Interaction,
                        if repaired { 45 } else { 22 },
                        if repaired { 498 } else { 248 },
                        if repaired { 8 } else { 4 },
                    ),
                ],
            )))
        }
    }

    with_modal_first_html_env_async(|| async {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(QuantumSwarmRegressionRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                },
                role: "production",
                calls: calls.clone(),
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(QuantumSwarmRegressionRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some(
                        "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance"
                            .to_string(),
                    ),
                },
                role: "acceptance",
                calls: calls.clone(),
            });
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::FullyLocal,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            "Quantum computers interactive explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            None,
        )
        .await;
        let evaluator = QuantumSwarmRegressionRenderEvaluator;

        let bundle =
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                "Quantum computers interactive explainer",
                "Create an interactive HTML artifact that explains quantum computers",
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::AdaptiveWorkGraph,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("quantum swarm bundle should generate");

        assert!(bundle.candidate_summaries.is_empty());
        assert_eq!(
            bundle
                .swarm_plan
                .as_ref()
                .map(|plan| plan.execution_domain.as_str()),
            Some("chat_artifact")
        );
        assert_eq!(
            bundle
                .swarm_execution
                .as_ref()
                .map(|execution| execution.verification_status.as_str()),
            Some("pass")
        );
        assert_eq!(
            bundle
                .swarm_execution
                .as_ref()
                .map(|execution| execution.current_stage.as_str()),
            Some("ready")
        );
        assert_eq!(
            bundle.validation.classification,
            ChatArtifactValidationStatus::Pass
        );
        assert!(bundle
            .swarm_worker_receipts
            .iter()
            .any(|receipt| receipt.role == ChatArtifactWorkerRole::Repair
                && receipt.status == ChatArtifactWorkItemStatus::Succeeded));
        assert!(bundle
            .swarm_plan
            .as_ref()
            .is_some_and(|plan| plan
                .work_items
                .iter()
                .any(|item| item.id == "repair-pass-1"
                    && item.spawned_from_id.as_deref() == Some("repair"))));
        assert!(bundle
            .swarm_change_receipts
            .iter()
            .any(|receipt| receipt.work_item_id == "repair-pass-1" && receipt.operation_count > 0));
        assert!(bundle
            .swarm_merge_receipts
            .iter()
            .any(|receipt| receipt.work_item_id == "repair-pass-1"));
        assert!(bundle
            .swarm_verification_receipts
            .iter()
            .any(|receipt| receipt.kind == "artifact_validation"));
        assert!(bundle
            .execution_envelope
            .as_ref()
            .is_some_and(|envelope| envelope
                .graph_mutation_receipts
                .iter()
                .any(|receipt| receipt.mutation_kind == "subtask_spawned")));
        assert!(bundle
            .execution_envelope
            .as_ref()
            .is_some_and(|envelope| envelope
                .dispatch_batches
                .iter()
                .any(|batch| {
                    batch.status != "blocked"
                        && batch
                            .work_item_ids
                            .iter()
                            .filter(|id| id.starts_with("section-"))
                            .count()
                            >= 2
                })));
        assert!(bundle
            .render_evaluation
            .as_ref()
            .is_some_and(|evaluation| evaluation.captures.iter().any(|capture| {
                capture.viewport == ChatArtifactRenderCaptureViewport::Interaction
                    && capture.interactive_element_count >= 8
            })));
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html"
                && file.body.contains("data-verified-repair=\"quantum-state-compare\"")
                && file.body.contains("Quantum Qubit")
        }));

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|call| call == "production:brief"));
        assert!(recorded_calls.iter().any(|call| call == "production:skeleton"));
        assert!(recorded_calls.iter().any(|call| call == "production:style"));
        assert!(recorded_calls.iter().any(|call| call == "production:interaction"));
        assert!(recorded_calls.iter().any(|call| call == "production:repair"));
        assert!(!recorded_calls
            .iter()
            .any(|call| call.starts_with("acceptance:")));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":validation"))
                .count(),
            0
        );
    })
    .await;
}

#[tokio::test]
async fn local_html_swarm_strategy_breaks_complex_mission_control_query_into_iterative_waves() {
    #[derive(Clone)]
    struct ComplexMissionControlRuntime {
        provenance: ChatRuntimeProvenance,
        role: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        section_regions: Vec<String>,
        repair_region: String,
    }

    fn section_region_from_prompt(prompt: &str, section_regions: &[String]) -> Option<String> {
        let candidate = [
            "\"targetRegion\":\"",
            "\"targetRegion\": \"",
            "targetRegion\":\"",
            "targetRegion\": \"",
        ]
        .into_iter()
        .find_map(|needle| {
            let start = prompt.find(needle)? + needle.len();
            let rest = &prompt[start..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        });

        candidate.filter(|region| section_regions.iter().any(|entry| entry == region))
    }

    #[async_trait]
    impl InferenceRuntime for ComplexMissionControlRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            let prompt = decode_chat_test_prompt(input_context);
            let stage = if prompt.contains("typed artifact brief planner") {
                "brief".to_string()
            } else if prompt.contains("typed swarm Skeleton worker") {
                "skeleton".to_string()
            } else if prompt.contains("typed swarm SectionContent worker") {
                let region = section_region_from_prompt(&prompt, &self.section_regions)
                    .unwrap_or_else(|| "section:unknown".to_string());
                format!("section:{region}")
            } else if prompt.contains("typed swarm StyleSystem worker") {
                "style".to_string()
            } else if prompt.contains("typed swarm Interaction worker") {
                "interaction".to_string()
            } else if prompt.contains("typed swarm Repair worker") {
                "repair".to_string()
            } else if prompt.contains("typed swarm Integrator worker") {
                "integrator".to_string()
            } else if prompt.contains("typed artifact validation") {
                "validation".to_string()
            } else {
                "unknown".to_string()
            };

            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("{}:{stage}", self.role));

            let response = if stage == "brief" {
                serde_json::to_value(sample_complex_mission_control_brief()).expect("complex brief")
            } else if stage == "skeleton" {
                serde_json::json!({
                    "summary": "Mission control workbook shell",
                    "notes": ["Created the canonical mission-control HTML shell."],
                    "operations": [{
                        "kind": "create_file",
                        "path": "index.html",
                        "mime": "text/html",
                        "role": "primary",
                        "renderable": true,
                        "downloadable": true,
                        "encoding": "utf8",
                        "body": "<!doctype html><html><head><meta charset=\"utf-8\"><title>Post-quantum migration mission control</title></head><body><main><header><h1>Post-quantum migration mission control</h1><p>Track rollout phases, inspect risk posture, compare owner handoffs, and test cutover readiness from one control room artifact.</p><div class=\"mode-switch\"><button type=\"button\" data-panel=\"phases\" aria-selected=\"true\">Phases</button><button type=\"button\" data-panel=\"risk\" aria-selected=\"false\">Risk</button><button type=\"button\" data-panel=\"handoffs\" aria-selected=\"false\">Handoffs</button></div></header><aside class=\"detail-rail\"><h2>Operator detail</h2><p id=\"detail-copy\">Phases panel is selected with fleet rollout evidence visible on first paint.</p></aside></main></body></html>"
                    }]
                })
            } else if let Some(region) = stage.strip_prefix("section:") {
                let section_markup = if region == self.section_regions[0] {
                    "<section data-panel=\"phases\" class=\"mission-panel\"><article><h2>Fleet rollout phases</h2><p>Wave 1 upgrades signing infrastructure, Wave 2 rotates edge services, and Wave 3 retires the legacy fallback lane after verification clears.</p><ol><li><strong>Pilot:</strong> five canary regions with manual approval.</li><li><strong>Expansion:</strong> regional fleet rollout with live latency watch.</li><li><strong>Retire:</strong> remove the legacy signing path after rollback confidence stays green.</li></ol><div class=\"evidence-strip\"><button type=\"button\" data-detail=\"Pilot phase focuses on low-blast-radius rollout across five regions.\">Pilot focus</button><button type=\"button\" data-detail=\"Expansion phase compares readiness, latency, and rollback tolerance.\">Expansion focus</button></div></article></section>"
                } else if region == self.section_regions[1] {
                    "<section data-panel=\"risk\" class=\"mission-panel\"><article><h2>Cryptography risk drilldown</h2><p>Inspect signing libraries, vendor readiness, and support exposure before each cutover decision.</p><table><tr><th>Surface</th><th>Status</th><th>Risk</th></tr><tr><td>Identity signing</td><td>Library patched</td><td>Low</td></tr><tr><td>Mobile SDK</td><td>Vendor awaiting rollout</td><td>Medium</td></tr><tr><td>Support scripts</td><td>Legacy fallback active</td><td>High</td></tr></table><div class=\"risk-toggles\"><button type=\"button\" data-risk=\"identity\">Identity</button><button type=\"button\" data-risk=\"mobile\">Mobile</button><button type=\"button\" data-risk=\"support\">Support</button></div></article></section>"
                } else {
                    "<section data-panel=\"handoffs\" class=\"mission-panel\"><article><h2>Owner handoffs and cutover simulation</h2><p>Compare who owns preflight, cutover, and rollback, then simulate whether the current readiness state permits launch.</p><div class=\"ownership-grid\"><div><h3>Infrastructure</h3><p>Owns certificate rotation, cutover execution, and rollback thresholds.</p></div><div><h3>Product</h3><p>Owns rollout messaging, customer sequencing, and regional launch approval.</p></div><div><h3>Support</h3><p>Owns incident intake, escalation templates, and customer-safe fallback guidance.</p></div></div><div class=\"simulator\"><button type=\"button\" data-sim=\"hold\">Hold rollout</button><button type=\"button\" data-sim=\"launch\">Launch rollout</button></div><p id=\"sim-status\">Simulation idle. Review ownership signals before launch.</p></article></section>"
                };

                serde_json::json!({
                    "summary": format!("Filled {region} with request-grounded mission-control content."),
                    "notes": [format!("Patched scoped region {region}.")],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": region,
                        "body": section_markup
                    }]
                })
            } else if stage == "style" {
                serde_json::json!({
                    "summary": "Applied the mission-control style system.",
                    "notes": ["Added the shared slate hierarchy and compact chrome."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": "style-system",
                        "body": "<style>:root{color-scheme:dark;--bg:#11161c;--panel:#1a212b;--panel-alt:#151b24;--border:#2c3948;--text:#e8eef6;--muted:#94a3b8;--accent:#7dd3fc;--warn:#f59e0b;}*{box-sizing:border-box;}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);}main{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:18px;padding:22px;max-width:1200px;margin:0 auto;}header,section,aside{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:18px;}header{grid-column:1 / span 2;display:grid;gap:14px;}h1,h2,h3,p,ol{margin:0;}p,li,td,th{color:var(--muted);line-height:1.5;}table{width:100%;border-collapse:collapse;margin-top:12px;}th,td{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;}button{border:1px solid #31506d;background:#182635;color:var(--text);border-radius:999px;padding:9px 13px;font:inherit;cursor:pointer;}button[aria-selected=\"true\"],button[data-active=\"true\"]{border-color:var(--accent);box-shadow:0 0 0 1px rgba(125,211,252,.34) inset;}header .mode-switch,.evidence-strip,.risk-toggles,.simulator{display:flex;gap:10px;flex-wrap:wrap;}.mission-panel{display:grid;gap:14px;}.ownership-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;}.ownership-grid>div{background:var(--panel-alt);border:1px solid var(--border);border-radius:14px;padding:12px;}.detail-rail{position:sticky;top:18px;height:max-content;}#sim-status{padding:12px 14px;border-radius:14px;background:rgba(125,211,252,.08);border:1px solid rgba(125,211,252,.22);color:var(--text);}strong{color:var(--text);}</style>"
                    }]
                })
            } else if stage == "interaction" {
                serde_json::json!({
                    "summary": "Wired the mission-control interaction grammar.",
                    "notes": ["Bound the control bar, detail rail, risk drilldown, and cutover simulator."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": "interaction",
                        "body": "<script>const detail=document.getElementById('detail-copy');const panels=[...document.querySelectorAll('.mission-panel')];const tabButtons=[...document.querySelectorAll('button[data-panel]')];tabButtons.forEach((button)=>button.addEventListener('click',()=>{const target=button.dataset.panel;tabButtons.forEach((control)=>control.setAttribute('aria-selected',String(control===button)));panels.forEach((panel)=>panel.dataset.active=String(panel.dataset.panel===target));detail.textContent=target==='phases'?'Phases panel selected. Inspect the rollout wave timing and the readiness evidence strip.':target==='risk'?'Risk panel selected. Compare surface readiness and vendor exposure before cutover.':'Handoffs panel selected. Compare owners and simulate whether launch can proceed.';}));document.querySelectorAll('[data-detail]').forEach((button)=>button.addEventListener('click',()=>{detail.textContent=button.dataset.detail;}));document.querySelectorAll('[data-risk]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-risk]').forEach((control)=>control.dataset.active=String(control===button));detail.textContent=button.dataset.risk==='identity'?'Identity path is patched and ready for early rollout.':button.dataset.risk==='mobile'?'Mobile path is blocked on vendor rollout timing.':'Support path still depends on the legacy fallback lane.';}));const simStatus=document.getElementById('sim-status');document.querySelectorAll('[data-sim]').forEach((button)=>button.addEventListener('click',()=>{document.querySelectorAll('[data-sim]').forEach((control)=>control.dataset.active=String(control===button));if(button.dataset.sim==='launch'){simStatus.textContent='Launch simulation: proceed only if vendor readiness and rollback staffing both stay green.';detail.textContent='Launch simulation selected. Confirm support staffing and vendor readiness before go-live.';}else{simStatus.textContent='Hold simulation: keep the rollout paused until support scripts leave the legacy lane.';detail.textContent='Hold simulation selected. Remediate the support fallback dependency before launch.';}}));</script>"
                    }]
                })
            } else if stage == "repair" {
                serde_json::json!({
                    "summary": "Added the missing rollback playbook detail.",
                    "notes": ["Repair added the cited fallback playbook depth."],
                    "operations": [{
                        "kind": "replace_region",
                        "path": "index.html",
                        "regionId": self.repair_region,
                        "body": "<section data-panel=\"handoffs\" class=\"mission-panel\" data-repaired=\"rollback-playbook\"><article><h2>Owner handoffs and cutover simulation</h2><p>Compare who owns preflight, cutover, and rollback, then simulate whether the current readiness state permits launch.</p><div class=\"ownership-grid\"><div><h3>Infrastructure</h3><p>Owns certificate rotation, cutover execution, and rollback thresholds.</p></div><div><h3>Product</h3><p>Owns rollout messaging, customer sequencing, and regional launch approval.</p></div><div><h3>Support</h3><p>Owns incident intake, escalation templates, and customer-safe fallback guidance.</p></div></div><section class=\"rollback-playbook\"><h3>Rollback playbook</h3><p>If vendor readiness drops or support fallback remains red, freeze launch, return traffic to the legacy signer, and page the owning leads in the order shown above.</p></section><div class=\"simulator\"><button type=\"button\" data-sim=\"hold\">Hold rollout</button><button type=\"button\" data-sim=\"launch\">Launch rollout</button></div><p id=\"sim-status\">Simulation idle. Review ownership signals before launch.</p></article></section>"
                    }]
                })
            } else if stage == "integrator" {
                serde_json::json!({
                    "summary": "Integrator stayed in reserve.",
                    "notes": ["Local HTML path keeps the integrator as a reserve seam."],
                    "operations": []
                })
            } else if stage == "validation" {
                let repaired_already = self
                    .calls
                    .lock()
                    .expect("calls lock")
                    .iter()
                    .any(|call| call == "production:repair")
                    || prompt.contains("data-repaired=\"rollback-playbook\"")
                    || prompt.contains("Rollback playbook");
                if repaired_already {
                    serde_json::json!({
                        "classification": "pass",
                        "requestFaithfulness": 5,
                        "conceptCoverage": 5,
                        "interactionRelevance": 5,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 5,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": null,
                        "rationale": "The repaired mission-control artifact now covers rollout, risk, ownership, and rollback decisions with visible interactions."
                    })
                } else {
                    serde_json::json!({
                        "classification": "repairable",
                        "requestFaithfulness": 4,
                        "conceptCoverage": 4,
                        "interactionRelevance": 4,
                        "layoutCoherence": 4,
                        "visualHierarchy": 4,
                        "completeness": 3,
                        "genericShellDetected": false,
                        "trivialShellDetected": false,
                        "deservesPrimaryArtifactView": true,
                        "patchedExistingArtifact": null,
                        "continuityRevisionUx": null,
                        "strongestContradiction": "The artifact still needs an explicit rollback playbook inside the owner handoff surface.",
                        "rationale": "The control room is strong, but the launch decision loop is incomplete without a visible rollback playbook."
                    })
                }
            } else {
                return Err(VmError::HostError("unexpected Chat prompt".to_string()));
            };

            Ok(response.to_string().into_bytes())
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
    struct ComplexMissionControlRenderEvaluator;

    #[async_trait]
    impl ChatArtifactRenderEvaluator for ComplexMissionControlRenderEvaluator {
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
                .map(|file| file.body.contains("data-repaired=\"rollback-playbook\""))
                .unwrap_or(false);

            Ok(Some(chat_test_render_evaluation(
                if repaired { 32 } else { 24 },
                true,
                if repaired {
                    Vec::new()
                } else {
                    vec![ChatArtifactRenderFinding {
                        code: "rollback_playbook_missing".to_string(),
                        severity: ChatArtifactRenderFindingSeverity::Warning,
                        summary: "The first render still needs an explicit rollback playbook in the handoff surface.".to_string(),
                    }]
                },
                vec![
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Desktop,
                        if repaired { 58 } else { 42 },
                        if repaired { 910 } else { 680 },
                        if repaired { 12 } else { 8 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Mobile,
                        if repaired { 51 } else { 36 },
                        if repaired { 840 } else { 590 },
                        if repaired { 11 } else { 7 },
                    ),
                    chat_test_render_capture(
                        ChatArtifactRenderCaptureViewport::Interaction,
                        if repaired { 56 } else { 40 },
                        if repaired { 876 } else { 622 },
                        if repaired { 13 } else { 8 },
                    ),
                ],
            )))
        }
    }

    with_modal_first_html_env_async(|| async {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_complex_mission_control_brief();
        let blueprint = derive_chat_artifact_blueprint(&request, &brief);
        let swarm_plan = super::generation::build_chat_artifact_swarm_plan(
            &request,
            Some(&blueprint),
            &brief,
            ChatExecutionStrategy::AdaptiveWorkGraph,
        );
        let section_regions = swarm_plan
            .work_items
            .iter()
            .filter(|item| item.role == ChatArtifactWorkerRole::SectionContent)
            .flat_map(|item| item.write_regions.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            section_regions.len(),
            3,
            "complex HTML briefs should coalesce into three bounded section workers"
        );
        let repair_region = section_regions
            .last()
            .cloned()
            .expect("repair region should exist");

        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(ComplexMissionControlRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
                },
                role: "production",
                calls: calls.clone(),
                section_regions: section_regions.clone(),
                repair_region: repair_region.clone(),
            });
        let acceptance_runtime: Arc<dyn InferenceRuntime> =
            Arc::new(ComplexMissionControlRuntime {
                provenance: ChatRuntimeProvenance {
                    kind: ChatRuntimeProvenanceKind::RealLocalRuntime,
                    label: "openai-compatible".to_string(),
                    model: Some("qwen3.5:9b".to_string()),
                    endpoint: Some(
                        "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance"
                            .to_string(),
                    ),
                },
                role: "acceptance",
                calls: calls.clone(),
                section_regions: section_regions.clone(),
                repair_region: repair_region.clone(),
            });
        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request,
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::FullyLocal,
        );
        let planning_context = planned_prepared_context_with_runtime_plan(
            &runtime_plan,
            "Post-quantum migration mission control",
            "Create an interactive HTML mission control artifact for a post-quantum migration program that lets operators compare rollout phases, inspect cryptography risk, simulate cutover decisions, and review owner handoffs with a visible rollback playbook.",
            &request,
            None,
        )
        .await;
        let evaluator = ComplexMissionControlRenderEvaluator;

        let bundle =
            generate_chat_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
                runtime_plan,
                "Post-quantum migration mission control",
                "Create an interactive HTML mission control artifact for a post-quantum migration program that lets operators compare rollout phases, inspect cryptography risk, simulate cutover decisions, and review owner handoffs with a visible rollback playbook.",
                &request,
                None,
                &planning_context,
                ChatExecutionStrategy::AdaptiveWorkGraph,
                Some(&evaluator),
                None,
                None,
            )
            .await
            .expect("complex mission-control swarm bundle should generate");

        assert!(bundle.candidate_summaries.is_empty());
        assert_eq!(
            bundle.validation.classification,
            ChatArtifactValidationStatus::Pass
        );

        let envelope = bundle
            .execution_envelope
            .as_ref()
            .expect("execution envelope");
        assert_eq!(
            envelope.execution_summary.as_ref().map(|summary| summary.current_stage.as_str()),
            Some("ready")
        );
        assert_eq!(
            envelope.execution_summary.as_ref().map(|summary| summary.verification_status.as_str()),
            Some("pass")
        );
        assert!(
            envelope.dispatch_batches.len() >= 5,
            "complex local HTML should require several iterative dispatch waves"
        );
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().filter(|id| id.starts_with("section-")).count() == 2
                && !batch.deferred_work_item_ids.is_empty()
        }));
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().filter(|id| id.starts_with("section-")).count() == 1
                && batch.deferred_work_item_ids.is_empty()
        }));
        assert!(envelope.dispatch_batches.iter().any(|batch| {
            batch.work_item_ids.iter().any(|id| id == "style-system")
                && batch.work_item_ids.iter().any(|id| id == "interaction")
        }));
        assert!(envelope
            .graph_mutation_receipts
            .iter()
            .any(|receipt| receipt.mutation_kind == "subtask_spawned"));
        assert!(envelope
            .repair_receipts
            .iter()
            .any(|receipt| receipt.status == "pass"
                && receipt
                    .work_item_ids
                    .iter()
                    .any(|id| id == "repair-pass-1")));
        assert!(
            envelope
                .budget_summary
                .as_ref()
                .and_then(|summary| summary.token_budget)
                .unwrap_or_default()
                > 0
        );
        assert!(
            envelope
                .budget_summary
                .as_ref()
                .and_then(|summary| summary.dispatched_worker_count)
                .unwrap_or_default()
                >= 7
        );

        let section_receipts = bundle
            .swarm_worker_receipts
            .iter()
            .filter(|receipt| receipt.role == ChatArtifactWorkerRole::SectionContent)
            .collect::<Vec<_>>();
        assert_eq!(section_receipts.len(), 3);
        assert!(section_receipts.iter().all(|receipt| {
            receipt.status == ChatArtifactWorkItemStatus::Succeeded
                && receipt.write_regions.len() == 1
        }));
        assert!(bundle
            .swarm_change_receipts
            .iter()
            .filter(|receipt| receipt.work_item_id.starts_with("section-"))
            .all(|receipt| receipt.operation_count == 1 && receipt.touched_regions.len() == 1));
        assert!(bundle
            .swarm_verification_receipts
            .iter()
            .any(|receipt| receipt.kind == "artifact_validation"));
        assert!(bundle.winner.files.iter().any(|file| {
            file.path == "index.html"
                && file.body.contains("Fleet rollout phases")
                && file.body.contains("Cryptography risk drilldown")
                && file.body.contains("Owner handoffs and cutover simulation")
                && file.body.contains("Rollback playbook")
                && file.body.contains("data-repaired=\"rollback-playbook\"")
        }));
        assert!(bundle
            .render_evaluation
            .as_ref()
            .is_some_and(|evaluation| evaluation.captures.iter().any(|capture| {
                capture.viewport == ChatArtifactRenderCaptureViewport::Interaction
                    && capture.interactive_element_count >= 13
            })));

        let recorded_calls = calls.lock().expect("calls lock").clone();
        assert!(recorded_calls.iter().any(|call| call == "production:brief"));
        assert!(recorded_calls.iter().any(|call| call == "production:skeleton"));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.starts_with("production:section:section:"))
                .count(),
            3
        );
        assert!(recorded_calls.iter().any(|call| call == "production:style"));
        assert!(recorded_calls.iter().any(|call| call == "production:interaction"));
        assert!(recorded_calls.iter().any(|call| call == "production:repair"));
        assert!(!recorded_calls
            .iter()
            .any(|call| call.starts_with("acceptance:")));
        assert_eq!(
            recorded_calls
                .iter()
                .filter(|call| call.ends_with(":validation"))
                .count(),
            0
        );
    })
    .await;
}
