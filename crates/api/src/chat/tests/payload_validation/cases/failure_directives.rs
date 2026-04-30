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

