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

