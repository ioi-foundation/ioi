use super::*;
use ioi_api::studio::{compile_studio_artifact_ir, derive_studio_artifact_blueprint};
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactFileRole,
    StudioArtifactPersistenceMode, StudioExecutionSubstrate, StudioOutcomeArtifactScope,
    StudioOutcomeArtifactVerificationRequest, StudioPresentationSurface,
};

fn interactive_html_request() -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    }
}

fn document_html_request() -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Document,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    }
}

fn interactive_html_brief() -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "inspect an interactive launch explainer".to_string(),
        subject_domain: "launch review".to_string(),
        artifact_thesis:
            "Keep the first paint visible while the control bar switches between evidence views."
                .to_string(),
        required_concepts: vec!["overview".to_string(), "metrics".to_string()],
        required_interactions: vec!["view switching".to_string()],
        query_profile: None,
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["launch evidence".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["comparison panel".to_string()],
    }
}

fn document_markdown_request() -> StudioOutcomeArtifactRequest {
    StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Document,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::Markdown,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    }
}

fn document_markdown_brief() -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "engineers".to_string(),
        job_to_be_done: "explain HTTP request lifecycle in five bullets".to_string(),
        subject_domain: "HTTP request lifecycle".to_string(),
        artifact_thesis: "A HTTP request lifecycle document".to_string(),
        required_concepts: vec![
            "HTTP request lifecycle".to_string(),
            "HTTP request lifecycle summary".to_string(),
            "HTTP request lifecycle evidence".to_string(),
        ],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: vec!["grounded document clarity".to_string()],
        factual_anchors: vec![
            "HTTP request lifecycle".to_string(),
            "HTTP request lifecycle examples".to_string(),
        ],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["HTTP request lifecycle evidence".to_string()],
    }
}

fn viewport_capture(
    viewport: StudioArtifactRenderCaptureViewport,
    visible_text_chars: usize,
    interactive_element_count: usize,
) -> ViewportCapture {
    ViewportCapture {
        capture: StudioArtifactRenderCapture {
            viewport,
            width: 1440,
            height: 960,
            screenshot_sha256: format!("sha-{viewport:?}"),
            screenshot_byte_count: 1024,
            visible_element_count: 18,
            visible_text_chars,
            interactive_element_count,
            screenshot_changed_from_previous: false,
        },
        dom: DomCaptureMetrics {
            visible_element_count: 18,
            visible_text_chars,
            interactive_element_count,
            section_count: 3,
            response_region_count: 0,
            evidence_surface_count: 2,
            actionable_affordance_count: interactive_element_count,
            active_affordance_count: 0,
            heading_count: 2,
            main_present: true,
            body_font_size: 16.0,
            heading_font_size: 28.0,
            avg_text_contrast: 5.0,
            min_text_contrast: 4.5,
            font_family_count: 2,
            dominant_left_alignment_ratio: 0.7,
            gap_consistency: 0.7,
            overlap_count: 0,
            response_region_text: None,
        },
        analysis: ScreenshotAnalysis {
            occupied_ratio: 0.35,
            luminance_stddev: 0.2,
        },
    }
}

#[test]
fn markdown_blueprint_consistency_accepts_dense_static_document_surfaces() {
    let request = document_markdown_request();
    let brief = document_markdown_brief();
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let mut desktop = viewport_capture(StudioArtifactRenderCaptureViewport::Desktop, 420, 0);
    desktop.dom.section_count = 1;
    desktop.dom.evidence_surface_count = 0;
    let mut mobile = viewport_capture(StudioArtifactRenderCaptureViewport::Mobile, 320, 0);
    mobile.dom.section_count = 1;
    mobile.dom.evidence_surface_count = 0;

    let score = score_blueprint_consistency(
        &brief,
        Some(&blueprint),
        Some(&artifact_ir),
        &desktop,
        &mobile,
        None,
        false,
    );

    assert_eq!(score, 5);
}

#[tokio::test]
async fn browser_render_evaluator_captures_boot_syntax_errors() {
    let evaluator = BrowserStudioArtifactRenderEvaluator::default();
    let request = interactive_html_request();
    let brief = interactive_html_brief();
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Interactive launch explainer".to_string(),
        notes: vec!["syntax regression".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><head><meta charset=\"utf-8\"><style>body{margin:0;font-family:Georgia,serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside{background:#fffdf8;border:1px solid #d5c7ad;border-radius:16px;padding:1rem;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}[hidden]{display:none !important;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics without leaving the artifact surface.</p><div><button type=\"button\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"metrics\">Metrics</button></div></section><section id=\"overview-panel\" data-view-panel=\"overview\"><h2>Overview</h2><p>Readiness evidence stays visible on first paint.</p></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><h2>Metrics</h2><p>Metrics evidence becomes visible after interaction.</p></section><aside><p id=\"detail-copy\">Overview selected.</p></aside></main><script>const detail=document.getElementById('detail-copy');const panels=Array.from(document.querySelectorAll('[data-view-panel]'));document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{panels.forEach((panel)=>{panel.hidden=panel.dataset.viewPanel!==button.dataset.view;});detail.textContent=button.dataset.view + ' selected';});</script></body></html>".to_string(),
        }],
    };

    let render_evaluation = evaluator
        .evaluate_candidate_render(&request, &brief, None, None, None, &candidate)
        .await
        .expect("render evaluation should succeed")
        .expect("html render evaluation should be supported");

    let boot_obligation = render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| obligation.obligation_id == "runtime_boot_clean")
        .expect("runtime boot obligation");

    assert_eq!(
        boot_obligation.status,
        StudioArtifactAcceptanceObligationStatus::Failed
    );
    assert!(
        boot_obligation
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("SyntaxError")),
        "expected boot syntax error detail, got {:?}",
        boot_obligation.detail
    );
    assert!(render_evaluation.findings.iter().any(|finding| {
        finding.code == "runtime_boot_clean" && finding.summary.contains("SyntaxError")
    }));
}

#[tokio::test]
async fn browser_render_evaluator_blocks_dead_controls() {
    let evaluator = BrowserStudioArtifactRenderEvaluator::default();
    let request = interactive_html_request();
    let brief = interactive_html_brief();
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Interactive explainer with dead controls".to_string(),
        notes: vec!["no-op controls".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><head><meta charset=\"utf-8\"><style>body{margin:0;font-family:Georgia,serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside{background:#fffdf8;border:1px solid #d5c7ad;border-radius:16px;padding:1rem;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}[hidden]{display:none !important;}</style></head><body><main><section><h1>Launch review</h1><p>Compare readiness and metrics without leaving the artifact surface.</p><div><button type=\"button\" data-view=\"overview\">Overview</button><button type=\"button\" data-view=\"metrics\">Metrics</button></div></section><section id=\"overview-panel\" data-view-panel=\"overview\"><h2>Overview</h2><p>Readiness evidence stays visible on first paint.</p></section><section id=\"metrics-panel\" data-view-panel=\"metrics\" hidden><h2>Metrics</h2><p>Metrics evidence should become visible after interaction.</p></section><aside><p id=\"detail-copy\">Overview selected.</p></aside><script>document.querySelectorAll('button[data-view]').forEach((button)=>button.addEventListener('click',()=>{button.setAttribute('data-clicked','true');}));</script></main></body></html>".to_string(),
        }],
    };

    let render_evaluation = evaluator
        .evaluate_candidate_render(&request, &brief, None, None, None, &candidate)
        .await
        .expect("render evaluation should succeed")
        .expect("html render evaluation should be supported");

    let controls_obligation = render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| obligation.obligation_id == "controls_execute_cleanly")
        .expect("controls_execute_cleanly obligation");
    assert_eq!(
        controls_obligation.status,
        StudioArtifactAcceptanceObligationStatus::Failed
    );

    let failed_witness = render_evaluation
        .execution_witnesses
        .iter()
        .find(|witness| witness.status == StudioArtifactExecutionWitnessStatus::Failed)
        .expect("failed witness for dead control");
    assert!(failed_witness
        .summary
        .contains("did not change visible artifact state"));
    assert!(render_evaluation.findings.iter().any(|finding| {
        finding.code == "controls_execute_cleanly" && finding.summary.contains("failedWitnesses=")
    }));
}

#[tokio::test]
async fn browser_render_evaluator_does_not_require_interaction_contract_for_document_html() {
    let evaluator = BrowserStudioArtifactRenderEvaluator::default();
    let request = document_html_request();
    let brief = StudioArtifactBrief {
        audience: "learners".to_string(),
        job_to_be_done: "read a document about quantum computers".to_string(),
        subject_domain: "quantum computing".to_string(),
        artifact_thesis: "Explain the topic clearly in one HTML document.".to_string(),
        required_concepts: vec!["qubits".to_string(), "superposition".to_string()],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["quantum computers".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["quantum computers basics".to_string()],
    };
    let candidate = StudioGeneratedArtifactPayload {
        summary: "Document HTML with incidental buttons".to_string(),
        notes: vec!["controls are incidental, not contract-defining".to_string()],
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><head><meta charset=\"utf-8\"><style>body{margin:0;font-family:Georgia,serif;background:#f6f1e7;color:#1b1a17;}main{display:grid;gap:1rem;padding:1.5rem;}section,aside{background:#fffdf8;border:1px solid #d5c7ad;border-radius:16px;padding:1rem;}button{border:1px solid #8c6f48;background:#f0dfc0;border-radius:999px;padding:0.45rem 0.85rem;}</style></head><body><main><section><h1>Quantum computers explained</h1><p>Quantum computers use qubits and interference to explore many possibilities before measurement.</p><div><button type=\"button\" onclick=\"setMode('classical')\">Classical mode</button><button type=\"button\" onclick=\"setMode('quantum')\">Quantum mode</button></div></section><section><h2>Key idea</h2><p>Superposition keeps amplitudes in play until measurement collapses a visible answer.</p></section></main></body></html>".to_string(),
        }],
    };

    let render_evaluation = evaluator
        .evaluate_candidate_render(&request, &brief, None, None, None, &candidate)
        .await
        .expect("render evaluation should succeed")
        .expect("html render evaluation should be supported");

    assert!(!render_evaluation
        .acceptance_obligations
        .iter()
        .any(|obligation| obligation.obligation_id == "controls_execute_cleanly"));
    assert!(!render_evaluation
        .findings
        .iter()
        .any(|finding| finding.code == "controls_execute_cleanly"));
    assert!(!render_evaluation.interaction_capture_attempted);
    assert!(render_evaluation.execution_witnesses.is_empty());
}

#[test]
fn runtime_boot_clean_obligation_applies_to_all_browser_backed_renderers() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Visual,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::Svg,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "inspect a visual artifact".to_string(),
        subject_domain: "launch review".to_string(),
        artifact_thesis: "Render the visual cleanly on first paint.".to_string(),
        required_concepts: vec!["timeline".to_string()],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["launch evidence".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["chart".to_string()],
    };
    let desktop = viewport_capture(StudioArtifactRenderCaptureViewport::Desktop, 120, 0);
    let mobile = viewport_capture(StudioArtifactRenderCaptureViewport::Mobile, 110, 0);
    let acceptance_policy =
        build_studio_artifact_render_acceptance_policy(&request, &brief, None, None);
    let render_evaluation = score_render_evaluation(
        &request,
        &brief,
        None,
        None,
        &desktop,
        &mobile,
        None,
        false,
        &["SyntaxError: missing ) after argument list".to_string()],
        &[],
        acceptance_policy,
    );

    let boot_obligation = render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| obligation.obligation_id == "runtime_boot_clean")
        .expect("runtime boot obligation");
    assert_eq!(
        boot_obligation.status,
        StudioArtifactAcceptanceObligationStatus::Failed
    );
    assert!(render_evaluation
        .findings
        .iter()
        .any(|finding| finding.code == "runtime_boot_clean"));
    assert!(!render_evaluation
        .acceptance_obligations
        .iter()
        .any(|obligation| obligation.obligation_id == "controls_execute_cleanly"));
}
