use super::evidence::*;
use super::manifest::*;
use super::runtime::*;
use super::*;
use axum::{extract::State, routing::post, Json, Router};
use ioi_api::studio::{
    pdf_artifact_bytes, StudioArtifactJudgeClassification, StudioArtifactSelectionTarget,
    StudioGeneratedArtifactFile, StudioGeneratedArtifactPayload,
};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, HttpInferenceRuntime};
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactFailure, StudioArtifactFailureKind, StudioArtifactFileRole,
    StudioArtifactLifecycleState, StudioArtifactManifest, StudioArtifactManifestFile,
    StudioArtifactManifestTab, StudioArtifactManifestVerification, StudioArtifactTabKind,
    StudioArtifactVerificationStatus, StudioOutcomeArtifactRequest, StudioRuntimeProvenance,
    StudioRuntimeProvenanceKind,
};
use serde_json::{json, Value};
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn strong_markdown_fixture() -> &'static str {
    "# Quarterly Release Checklist

## Scope
This artifact captures the release checklist for the quarterly launch. It outlines the
readiness gates, launch owners, rollback expectations, customer communication work, and
post-launch verification steps that must be complete before the release can be presented
as successful in Studio.

## Readiness Gates
- Confirm the release branch is frozen and tagged.
- Verify migration notes, dependency updates, and environment changes.
- Validate the primary render output in Studio and confirm evidence is attached.
- Confirm rollback instructions, validation checks, and monitoring thresholds are current.

## Launch Sequence
1. Announce the release window to support and go-to-market partners.
2. Apply migrations and ship the staged artifact build.
3. Verify the production surface, source payload, and download package.
4. Capture launch evidence, customer-facing notes, and on-call ownership.

## Verification
The artifact is only considered ready when render verification passes, source files are
present for inspection, and the evidence summary points to real materialized outputs
rather than worker prose or placeholder copy.
"
}

fn sample_manifest() -> StudioArtifactManifest {
    StudioArtifactManifest {
        artifact_id: "artifact_123".to_string(),
        title: "Quarterly Report".to_string(),
        artifact_class: StudioArtifactClass::Document,
        renderer: StudioRendererKind::Markdown,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::Markdown),
            file_path: Some("report.md".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "report.md".to_string(),
            mime: "text/markdown".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Render contract verified.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    }
}

fn blocked_failure_manifest() -> StudioArtifactManifest {
    let failure = StudioArtifactFailure {
        kind: StudioArtifactFailureKind::InferenceUnavailable,
        code: "inference_unavailable".to_string(),
        message: "Studio cannot route or materialize artifacts because inference is unavailable."
            .to_string(),
    };
    let provenance = StudioRuntimeProvenance {
        kind: StudioRuntimeProvenanceKind::InferenceUnavailable,
        label: "inference unavailable".to_string(),
        model: None,
        endpoint: None,
    };
    StudioArtifactManifest {
        artifact_id: "artifact_blocked".to_string(),
        title: "Blocked artifact".to_string(),
        artifact_class: StudioArtifactClass::ReportBundle,
        renderer: StudioRendererKind::BundleManifest,
        primary_tab: "evidence".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "evidence".to_string(),
            label: "Evidence".to_string(),
            kind: StudioArtifactTabKind::Evidence,
            renderer: None,
            file_path: None,
            lens: Some("evidence".to_string()),
        }],
        files: Vec::new(),
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Blocked,
            lifecycle_state: StudioArtifactLifecycleState::Blocked,
            summary: failure.message.clone(),
            production_provenance: Some(provenance.clone()),
            acceptance_provenance: Some(provenance),
            failure: Some(failure),
        },
        storage: None,
    }
}

#[test]
fn runtime_provenance_matches_ignores_lane_only_endpoint_tags() {
    let production = StudioRuntimeProvenance {
        kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
        label: "openai-compatible".to_string(),
        model: Some("qwen3:8b".to_string()),
        endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
    };
    let acceptance = StudioRuntimeProvenance {
        kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
        label: "openai-compatible".to_string(),
        model: Some("qwen3:8b".to_string()),
        endpoint: Some("http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string()),
    };

    assert!(runtime_provenance_matches(&production, &acceptance));
}

#[test]
fn validate_manifest_rejects_missing_primary_tab() {
    let mut manifest = sample_manifest();
    manifest.primary_tab = "source".to_string();
    let errors = validate_manifest(&manifest);
    assert!(errors
        .iter()
        .any(|error| error.contains("primaryTab 'source' does not match any tab id")));
}

#[test]
fn generate_prefers_distinct_local_acceptance_runtime_for_route() {
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        "http://127.0.0.1:11434/v1/chat/completions".to_string(),
        "ollama".to_string(),
        "qwen2.5:14b".to_string(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        "http://127.0.0.1:11434/v1/chat/completions".to_string(),
        "ollama".to_string(),
        "qwen2.5:7b".to_string(),
    ));

    let selected = select_generate_route_runtime(&production_runtime, &acceptance_runtime);
    let selected_provenance = selected.studio_runtime_provenance();

    assert_eq!(
        selected_provenance.kind,
        StudioRuntimeProvenanceKind::RealLocalRuntime
    );
    assert_eq!(selected_provenance.model.as_deref(), Some("qwen2.5:7b"));
}

#[test]
fn validate_materialized_markdown_contract_reads_real_file() -> Result<()> {
    let root = tempdir()?;
    fs::write(root.path().join("report.md"), strong_markdown_fixture())?;
    let errors = validate_materialized_files(&sample_manifest(), root.path());
    assert!(
        errors.is_empty(),
        "unexpected validation errors: {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_pdf_contract_rejects_placeholder_brief_copy() -> Result<()> {
    let root = tempdir()?;
    let pdf = pdf_artifact_bytes(
        "Launch brief",
        "Executive Summary\n\nThis launch brief gives stakeholders a quick read on scope, audience, positioning, rollout timing, success measures, and operating risks before release approval.\n\nProject Scope\n\n- Objective: [Detailed objective]\n- Deliverables: [Detailed deliverables]\n- Regions: North America and Europe.\n\nTarget Audience\n\n- Audience: [Detailed audience segment]\n- Need: Faster retailer onboarding and clearer product positioning.\n\nMarketing Strategy\n\n- Channels: [Detailed channel plan]\n- Messaging: Trust, convenience, and measurable outcomes.\n\nTimeline and Milestones\n\n- Kickoff: [Detailed kickoff date]\n- Launch window: [Detailed launch window]\n- Review: [Detailed review milestone]\n\nNext Steps and Risks\n\n- Action: Align legal, marketing, and support owners this week.\n- Risk: [Detailed risk note]",
    );
    fs::write(root.path().join("brief.pdf"), pdf)?;

    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_pdf".to_string(),
        title: "Launch brief".to_string(),
        artifact_class: StudioArtifactClass::Document,
        renderer: StudioRendererKind::PdfEmbed,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::PdfEmbed),
            file_path: Some("brief.pdf".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "brief.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Render contract verified.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    };

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(errors
        .iter()
        .any(|error| error.contains("placeholder-grade copy")));
    Ok(())
}

#[test]
fn validate_materialized_pdf_contract_accepts_heading_structured_brief_copy() -> Result<()> {
    let root = tempdir()?;
    let pdf = pdf_artifact_bytes(
        "Launch brief",
        "Executive Summary\n\nThis launch brief summarizes the project scope, target audience, marketing strategy, timeline, milestones, and operational risks for stakeholders reviewing the artifact stage.\n\nProject Scope\n\n- Objective: Introduce product X in selected regions.\n- Deliverables: launch plan, marketing assets, and support readiness.\n\nTarget Audience\n\n- Audience: Tech-savvy professionals ages 18-35.\n- Regions: North America and Europe.\n\nMarketing Strategy\n\n- Channels: Social campaigns, partnerships, and email.\n- Budget: Initial launch allocation and milestone tracking.\n\nTimeline and Milestones\n\n- Q1: Internal readiness and testing.\n- Q2: Beta rollout and revisions.\n- Q3: Regional launch and verification.\n\nNext Steps and Risks\n\n- Finalize collateral.\n- Track supply chain and readiness risks.",
    );
    fs::write(root.path().join("brief.pdf"), pdf)?;

    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_pdf".to_string(),
        title: "Launch brief".to_string(),
        artifact_class: StudioArtifactClass::Document,
        renderer: StudioRendererKind::PdfEmbed,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::PdfEmbed),
            file_path: Some("brief.pdf".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "brief.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Render contract verified.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    };

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors.is_empty(),
        "unexpected validation errors: {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_manifest_accepts_truthful_blocked_failure_envelope() {
    let errors = validate_manifest(&blocked_failure_manifest());
    assert!(
        errors.is_empty(),
        "blocked failure manifest should remain valid evidence, got {errors:?}"
    );
}

#[test]
fn validate_materialized_failure_envelope_skips_primary_render_contract() -> Result<()> {
    let root = tempdir()?;
    let errors = validate_materialized_files(&blocked_failure_manifest(), root.path());
    assert!(
        errors.is_empty(),
        "blocked failure envelope should not demand a renderable file, got {errors:?}"
    );
    Ok(())
}

#[test]
fn parse_selected_targets_accepts_typed_json() -> Result<()> {
    let parsed = super::generation::parse_selected_targets(&[r#"{"sourceSurface":"render","path":"index.html","label":"chart section","snippet":"Hero chart"}"#.to_string()])?;
    assert_eq!(
        parsed,
        vec![StudioArtifactSelectionTarget {
            source_surface: "render".to_string(),
            path: Some("index.html".to_string()),
            label: "chart section".to_string(),
            snippet: "Hero chart".to_string(),
        }]
    );
    Ok(())
}

#[test]
fn apply_selected_targets_to_loaded_refinement_overlays_existing_selection() -> Result<()> {
    let mut refinement = Some(super::types::LoadedRefinementEvidence {
        artifact_id: Some("artifact-1".to_string()),
        revision_id: Some("revision-1".to_string()),
        title: "Dog shampoo rollout".to_string(),
        summary: "Current artifact".to_string(),
        renderer: StudioRendererKind::HtmlIframe,
        files: Vec::new(),
        selected_targets: Vec::new(),
        taste_memory: None,
    });
    let selected_targets = vec![StudioArtifactSelectionTarget {
        source_surface: "render".to_string(),
        path: Some("index.html".to_string()),
        label: "chart section".to_string(),
        snippet: "Hero chart".to_string(),
    }];

    super::generation::apply_selected_targets_to_loaded_refinement(
        &mut refinement,
        selected_targets.as_slice(),
    )?;

    assert_eq!(
        refinement
            .as_ref()
            .expect("refinement should remain available")
            .selected_targets,
        selected_targets
    );
    Ok(())
}

#[tokio::test]
async fn route_uses_local_fixture_runtime() -> Result<()> {
    let route = route_with_runtime(
            Arc::new(FixtureInferenceRuntime {
                payload: r#"{"outcomeKind":"artifact","confidence":0.93,"needsClarification":false,"clarificationQuestions":[],"artifact":{"artifactClass":"document","deliverableShape":"single_file","renderer":"markdown","presentationSurface":"side_panel","persistence":"artifact_scoped","executionSubstrate":"none","workspaceRecipeId":null,"presentationVariantId":null,"scope":{"targetProject":null,"createNewWorkspace":false,"mutationBoundary":["artifact"]},"verification":{"requireRender":true,"requireBuild":false,"requirePreview":false,"requireExport":true,"requireDiffReview":false}}}"#
                    .to_string(),
                source_label: "fixture://route".to_string(),
            }),
            "Create a markdown launch brief",
            None,
            None,
        )
        .await
        .map_err(anyhow::Error::msg)?;
    assert_eq!(outcome_kind_label(&route), "artifact");
    assert!(route.artifact.is_some());
    Ok(())
}

#[test]
fn resolve_local_runtime_config_uses_explicit_values() {
    let config = resolve_local_runtime_config(
        Some("http://127.0.0.1:11434/v1/chat/completions"),
        Some("secret"),
        Some("llama3.1"),
    );
    assert_eq!(
        config,
        LocalRouteRuntimeConfig {
            api_url: "http://127.0.0.1:11434/v1/chat/completions".to_string(),
            api_key: "secret".to_string(),
            model_name: "llama3.1".to_string(),
        }
    );
}

#[tokio::test]
async fn route_uses_local_http_runtime_path() -> Result<()> {
    #[derive(Clone)]
    struct LocalFixtureState {
        content: String,
    }

    async fn respond(
        State(state): State<LocalFixtureState>,
        Json(_request): Json<Value>,
    ) -> Json<Value> {
        Json(json!({
            "choices": [{
                "message": {
                    "content": state.content
                },
                "finish_reason": "stop"
            }]
        }))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let state = LocalFixtureState {
            content: r#"{"outcomeKind":"visualizer","confidence":0.88,"needsClarification":false,"clarificationQuestions":[],"artifact":null}"#
                .to_string(),
        };
    let app = Router::new()
        .route("/v1/chat/completions", post(respond))
        .with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let runtime = build_inference_runtime(
        None,
        true,
        false,
        Some(&format!("http://{address}/v1/chat/completions")),
        None,
        Some("llama3"),
    )?;
    let route =
        route_with_runtime(runtime, "Render this as an inline visualizer", None, None).await?;

    assert_eq!(outcome_kind_label(&route), "visualizer");
    assert!(route.artifact.is_none());

    let _ = shutdown_tx.send(());
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn workspace_generate_uses_scaffold_path_and_judges_pass() -> Result<()> {
    let request: StudioOutcomeArtifactRequest = serde_json::from_value(json!({
        "artifactClass": "workspace_project",
        "deliverableShape": "workspace_project",
        "renderer": "workspace_surface",
        "presentationSurface": "tabbed_panel",
        "persistence": "workspace_filesystem",
        "executionSubstrate": "workspace_runtime",
        "workspaceRecipeId": "vite-static-html",
        "presentationVariantId": null,
        "scope": {
            "targetProject": "studio-workspace",
            "createNewWorkspace": true,
            "mutationBoundary": ["workspace"]
        },
        "verification": {
            "requireRender": true,
            "requireBuild": true,
            "requirePreview": true,
            "requireExport": false,
            "requireDiffReview": true
        }
    }))?;

    let bundle = generate_workspace_artifact_bundle_with_runtimes(
        Arc::new(MockInferenceRuntime),
        Arc::new(MockInferenceRuntime),
        "Billing settings surface",
        "Create a workspace project for a billing settings surface",
        &request,
        None,
    )
    .await
    .map_err(anyhow::Error::msg)?;

    assert_eq!(
        bundle.judge.classification,
        StudioArtifactJudgeClassification::Pass
    );
    assert_eq!(bundle.winning_candidate_id, "candidate-1");
    assert!(bundle
        .winner
        .files
        .iter()
        .any(|file| file.path == "index.html"));
    assert!(bundle
        .winner
        .files
        .iter()
        .any(|file| file.path == "package.json"));
    Ok(())
}

#[test]
fn materialize_manifest_copies_files_and_manifest() -> Result<()> {
    let source_dir = tempdir()?;
    let output_dir = tempdir()?;
    fs::write(
        source_dir.path().join("report.md"),
        strong_markdown_fixture(),
    )?;

    run_materialize(
        &write_manifest_fixture(&sample_manifest(), source_dir.path())?,
        source_dir.path(),
        output_dir.path(),
        true,
    )?;

    assert!(output_dir.path().join("report.md").exists());
    assert!(output_dir.path().join("artifact-manifest.json").exists());
    assert!(output_dir.path().join("README.md").exists());
    Ok(())
}

#[test]
fn materialize_blocked_failure_manifest_keeps_evidence_package_valid() -> Result<()> {
    let source_dir = tempdir()?;
    let output_dir = tempdir()?;

    run_materialize(
        &write_manifest_fixture(&blocked_failure_manifest(), source_dir.path())?,
        source_dir.path(),
        output_dir.path(),
        true,
    )?;

    assert!(output_dir.path().join("artifact-manifest.json").exists());
    assert!(output_dir.path().join("README.md").exists());
    Ok(())
}

#[test]
fn inspection_reports_source_first_when_render_is_not_ready() {
    let mut manifest = sample_manifest();
    manifest.verification.status = StudioArtifactVerificationStatus::Partial;
    manifest.verification.lifecycle_state = StudioArtifactLifecycleState::Partial;

    let inspection = inspection_for_manifest(&manifest);
    assert_eq!(inspection.preferred_stage_mode, "source");
    assert!(!inspection.render_surface_available);
}

#[test]
fn validate_materialized_html_quality_rejects_placeholder_shell() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Launch page".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Render contract verified.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section><h1>Placeholder</h1><p>Coming soon.</p></section></main></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("presentation contract failed")),
        "expected presentation-quality failure, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_html_ready_manifest_still_requires_quality_contract() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Launch page".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Acceptance judged the artifact ready for primary presentation.".to_string(),
            production_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            acceptance_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("llama3.2:3b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing, adoption by channel, and retailer education stay visible in the page.</p></section></main></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("presentation contract failed")),
        "expected acceptance-ready HTML manifest to keep enforcing quality, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_html_rejects_empty_svg_chart_shells_even_when_ready() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Dog shampoo rollout".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Acceptance judged the artifact ready for primary presentation.".to_string(),
            production_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            acceptance_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:14b".to_string()),
                endpoint: Some(
                    "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
                ),
            }),
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing and channel metrics stay visible.</p></section><article><button type=\"button\">Show adoption</button><svg width=\"400\" height=\"220\"><!-- chart data goes here --></svg></article><footer><p>Readiness owners stay visible.</p></footer><script>document.querySelector('button').addEventListener('click',()=>{});</script></main></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("empty placeholder shells")),
        "expected empty SVG shell failure, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_html_rejects_empty_chart_container_shells_even_when_ready() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Dog shampoo rollout".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Acceptance judged the artifact ready for primary presentation.".to_string(),
            production_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            acceptance_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:14b".to_string()),
                endpoint: Some(
                    "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
                ),
            }),
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing and channel metrics stay visible.</p></section><article><button type=\"button\">Show adoption</button><article id=\"conditionComparisonChart\"></article><article id=\"ingredientBreakdownChart\"><!-- chart fills later --></article></article><footer><p>Readiness owners stay visible.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("containers are still empty placeholder shells")),
        "expected empty chart container shell failure, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_html_rejects_placeholder_comments_and_missing_ids_even_when_ready(
) -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Dog shampoo rollout".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Acceptance judged the artifact ready for primary presentation.".to_string(),
            production_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            acceptance_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:14b".to_string()),
                endpoint: Some(
                    "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
                ),
            }),
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section><h1>Explain the Key Features and Benefits of a New Dog Shampoo Through Interactive Charts and Data Visualizations</h1></section><section class=\"controls\"><button id=\"chart1\" class=\"control\">Chart 1: pH Levels</button><button id=\"chart2\" class=\"control\">Chart 2: Ingredient Breakdowns</button><button id=\"chart3\" class=\"control\">Chart 3: Before & After Condition Comparisons</button></section><section><div id=\"chart1-container\"><svg width=\"500\" height=\"300\" viewBox=\"0 0 500 300\"><!-- Placeholder SVG content for Chart 1 --><rect x=\"100\" y=\"100\" width=\"80\" height=\"100\" fill=\"#ffd700\"></rect></svg></div></section><aside id=\"detail-panel\"><h2>Product Rollout Details</h2><p>Key benefits and performance metrics for the new dog shampoo.</p></aside></main><script>const chartContainers=document.querySelectorAll('#chart1-container, #chart2-container, #chart3-container');document.getElementById('chart2').addEventListener('click',()=>{chartContainers.forEach((container)=>container.style.display='none');document.getElementById('chart2-container').style.display='flex';});</script></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("placeholder-grade copy or comments")),
        "expected placeholder comment failure, got {errors:?}"
    );
    assert!(
        errors.iter().any(|error| error.contains("missing DOM ids")),
        "expected missing DOM id failure, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_html_rejects_empty_shared_detail_regions_even_when_ready() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Dog shampoo rollout".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Acceptance judged the artifact ready for primary presentation.".to_string(),
            production_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            acceptance_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:14b".to_string()),
                endpoint: Some(
                    "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
                ),
            }),
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Compare launch readiness, channel adoption, formula proof points, retailer timing, and subscription retention in one surfaced review.</p><p>The default state should already explain why retail leads first-wave education while subscription carries repeat-purchase lift into the second phase.</p><button type=\"button\" id=\"retail\">Retail</button><button type=\"button\" id=\"subscription\">Subscription</button></section><section><article class=\"chart\"><h2>Channel adoption</h2><svg viewBox=\"0 0 220 120\" role=\"img\" aria-label=\"Dog shampoo adoption chart\"><rect x=\"20\" y=\"48\" width=\"40\" height=\"52\"></rect><rect x=\"88\" y=\"34\" width=\"40\" height=\"66\"></rect><text x=\"20\" y=\"114\">Retail</text><text x=\"88\" y=\"114\">Subscription</text></svg><p>Retail stays selected by default while launch operations monitor sell-through, clinic sampling, and ingredient education across the first six weeks.</p></article></section><aside id=\"detail-panel\"><h2>Comparison detail</h2><!-- default detail arrives later --></aside></main><script>const detail=document.getElementById('detail-panel');document.getElementById('retail').addEventListener('click',()=>{detail.dataset.view='retail';});document.getElementById('subscription').addEventListener('click',()=>{detail.dataset.view='subscription';});</script></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("shared detail or comparison regions are empty")),
        "expected empty shared detail failure, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_html_rejects_unlabeled_chart_svg_shells_even_when_ready() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Dog shampoo rollout".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Acceptance judged the artifact ready for primary presentation.".to_string(),
            production_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            acceptance_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:14b".to_string()),
                endpoint: Some(
                    "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
                ),
            }),
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section><h1>Dog shampoo rollout</h1><p>Launch sequencing and channel metrics stay visible.</p></section><article class=\"chart\"><button type=\"button\">Show adoption</button><svg width=\"400\" height=\"220\"><circle cx=\"120\" cy=\"110\" r=\"82\" stroke=\"#335\" stroke-width=\"18\" fill=\"none\"></circle><circle cx=\"120\" cy=\"110\" r=\"56\" stroke=\"#7aa\" stroke-width=\"18\" fill=\"none\"></circle></svg></article><footer><p>Readiness owners stay visible.</p><script>document.querySelector('button').addEventListener('click',()=>{});</script></footer></main></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("SVG regions are still unlabeled shells")),
        "expected unlabeled chart SVG shell failure, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_materialized_html_rejects_empty_sectioning_shells_even_when_ready() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "artifact_html".to_string(),
        title: "Dog shampoo rollout".to_string(),
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        primary_tab: "render".to_string(),
        tabs: vec![StudioArtifactManifestTab {
            id: "render".to_string(),
            label: "Render".to_string(),
            kind: StudioArtifactTabKind::Render,
            renderer: Some(StudioRendererKind::HtmlIframe),
            file_path: Some("index.html".to_string()),
            lens: None,
        }],
        files: vec![StudioArtifactManifestFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            artifact_id: None,
            external_url: None,
        }],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Acceptance judged the artifact ready for primary presentation.".to_string(),
            production_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:7b".to_string()),
                endpoint: Some("http://127.0.0.1:11434/v1/chat/completions".to_string()),
            }),
            acceptance_provenance: Some(StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::RealLocalRuntime,
                label: "openai-compatible".to_string(),
                model: Some("qwen2.5:14b".to_string()),
                endpoint: Some(
                    "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance".to_string(),
                ),
            }),
            failure: None,
        },
        storage: None,
    };
    fs::write(
            root.path().join("index.html"),
            "<!doctype html><html><body><main><section id=\"hero\"></section><section id=\"scenario\"></section><aside id=\"evidence\"></aside><details><summary>Inspect supporting detail</summary><p>Inline detail.</p></details></main></body></html>",
        )?;

    let errors = validate_materialized_files(&manifest, root.path());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("empty first-paint shells")),
        "expected empty section shell failure, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_workspace_source_first_without_preview_is_truthful() -> Result<()> {
    let root = tempdir()?;
    let manifest = StudioArtifactManifest {
        artifact_id: "workspace_artifact".to_string(),
        title: "Workspace artifact".to_string(),
        artifact_class: StudioArtifactClass::WorkspaceProject,
        renderer: StudioRendererKind::WorkspaceSurface,
        primary_tab: "workspace".to_string(),
        tabs: vec![
            StudioArtifactManifestTab {
                id: "preview".to_string(),
                label: "Preview".to_string(),
                kind: StudioArtifactTabKind::Render,
                renderer: Some(StudioRendererKind::HtmlIframe),
                file_path: None,
                lens: Some("preview".to_string()),
            },
            StudioArtifactManifestTab {
                id: "workspace".to_string(),
                label: "Workspace".to_string(),
                kind: StudioArtifactTabKind::Workspace,
                renderer: Some(StudioRendererKind::WorkspaceSurface),
                file_path: Some("index.html".to_string()),
                lens: Some("code".to_string()),
            },
        ],
        files: vec![
            StudioArtifactManifestFile {
                path: "index.html".to_string(),
                mime: "text/html".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                artifact_id: None,
                external_url: None,
            },
            StudioArtifactManifestFile {
                path: "artifact-manifest.json".to_string(),
                mime: "application/json".to_string(),
                role: StudioArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                artifact_id: None,
                external_url: None,
            },
        ],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Workspace scaffold is ready for source-first review.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    };

    let errors = validate_presentation_quality(&manifest, root.path());
    assert!(
        errors.is_empty(),
        "expected source-first workspace to validate, got {errors:?}"
    );
    Ok(())
}

#[test]
fn validate_workspace_preview_primary_uses_verified_manifest_state() -> Result<()> {
    let root = tempdir()?;
    fs::create_dir_all(root.path().join("src"))?;
    fs::write(
        root.path().join("src/App.tsx"),
        "export default function App() { return <main><h1>Billing settings</h1></main>; }",
    )?;
    fs::write(root.path().join("artifact-manifest.json"), "{}")?;
    let manifest = StudioArtifactManifest {
        artifact_id: "workspace_artifact_ready".to_string(),
        title: "Workspace artifact".to_string(),
        artifact_class: StudioArtifactClass::WorkspaceProject,
        renderer: StudioRendererKind::WorkspaceSurface,
        primary_tab: "preview".to_string(),
        tabs: vec![
            StudioArtifactManifestTab {
                id: "preview".to_string(),
                label: "Preview".to_string(),
                kind: StudioArtifactTabKind::Render,
                renderer: Some(StudioRendererKind::HtmlIframe),
                file_path: None,
                lens: Some("preview".to_string()),
            },
            StudioArtifactManifestTab {
                id: "workspace".to_string(),
                label: "Workspace".to_string(),
                kind: StudioArtifactTabKind::Workspace,
                renderer: Some(StudioRendererKind::WorkspaceSurface),
                file_path: Some("src/App.tsx".to_string()),
                lens: Some("code".to_string()),
            },
        ],
        files: vec![
            StudioArtifactManifestFile {
                path: "src/App.tsx".to_string(),
                mime: "text/jsx".to_string(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: true,
                artifact_id: None,
                external_url: None,
            },
            StudioArtifactManifestFile {
                path: "artifact-manifest.json".to_string(),
                mime: "application/json".to_string(),
                role: StudioArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                artifact_id: None,
                external_url: None,
            },
        ],
        verification: StudioArtifactManifestVerification {
            status: StudioArtifactVerificationStatus::Ready,
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary: "Preview verified and workspace lenses are ready.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    };

    let inspection = inspection_for_manifest(&manifest);
    assert!(inspection.render_surface_available);
    assert_eq!(inspection.preferred_stage_mode, "render");

    let presentation_errors = validate_presentation_quality(&manifest, root.path());
    assert!(
        presentation_errors.is_empty(),
        "expected preview-ready workspace to validate, got {presentation_errors:?}"
    );
    Ok(())
}

#[test]
fn compose_reply_uses_verification_state() {
    let reply = compose_verified_reply(&sample_manifest());
    assert_eq!(reply.status, "ready");
    assert_eq!(reply.lifecycle_state, "ready");
    assert!(reply.summary.contains("Render contract verified."));
}

#[test]
fn write_generated_payload_compiles_pdf_bytes_without_mock_shell() -> Result<()> {
    let root = tempdir()?;
    let payload = StudioGeneratedArtifactPayload {
        summary: "Launch brief".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "launch_summary.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: None,
            body: "Executive summary\n\nThis launch brief includes the goals, rollout plan, owner table, milestone timeline, and verification notes for the artifact stage.".to_string(),
        }],
    };

    write_generated_payload(root.path(), "Launch brief", &payload)?;

    let bytes = fs::read(root.path().join("launch_summary.pdf"))?;
    let text = String::from_utf8_lossy(&bytes);
    assert!(bytes.starts_with(b"%PDF-1.4\n"));
    assert!(bytes.len() > 800);
    assert!(!text.contains("Studio mock PDF"));
    Ok(())
}

#[test]
fn write_generated_payload_unwraps_nested_html_payload_envelopes() -> Result<()> {
    let root = tempdir()?;
    let nested_html = "<!doctype html><html><body><main><section><h1>AI tools editorial launch</h1><p>Interactive launch evidence stays visible.</p></section><aside><h2>Detail</h2><p id=\"detail-copy\">Overview is selected by default.</p></aside><footer><p>Footer note.</p></footer></main></body></html>";
    let payload = StudioGeneratedArtifactPayload {
        summary: "Launch page".to_string(),
        notes: Vec::new(),
        files: vec![StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ioi_api::studio::StudioGeneratedArtifactEncoding::Utf8),
            body: json!({
                "summary": "Nested launch page",
                "notes": ["wrapped once"],
                "files": [{
                    "path": "launch-page.html",
                    "mime": "text/html",
                    "role": "primary",
                    "renderable": true,
                    "downloadable": true,
                    "encoding": "utf8",
                    "body": nested_html
                }]
            })
            .to_string(),
        }],
    };

    write_generated_payload(root.path(), "Launch page", &payload)?;

    let written = fs::read_to_string(root.path().join("index.html"))?;
    assert_eq!(written, nested_html);
    Ok(())
}

#[test]
fn load_generated_evidence_accepts_blocked_verified_reply_envelope() -> Result<()> {
    let root = tempdir()?;
    let manifest = blocked_failure_manifest();
    let failure = manifest
        .verification
        .failure
        .clone()
        .expect("failure envelope");
    let production_provenance = manifest.verification.production_provenance.clone();
    let acceptance_provenance = manifest.verification.acceptance_provenance.clone();
    fs::write(
        root.path().join("generation.json"),
        serde_json::to_vec_pretty(&json!({
            "prompt": "Create an interactive HTML artifact that explains a product rollout with charts for a productivity assistant",
            "title": manifest.title,
            "route": {
                "outcomeKind": "artifact",
                "confidence": 0.0,
                "needsClarification": false,
                "clarificationQuestions": [],
                "artifact": {
                    "artifactClass": "report_bundle",
                    "deliverableShape": "file_set",
                    "renderer": "bundle_manifest",
                    "presentationSurface": "side_panel",
                    "persistence": "artifact_scoped",
                    "executionSubstrate": "none",
                    "workspaceRecipeId": null,
                    "presentationVariantId": null,
                    "scope": {
                        "targetProject": null,
                        "createNewWorkspace": false,
                        "mutationBoundary": ["artifact"]
                    },
                    "verification": {
                        "requireRender": false,
                        "requireBuild": false,
                        "requirePreview": false,
                        "requireExport": false,
                        "requireDiffReview": false
                    }
                }
            },
            "artifactBrief": null,
            "editIntent": null,
            "candidateSummaries": [],
            "winningCandidateId": null,
            "winningCandidateRationale": null,
            "judge": {
                "classification": "blocked",
                "requestFaithfulness": 1,
                "conceptCoverage": 1,
                "interactionRelevance": 1,
                "layoutCoherence": 1,
                "visualHierarchy": 1,
                "completeness": 1,
                "genericShellDetected": false,
                "trivialShellDetected": false,
                "deservesPrimaryArtifactView": false,
                "patchedExistingArtifact": null,
                "continuityRevisionUx": null,
                "strongestContradiction": failure.message,
                "rationale": failure.message
            },
            "outputOrigin": "inference_unavailable",
            "productionProvenance": production_provenance,
            "acceptanceProvenance": acceptance_provenance,
            "fallbackUsed": false,
            "uxLifecycle": "draft",
            "failure": failure,
            "manifest": manifest,
            "verifiedReply": {
                "status": "blocked",
                "lifecycleState": "blocked",
                "title": "Studio outcome: Blocked artifact",
                "summary": "Blocked artifact Studio cannot route or materialize artifacts because inference is unavailable.",
                "evidence": [
                    "production provenance: inference unavailable",
                    "acceptance provenance: inference unavailable",
                    "failure: Studio cannot route or materialize artifacts because inference is unavailable. (inference_unavailable)"
                ],
                "productionProvenance": {
                    "kind": "inference_unavailable",
                    "label": "inference unavailable",
                    "model": null,
                    "endpoint": null
                },
                "acceptanceProvenance": {
                    "kind": "inference_unavailable",
                    "label": "inference unavailable",
                    "model": null,
                    "endpoint": null
                },
                "failure": {
                    "kind": "inference_unavailable",
                    "code": "inference_unavailable",
                    "message": "Studio cannot route or materialize artifacts because inference is unavailable."
                }
            },
            "materializedFiles": [],
            "renderableFiles": []
        }))?,
    )?;

    let evidence = load_generated_evidence(root.path())?;
    assert_eq!(evidence.verified_reply.lifecycle_state, "blocked");
    assert_eq!(
        evidence
            .verified_reply
            .failure
            .as_ref()
            .expect("verified reply failure")
            .code,
        "inference_unavailable"
    );
    assert_eq!(
        evidence
            .production_provenance
            .as_ref()
            .expect("production provenance")
            .kind,
        StudioRuntimeProvenanceKind::InferenceUnavailable
    );
    Ok(())
}

fn write_manifest_fixture(manifest: &StudioArtifactManifest, root: &Path) -> Result<PathBuf> {
    let manifest_path = root.join("artifact-manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(manifest)?)?;
    Ok(manifest_path)
}
