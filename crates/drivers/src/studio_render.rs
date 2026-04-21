use crate::browser::{BrowserDriver, BrowserError};
use async_trait::async_trait;
use ioi_api::studio::{
    build_studio_artifact_render_acceptance_policy, StudioArtifactAcceptanceObligation,
    StudioArtifactAcceptanceObligationStatus, StudioArtifactBlueprint, StudioArtifactBrief,
    StudioArtifactEditIntent, StudioArtifactExecutionWitness, StudioArtifactExecutionWitnessStatus,
    StudioArtifactIR, StudioArtifactRenderAcceptancePolicy, StudioArtifactRenderCapture,
    StudioArtifactRenderCaptureViewport, StudioArtifactRenderEvaluation,
    StudioArtifactRenderEvaluator, StudioArtifactRenderFinding,
    StudioArtifactRenderFindingSeverity, StudioArtifactRenderObservation,
    StudioGeneratedArtifactFile, StudioGeneratedArtifactPayload,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{StudioOutcomeArtifactRequest, StudioRendererKind};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DESKTOP_VIEWPORT: (u32, u32) = (1440, 960);
const MOBILE_VIEWPORT: (u32, u32) = (390, 844);
const DEFAULT_CAPTURE_SETTLE_MS: u64 = 140;
const DEFAULT_MAX_AFFORDANCE_PROBES: usize = 4;

fn studio_render_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

pub struct BrowserStudioArtifactRenderEvaluator {
    browser: BrowserDriver,
}

impl Default for BrowserStudioArtifactRenderEvaluator {
    fn default() -> Self {
        let browser = BrowserDriver::new();
        browser.set_lease(true);
        Self { browser }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomCaptureMetrics {
    visible_element_count: usize,
    visible_text_chars: usize,
    interactive_element_count: usize,
    section_count: usize,
    response_region_count: usize,
    evidence_surface_count: usize,
    actionable_affordance_count: usize,
    active_affordance_count: usize,
    heading_count: usize,
    main_present: bool,
    body_font_size: f64,
    heading_font_size: f64,
    avg_text_contrast: f64,
    min_text_contrast: f64,
    font_family_count: usize,
    dominant_left_alignment_ratio: f64,
    gap_consistency: f64,
    overlap_count: usize,
    #[allow(dead_code)]
    #[serde(default)]
    response_region_text: Option<String>,
}

#[derive(Debug)]
struct ScreenshotAnalysis {
    occupied_ratio: f64,
    luminance_stddev: f64,
}

#[derive(Debug)]
struct ViewportCapture {
    capture: StudioArtifactRenderCapture,
    dom: DomCaptureMetrics,
    analysis: ScreenshotAnalysis,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeWitnessState {
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActionableControl {
    selector: String,
    label: String,
    action_kind: String,
    #[serde(default)]
    active: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InteractionStateSnapshot {
    signature: String,
    #[serde(default)]
    response_text: Option<String>,
    #[serde(default)]
    visible_text_sample: String,
    #[serde(default)]
    visible_region_count: usize,
    #[serde(default)]
    active_affordance_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct BrowserRenderSamplingPolicy {
    capture_settle_ms: u64,
    max_affordance_probes: usize,
}

#[derive(Debug, Clone, Copy)]
struct LayoutDensityScorePolicy {
    medium_visible_elements: usize,
    medium_visible_text_chars: usize,
    medium_occupied_ratio: f64,
    strong_visible_elements: usize,
    strong_visible_text_chars: usize,
    strong_occupied_ratio: f64,
    full_visible_elements: usize,
    full_visible_text_chars: usize,
    full_occupied_ratio: f64,
    medium_section_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct SpacingAlignmentScorePolicy {
    medium_alignment_ratio: f64,
    strong_gap_consistency: f64,
    full_alignment_ratio: f64,
    full_gap_consistency: f64,
}

#[derive(Debug, Clone, Copy)]
struct TypographyScorePolicy {
    medium_avg_contrast: f64,
    strong_min_contrast: f64,
    strong_heading_ratio: f64,
    full_avg_contrast: f64,
    full_heading_ratio: f64,
}

#[derive(Debug, Clone, Copy)]
struct VisualHierarchyScorePolicy {
    strong_heading_ratio: f64,
    strong_evidence_surface_count: usize,
    strong_luminance_stddev: f64,
    full_heading_count: usize,
    full_evidence_surface_count: usize,
    full_luminance_stddev: f64,
}

#[derive(Debug, Clone, Copy)]
struct BrowserRenderScoringPolicy {
    layout_density: LayoutDensityScorePolicy,
    spacing_alignment: SpacingAlignmentScorePolicy,
    typography: TypographyScorePolicy,
    visual_hierarchy: VisualHierarchyScorePolicy,
}

impl Default for BrowserRenderScoringPolicy {
    fn default() -> Self {
        Self {
            layout_density: LayoutDensityScorePolicy {
                medium_visible_elements: 8,
                medium_visible_text_chars: 120,
                medium_occupied_ratio: 0.16,
                strong_visible_elements: 16,
                strong_visible_text_chars: 220,
                strong_occupied_ratio: 0.24,
                full_visible_elements: 24,
                full_visible_text_chars: 320,
                full_occupied_ratio: 0.32,
                medium_section_count: 3,
            },
            spacing_alignment: SpacingAlignmentScorePolicy {
                medium_alignment_ratio: 0.35,
                strong_gap_consistency: 0.45,
                full_alignment_ratio: 0.55,
                full_gap_consistency: 0.6,
            },
            typography: TypographyScorePolicy {
                medium_avg_contrast: 3.5,
                strong_min_contrast: 3.0,
                strong_heading_ratio: 1.45,
                full_avg_contrast: 4.5,
                full_heading_ratio: 1.75,
            },
            visual_hierarchy: VisualHierarchyScorePolicy {
                strong_heading_ratio: 1.6,
                strong_evidence_surface_count: 2,
                strong_luminance_stddev: 0.14,
                full_heading_count: 2,
                full_evidence_surface_count: 3,
                full_luminance_stddev: 0.18,
            },
        }
    }
}

#[derive(Debug, Clone)]
struct WitnessProbeResult {
    action: ActionableControl,
    status: StudioArtifactExecutionWitnessStatus,
    summary: String,
    detail: Option<String>,
    console_errors: Vec<String>,
    state_changed: bool,
}

impl BrowserStudioArtifactRenderEvaluator {
    fn sampling_policy(
        &self,
        acceptance_policy: &StudioArtifactRenderAcceptancePolicy,
    ) -> BrowserRenderSamplingPolicy {
        BrowserRenderSamplingPolicy {
            capture_settle_ms: DEFAULT_CAPTURE_SETTLE_MS,
            max_affordance_probes: acceptance_policy
                .minimum_actionable_affordances
                .max(DEFAULT_MAX_AFFORDANCE_PROBES),
        }
    }

    async fn ensure_headless_browser(&self) -> Result<(), String> {
        self.browser.set_lease(true);
        self.browser
            .launch(true)
            .await
            .map_err(browser_error_to_string)
    }

    async fn capture_viewport(
        &self,
        viewport: StudioArtifactRenderCaptureViewport,
        width: u32,
        height: u32,
        previous_sha: Option<&str>,
        sampling_policy: BrowserRenderSamplingPolicy,
    ) -> Result<ViewportCapture, String> {
        tokio::time::sleep(Duration::from_millis(sampling_policy.capture_settle_ms)).await;
        let png = self
            .browser
            .capture_tab_screenshot_with_viewport(width, height, false)
            .await
            .map_err(browser_error_to_string)?;
        let dom: DomCaptureMetrics = self
            .browser
            .evaluate_js(render_dom_metrics_script())
            .await
            .map_err(browser_error_to_string)?;
        let analysis = analyze_screenshot(&png)?;
        let sha = hex::encode(
            sha256(&png).map_err(|error| format!("screenshot hash failed: {}", error))?,
        );
        Ok(ViewportCapture {
            capture: StudioArtifactRenderCapture {
                viewport,
                width,
                height,
                screenshot_sha256: sha.clone(),
                screenshot_byte_count: png.len(),
                visible_element_count: dom.visible_element_count,
                visible_text_chars: dom.visible_text_chars,
                interactive_element_count: dom.interactive_element_count,
                screenshot_changed_from_previous: previous_sha.is_some_and(|value| value != sha),
            },
            dom,
            analysis,
        })
    }

    async fn install_runtime_witness_collector(&self) -> Result<(), String> {
        self.browser
            .evaluate_js::<bool>(render_runtime_witness_collector_install_script())
            .await
            .map_err(browser_error_to_string)?;
        Ok(())
    }

    async fn runtime_witness_state(&self) -> Result<RuntimeWitnessState, String> {
        self.browser
            .evaluate_js::<RuntimeWitnessState>(render_runtime_witness_state_script())
            .await
            .map_err(browser_error_to_string)
    }

    async fn clear_runtime_witness_errors(&self) -> Result<(), String> {
        self.browser
            .evaluate_js::<bool>(render_runtime_witness_clear_script())
            .await
            .map_err(browser_error_to_string)?;
        Ok(())
    }

    async fn capture_interaction_state(&self) -> Result<InteractionStateSnapshot, String> {
        self.browser
            .evaluate_js::<InteractionStateSnapshot>(render_interaction_state_snapshot_script())
            .await
            .map_err(browser_error_to_string)
    }

    async fn discover_actionable_controls(&self) -> Result<Vec<ActionableControl>, String> {
        self.browser
            .evaluate_js::<Vec<ActionableControl>>(render_actionable_controls_script())
            .await
            .map_err(browser_error_to_string)
    }

    async fn perform_action_probe(
        &self,
        action: &ActionableControl,
        sampling_policy: BrowserRenderSamplingPolicy,
    ) -> WitnessProbeResult {
        let before = self.capture_interaction_state().await.ok();
        let _ = self.clear_runtime_witness_errors().await;

        let action_result = match action.action_kind.as_str() {
            "click" => self
                .browser
                .click_selector(&action.selector)
                .await
                .map_err(browser_error_to_string),
            kind => self
                .browser
                .evaluate_js::<bool>(&render_action_execution_script(&action.selector, kind))
                .await
                .map(|_| ())
                .map_err(browser_error_to_string),
        };

        tokio::time::sleep(Duration::from_millis(sampling_policy.capture_settle_ms)).await;
        let after = self.capture_interaction_state().await.ok();
        let runtime_state = self.runtime_witness_state().await.ok();
        let console_errors = runtime_state.map(|state| state.errors).unwrap_or_default();
        let state_changed = before
            .as_ref()
            .zip(after.as_ref())
            .is_some_and(|(left, right)| left.signature != right.signature);

        let (status, summary, detail) = match action_result {
            Err(error) => (
                StudioArtifactExecutionWitnessStatus::Blocked,
                format!("Studio could not exercise '{}'.", action.label),
                Some(error),
            ),
            Ok(()) if !console_errors.is_empty() => (
                StudioArtifactExecutionWitnessStatus::Failed,
                format!("'{}' triggered a runtime error.", action.label),
                Some(console_errors.join(" | ")),
            ),
            Ok(()) if state_changed => (
                StudioArtifactExecutionWitnessStatus::Passed,
                format!("'{}' changed visible artifact state.", action.label),
                after
                    .as_ref()
                    .and_then(|snapshot| snapshot.response_text.clone())
                    .or_else(|| {
                        after.as_ref().map(|snapshot| {
                            snapshot.visible_text_sample.chars().take(220).collect()
                        })
                    }),
            ),
            Ok(()) => {
                let detail = after.as_ref().map(|snapshot| {
                    format!(
                        "No visible state delta was observed after exercising '{}'. visibleRegions={} activeAffordances={} text='{}'",
                        action.label,
                        snapshot.visible_region_count,
                        snapshot.active_affordance_count,
                        snapshot.visible_text_sample.chars().take(180).collect::<String>(),
                    )
                });
                (
                    StudioArtifactExecutionWitnessStatus::Failed,
                    format!("'{}' did not change visible artifact state.", action.label),
                    detail,
                )
            }
        };

        WitnessProbeResult {
            action: action.clone(),
            status,
            summary,
            detail,
            console_errors,
            state_changed,
        }
    }

    async fn probe_interactions(
        &self,
        should_probe: bool,
        previous_sha: Option<&str>,
        sampling_policy: BrowserRenderSamplingPolicy,
    ) -> Result<(Vec<WitnessProbeResult>, Option<ViewportCapture>), String> {
        if !should_probe {
            return Ok((Vec::new(), None));
        }
        let discovered = self.discover_actionable_controls().await?;
        let actionable = select_actionable_controls_for_probe(
            &discovered,
            sampling_policy.max_affordance_probes,
        );
        let mut witnesses = Vec::new();
        let mut interaction_capture = None;

        for action in actionable {
            let witness = self.perform_action_probe(&action, sampling_policy).await;
            if interaction_capture.is_none()
                && witness.status == StudioArtifactExecutionWitnessStatus::Passed
            {
                interaction_capture = self
                    .capture_viewport(
                        StudioArtifactRenderCaptureViewport::Interaction,
                        DESKTOP_VIEWPORT.0,
                        DESKTOP_VIEWPORT.1,
                        previous_sha,
                        sampling_policy,
                    )
                    .await
                    .ok();
            }
            witnesses.push(witness);
        }

        Ok((witnesses, interaction_capture))
    }
}

#[async_trait]
impl StudioArtifactRenderEvaluator for BrowserStudioArtifactRenderEvaluator {
    async fn evaluate_candidate_render(
        &self,
        request: &StudioOutcomeArtifactRequest,
        brief: &StudioArtifactBrief,
        blueprint: Option<&StudioArtifactBlueprint>,
        artifact_ir: Option<&StudioArtifactIR>,
        _edit_intent: Option<&StudioArtifactEditIntent>,
        candidate: &StudioGeneratedArtifactPayload,
    ) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
        if !matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe
                | StudioRendererKind::Svg
                | StudioRendererKind::Markdown
                | StudioRendererKind::PdfEmbed
        ) {
            return Ok(None);
        }

        let started_at = Instant::now();
        let acceptance_policy =
            build_studio_artifact_render_acceptance_policy(request, brief, blueprint, artifact_ir);
        let sampling_policy = self.sampling_policy(&acceptance_policy);
        let preview_bundle = build_preview_bundle(request.renderer, candidate)?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:bundle_ready renderer={:?} entry={} elapsed_ms={}",
            request.renderer,
            preview_bundle.entry_path.display(),
            started_at.elapsed().as_millis()
        ));
        studio_render_trace(format!(
            "artifact_generation:render_eval:browser_launch:start elapsed_ms={}",
            started_at.elapsed().as_millis()
        ));
        self.ensure_headless_browser().await?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:browser_launch:ok elapsed_ms={}",
            started_at.elapsed().as_millis()
        ));
        self.browser
            .evaluate_on_new_document(render_runtime_witness_collector_install_script())
            .await
            .map_err(browser_error_to_string)?;
        let preview_url = format!("file://{}", preview_bundle.entry_path.display());
        studio_render_trace(format!(
            "artifact_generation:render_eval:navigate:start url={} elapsed_ms={}",
            preview_url,
            started_at.elapsed().as_millis()
        ));
        self.browser
            .navigate(&preview_url)
            .await
            .map_err(browser_error_to_string)?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:navigate:ok elapsed_ms={}",
            started_at.elapsed().as_millis()
        ));
        self.install_runtime_witness_collector().await?;

        studio_render_trace(format!(
            "artifact_generation:render_eval:desktop:start elapsed_ms={}",
            started_at.elapsed().as_millis()
        ));
        let desktop = self
            .capture_viewport(
                StudioArtifactRenderCaptureViewport::Desktop,
                DESKTOP_VIEWPORT.0,
                DESKTOP_VIEWPORT.1,
                None,
                sampling_policy,
            )
            .await?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:desktop:ok bytes={} elapsed_ms={}",
            desktop.capture.screenshot_byte_count,
            started_at.elapsed().as_millis()
        ));
        studio_render_trace(format!(
            "artifact_generation:render_eval:mobile:start elapsed_ms={}",
            started_at.elapsed().as_millis()
        ));
        let mobile = self
            .capture_viewport(
                StudioArtifactRenderCaptureViewport::Mobile,
                MOBILE_VIEWPORT.0,
                MOBILE_VIEWPORT.1,
                Some(&desktop.capture.screenshot_sha256),
                sampling_policy,
            )
            .await?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:mobile:ok bytes={} elapsed_ms={}",
            mobile.capture.screenshot_byte_count,
            started_at.elapsed().as_millis()
        ));
        let interaction_expected = brief.has_required_interaction_goals()
            || blueprint
                .map(|value| !value.interaction_plan.is_empty())
                .unwrap_or(false)
            || artifact_ir
                .map(|value| !value.interaction_graph.is_empty())
                .unwrap_or(false);
        let should_probe_interactions = request.renderer == StudioRendererKind::HtmlIframe
            && (request.artifact_class
                == ioi_types::app::StudioArtifactClass::InteractiveSingleFile
                || interaction_expected);
        let boot_errors = self.runtime_witness_state().await?.errors;
        studio_render_trace(format!(
            "artifact_generation:render_eval:interaction:start expected={} probe={} elapsed_ms={}",
            interaction_expected,
            should_probe_interactions,
            started_at.elapsed().as_millis()
        ));
        let (interaction_witnesses, interaction) = self
            .probe_interactions(
                should_probe_interactions,
                Some(&desktop.capture.screenshot_sha256),
                sampling_policy,
            )
            .await?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:interaction:ok captured={} witnesses={} elapsed_ms={}",
            interaction.is_some(),
            interaction_witnesses.len(),
            started_at.elapsed().as_millis()
        ));

        let render_evaluation = score_render_evaluation(
            request,
            brief,
            blueprint,
            artifact_ir,
            &desktop,
            &mobile,
            interaction.as_ref(),
            interaction_expected,
            &boot_errors,
            &interaction_witnesses,
            acceptance_policy,
        );
        studio_render_trace(format!(
            "artifact_generation:render_eval:scored overall={} elapsed_ms={}",
            render_evaluation.overall_score,
            started_at.elapsed().as_millis()
        ));
        let _ = fs::remove_dir_all(&preview_bundle.root_dir);
        Ok(Some(render_evaluation))
    }
}

struct PreviewBundle {
    root_dir: PathBuf,
    entry_path: PathBuf,
}

fn build_preview_bundle(
    renderer: StudioRendererKind,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<PreviewBundle, String> {
    let root_dir = std::env::temp_dir().join(format!("studio-render-{}", Uuid::new_v4()));
    fs::create_dir_all(&root_dir).map_err(|error| {
        format!(
            "failed to create temporary render-eval root '{}': {}",
            root_dir.display(),
            error
        )
    })?;
    write_generated_files(&root_dir, &candidate.files)?;

    let entry_path = match renderer {
        StudioRendererKind::HtmlIframe => {
            let entry = candidate
                .files
                .iter()
                .find(|file| file.renderable && file.path.ends_with(".html"))
                .ok_or_else(|| {
                    "html_iframe candidate did not materialize a renderable HTML file.".to_string()
                })?;
            root_dir.join(safe_relative_path(&entry.path)?)
        }
        StudioRendererKind::Svg => {
            let source = candidate
                .files
                .iter()
                .find(|file| file.renderable && file.path.ends_with(".svg"))
                .ok_or_else(|| {
                    "svg candidate did not materialize a renderable SVG file.".to_string()
                })?;
            let preview_path = root_dir.join("__render_preview__.html");
            fs::write(&preview_path, wrap_svg_preview(&source.body))
                .map_err(|error| format!("failed to write SVG preview HTML: {}", error))?;
            preview_path
        }
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => {
            let source = candidate
                .files
                .iter()
                .find(|file| {
                    file.renderable || file.path.ends_with(".md") || file.path.ends_with(".txt")
                })
                .ok_or_else(|| {
                    "document candidate did not materialize a renderable source file.".to_string()
                })?;
            let preview_path = root_dir.join("__render_preview__.html");
            fs::write(&preview_path, wrap_markdown_preview(&source.body))
                .map_err(|error| format!("failed to write markdown preview HTML: {}", error))?;
            preview_path
        }
        _ => {
            return Err("renderer is not supported by browser-backed render evaluation".to_string())
        }
    };

    Ok(PreviewBundle {
        root_dir,
        entry_path,
    })
}

fn write_generated_files(
    root_dir: &Path,
    files: &[StudioGeneratedArtifactFile],
) -> Result<(), String> {
    for file in files {
        let relative = safe_relative_path(&file.path)?;
        let path = root_dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create preview parent directory '{}': {}",
                    parent.display(),
                    error
                )
            })?;
        }
        fs::write(&path, file.body.as_bytes()).map_err(|error| {
            format!(
                "failed to write preview file '{}': {}",
                path.display(),
                error
            )
        })?;
    }
    Ok(())
}

fn safe_relative_path(raw: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(format!(
            "render preview cannot write absolute artifact path '{}'",
            raw
        ));
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "render preview cannot write path '{}' outside the sandbox root",
                    raw
                ));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err("render preview received an empty file path".to_string());
    }
    Ok(clean)
}

fn wrap_svg_preview(svg_source: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SVG Preview</title>
  <style>
    html, body {{ margin: 0; min-height: 100%; background: #f5f4ef; color: #161616; }}
    body {{ display: grid; place-items: center; padding: 24px; }}
    main {{ width: min(92vw, 1100px); min-height: min(88vh, 820px); display: grid; place-items: center; background: white; border: 1px solid rgba(0,0,0,0.08); box-shadow: 0 24px 80px rgba(0,0,0,0.10); }}
    svg {{ width: 100%; height: auto; display: block; }}
  </style>
</head>
<body>
  <main>{}</main>
</body>
</html>"#,
        svg_source
    )
}

fn wrap_markdown_preview(markdown: &str) -> String {
    let rendered = render_markdown_to_html(markdown);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Document Preview</title>
  <style>
    :root {{ color-scheme: light; }}
    html, body {{ margin: 0; min-height: 100%; background: #f4f1ea; color: #1d1a17; }}
    body {{ font-family: Georgia, 'Times New Roman', serif; padding: clamp(20px, 3vw, 48px); }}
    main {{ max-width: 860px; margin: 0 auto; background: rgba(255,255,255,0.92); border: 1px solid rgba(0,0,0,0.08); padding: clamp(28px, 4vw, 56px); box-shadow: 0 18px 60px rgba(0,0,0,0.08); }}
    h1, h2, h3 {{ line-height: 1.1; margin: 0 0 0.6em; }}
    h1 {{ font-size: clamp(2rem, 4vw, 3rem); }}
    h2 {{ font-size: clamp(1.4rem, 2.8vw, 2rem); margin-top: 1.8em; }}
    h3 {{ font-size: 1.15rem; margin-top: 1.35em; }}
    p, li, blockquote {{ font-size: 1rem; line-height: 1.72; }}
    ul, ol {{ padding-left: 1.35rem; }}
    code, pre {{ font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, monospace; }}
    pre {{ padding: 14px; overflow: auto; background: #f7f7f7; border-radius: 10px; }}
    blockquote {{ margin: 1.2em 0; padding-left: 1rem; border-left: 3px solid rgba(0,0,0,0.18); color: #4b433b; }}
  </style>
</head>
<body>
  <main>{}</main>
</body>
</html>"#,
        rendered
    )
}

fn render_markdown_to_html(markdown: &str) -> String {
    let mut html = String::new();
    let mut in_list = false;
    let mut in_code_block = false;
    let mut code_buffer = String::new();

    for raw_line in markdown.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_code_block {
                html.push_str("<pre><code>");
                html.push_str(&escape_html(&code_buffer));
                html.push_str("</code></pre>");
                code_buffer.clear();
                in_code_block = false;
            } else {
                in_code_block = true;
            }
            continue;
        }
        if in_code_block {
            code_buffer.push_str(line);
            code_buffer.push('\n');
            continue;
        }
        if trimmed.is_empty() {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            continue;
        }
        if let Some(content) = trimmed.strip_prefix("# ") {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            html.push_str("<h1>");
            html.push_str(&escape_html(content));
            html.push_str("</h1>");
            continue;
        }
        if let Some(content) = trimmed.strip_prefix("## ") {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            html.push_str("<h2>");
            html.push_str(&escape_html(content));
            html.push_str("</h2>");
            continue;
        }
        if let Some(content) = trimmed.strip_prefix("### ") {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            html.push_str("<h3>");
            html.push_str(&escape_html(content));
            html.push_str("</h3>");
            continue;
        }
        if let Some(content) = trimmed
            .strip_prefix("- [ ] ")
            .or_else(|| trimmed.strip_prefix("- "))
            .or_else(|| trimmed.strip_prefix("* "))
        {
            if !in_list {
                html.push_str("<ul>");
                in_list = true;
            }
            html.push_str("<li>");
            html.push_str(&escape_html(content));
            html.push_str("</li>");
            continue;
        }
        if let Some(content) = trimmed.strip_prefix("> ") {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            html.push_str("<blockquote>");
            html.push_str(&escape_html(content));
            html.push_str("</blockquote>");
            continue;
        }
        if in_list {
            html.push_str("</ul>");
            in_list = false;
        }
        html.push_str("<p>");
        html.push_str(&escape_html(trimmed));
        html.push_str("</p>");
    }

    if in_list {
        html.push_str("</ul>");
    }
    if in_code_block && !code_buffer.is_empty() {
        html.push_str("<pre><code>");
        html.push_str(&escape_html(&code_buffer));
        html.push_str("</code></pre>");
    }
    html
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_dom_metrics_script() -> &'static str {
    r#"(() => {
  const parseColor = (value) => {
    if (!value) return null;
    const match = String(value).trim().match(/rgba?\(([^)]+)\)/i);
    if (!match) return null;
    const parts = match[1].split(",").map((entry) => Number(entry.trim()));
    if (parts.length < 3) return null;
    return { r: parts[0] || 0, g: parts[1] || 0, b: parts[2] || 0, a: parts[3] == null ? 1 : parts[3] };
  };
  const luminance = (color) => {
    const channel = (value) => {
      const normalized = value / 255;
      return normalized <= 0.03928 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b);
  };
  const contrastRatio = (fg, bg) => {
    if (!fg || !bg) return null;
    const lighter = Math.max(luminance(fg), luminance(bg));
    const darker = Math.min(luminance(fg), luminance(bg));
    return (lighter + 0.05) / (darker + 0.05);
  };
  const visible = (el) => {
    if (!el || typeof el.getBoundingClientRect !== "function") return false;
    const rect = el.getBoundingClientRect();
    if (!(rect.width > 0 && rect.height > 0)) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity || "1") <= 0.02) return false;
    return rect.bottom >= 0 && rect.right >= 0 && rect.top <= window.innerHeight && rect.left <= window.innerWidth;
  };
  const semanticElements = Array.from(document.querySelectorAll("main, header, nav, section, article, aside, footer, h1, h2, h3, p, li, button, a, svg, canvas, table, figure, blockquote"))
    .filter(visible)
    .slice(0, 48);
  const textNodes = semanticElements.filter((el) => (el.innerText || "").trim().length > 0);
  const textChars = textNodes.reduce((sum, el) => sum + (el.innerText || "").trim().length, 0);
  const fontFamilies = new Set();
  const contrasts = [];
  let bodyFont = 16;
  let headingFont = 0;
  textNodes.slice(0, 18).forEach((el) => {
    const style = window.getComputedStyle(el);
    if (style.fontFamily) fontFamilies.add(style.fontFamily);
    const fontSize = Number.parseFloat(style.fontSize || "16") || 16;
    if (el.matches("h1,h2,h3")) headingFont = Math.max(headingFont, fontSize);
    else bodyFont = Math.min(bodyFont, fontSize);
    const fg = parseColor(style.color);
    const bg = parseColor(style.backgroundColor) || parseColor(window.getComputedStyle(document.body).backgroundColor);
    const ratio = contrastRatio(fg, bg);
    if (ratio != null && Number.isFinite(ratio)) contrasts.push(ratio);
  });
  if (!headingFont) {
    const heading = semanticElements.find((el) => el.matches("h1,h2,h3"));
    if (heading) {
      headingFont = Number.parseFloat(window.getComputedStyle(heading).fontSize || "16") || 16;
    }
  }
  const interactiveSelector = [
    "button",
    "[role='button']",
    "[role='tab']",
    "[role='switch']",
    "[role='checkbox']",
    "[role='radio']",
    "summary",
    "input:not([type='hidden'])",
    "select",
    "textarea",
    "a[href]"
  ].join(",");
  const interactive = Array.from(document.querySelectorAll(interactiveSelector)).filter(visible);
  const responseRegions = Array.from(document.querySelectorAll("aside, [aria-live], [role='status'], [role='region'], [role='alert']"))
    .filter((el) => visible(el) && String(el.innerText || "").trim().length > 0);
  const activeAffordances = Array.from(document.querySelectorAll("[aria-selected='true'], [aria-expanded='true'], [aria-pressed='true'], [aria-current], input:checked, option:checked, details[open], [open]"))
    .filter(visible);
  const alignments = semanticElements.map((el) => {
    const rect = el.getBoundingClientRect();
    return { left: Math.round(rect.left / 8) * 8, top: Math.round(rect.top / 8) * 8, bottom: Math.round(rect.bottom / 8) * 8, width: rect.width, height: rect.height };
  });
  const leftBuckets = new Map();
  alignments.forEach((rect) => leftBuckets.set(rect.left, (leftBuckets.get(rect.left) || 0) + 1));
  const dominantLeft = Array.from(leftBuckets.values()).sort((a, b) => b - a)[0] || 0;
  const overlapCount = alignments.reduce((sum, rect, index) => {
    return sum + alignments.slice(index + 1).filter((other) =>
      rect.left < other.left + other.width &&
      rect.left + rect.width > other.left &&
      rect.top < other.top + other.height &&
      rect.top + rect.height > other.top
    ).length;
  }, 0);
  const sortedTops = Array.from(new Set(alignments.map((rect) => rect.top))).sort((a, b) => a - b);
  const gaps = sortedTops.slice(1).map((top, index) => top - sortedTops[index]).filter((gap) => gap > 0);
  const avgGap = gaps.length ? gaps.reduce((sum, gap) => sum + gap, 0) / gaps.length : 0;
  const gapStd = gaps.length ? Math.sqrt(gaps.reduce((sum, gap) => sum + Math.pow(gap - avgGap, 2), 0) / gaps.length) : 0;
  const gapConsistency = avgGap > 0 ? Math.max(0, 1 - Math.min(1, gapStd / avgGap)) : 0;
  const responseRegion = responseRegions[0] || null;
  const evidenceSurfaceCount = Array.from(document.querySelectorAll("section, article, aside, figure, svg, canvas, table, [role='region'], [role='tabpanel']"))
    .filter(visible)
    .length;
  return {
    visibleElementCount: semanticElements.length,
    visibleTextChars: textChars,
    interactiveElementCount: interactive.length,
    sectionCount: Array.from(document.querySelectorAll("main, section, article, aside, nav, footer")).filter(visible).length,
    responseRegionCount: responseRegions.length,
    evidenceSurfaceCount,
    actionableAffordanceCount: interactive.length,
    activeAffordanceCount: activeAffordances.length,
    headingCount: Array.from(document.querySelectorAll("h1,h2,h3")).filter(visible).length,
    mainPresent: Boolean(document.querySelector("main")),
    bodyFontSize: bodyFont,
    headingFontSize: headingFont || bodyFont,
    avgTextContrast: contrasts.length ? contrasts.reduce((sum, value) => sum + value, 0) / contrasts.length : 1,
    minTextContrast: contrasts.length ? Math.min(...contrasts) : 1,
    fontFamilyCount: fontFamilies.size,
    dominantLeftAlignmentRatio: semanticElements.length ? dominantLeft / semanticElements.length : 0,
    gapConsistency,
    overlapCount,
    responseRegionText: responseRegion ? (responseRegion.innerText || "").trim() : null
  };
})()"#
}

fn render_runtime_witness_collector_install_script() -> &'static str {
    r#"(() => {
  const root = window.__studioRenderWitness || { errors: [], installed: false };
  if (!Array.isArray(root.errors)) {
    root.errors = [];
  }
  if (!root.installed) {
    window.addEventListener("error", (event) => {
      const detail = event && event.error && event.error.stack
        ? String(event.error.stack)
        : [event?.message, event?.filename, event?.lineno].filter(Boolean).join(" @ ");
      root.errors.push(detail || "window.error");
      root.errors = root.errors.slice(-12);
    });
    window.addEventListener("unhandledrejection", (event) => {
      const reason = event && event.reason
        ? (event.reason.stack || event.reason.message || String(event.reason))
        : "unhandledrejection";
      root.errors.push(String(reason));
      root.errors = root.errors.slice(-12);
    });
    root.installed = true;
  }
  window.__studioRenderWitness = root;
  return true;
})()"#
}

fn render_runtime_witness_state_script() -> &'static str {
    r#"(() => {
  const root = window.__studioRenderWitness || { errors: [] };
  return { errors: Array.isArray(root.errors) ? root.errors.slice(-12) : [] };
})()"#
}

fn render_runtime_witness_clear_script() -> &'static str {
    r#"(() => {
  const root = window.__studioRenderWitness || { errors: [], installed: true };
  root.errors = [];
  window.__studioRenderWitness = root;
  return true;
})()"#
}

fn render_interaction_state_snapshot_script() -> &'static str {
    r##"(() => {
  const visible = (el) => {
    if (!el || typeof el.getBoundingClientRect !== "function") return false;
    const rect = el.getBoundingClientRect();
    if (!(rect.width > 0 && rect.height > 0)) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity || "1") <= 0.02) return false;
    return true;
  };
  const text = (node) => String(node?.innerText || "").replace(/\s+/g, " ").trim();
  const responseTarget = Array.from(document.querySelectorAll("aside, [aria-live], [role='status'], [role='region'], [role='alert']"))
    .find((el) => visible(el) && text(el).length > 0);
  const visibleRegions = Array.from(document.querySelectorAll("main, section, article, aside, nav, footer, figure, table, [role='region'], [role='tabpanel'], svg, canvas"))
    .filter(visible)
    .slice(0, 12)
    .map((el) => el.getAttribute("aria-label") || el.id || text(el).slice(0, 48));
  const activeAffordances = Array.from(document.querySelectorAll("[aria-selected='true'], [aria-expanded='true'], [aria-pressed='true'], [aria-current], input:checked, option:checked, details[open], [open]"))
    .filter(visible)
    .slice(0, 12)
    .map((el) => el.getAttribute("aria-label") || el.id || text(el).slice(0, 32));
  const visibleTextSample = text(document.querySelector("main") || document.body).slice(0, 360);
  const signature = JSON.stringify({
    visibleRegions,
    activeAffordances,
    responseText: responseTarget ? text(responseTarget).slice(0, 200) : null,
    visibleTextSample,
  });
  return {
    signature,
    responseText: responseTarget ? text(responseTarget).slice(0, 200) : null,
    visibleTextSample,
    visibleRegionCount: visibleRegions.length,
    activeAffordanceCount: activeAffordances.length,
  };
})()"##
}

fn render_actionable_controls_script() -> &'static str {
    r##"(() => {
  const visible = (el) => {
    if (!el || typeof el.getBoundingClientRect !== "function") return false;
    const rect = el.getBoundingClientRect();
    if (!(rect.width > 0 && rect.height > 0)) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity || "1") <= 0.02) return false;
    if (el.matches("[disabled],[aria-disabled='true']")) return false;
    return true;
  };
  const text = (value) => String(value || "").replace(/\s+/g, " ").trim();
  const makeSelector = (el) => {
    if (!el) return null;
    const current = el.getAttribute("data-ioi-affordance-id");
    if (current) {
      return `[data-ioi-affordance-id="${CSS.escape(current)}"]`;
    }
    const generated = `aff-${Math.random().toString(36).slice(2, 10)}`;
    el.setAttribute("data-ioi-affordance-id", generated);
    return `[data-ioi-affordance-id="${CSS.escape(generated)}"]`;
  };
  const selector = [
    "button",
    "summary",
    "[role='button']",
    "[role='tab']",
    "[role='switch']",
    "[role='checkbox']",
    "[role='radio']",
    "a[href]",
    "input:not([type='hidden'])",
    "select",
    "textarea"
  ].join(",");
  const seen = new Set();
  return Array.from(document.querySelectorAll(selector))
    .filter(visible)
    .map((el) => {
      const actionKind = el.matches("select")
        ? "select_next"
        : el.matches("input[type='range']")
        ? "input_step"
        : el.matches("input[type='checkbox'], input[type='radio']")
        ? "toggle_input"
        : el.matches("input:not([type='hidden']):not([type='checkbox']):not([type='radio']):not([type='range']), textarea")
        ? "input_text"
        : "click";
      const label = text(
        el.getAttribute("aria-label") ||
          el.innerText ||
          el.value ||
          el.getAttribute("title") ||
          el.id ||
          el.getAttribute("name") ||
          el.tagName
      );
      return {
        selector: makeSelector(el),
        label: label || el.tagName.toLowerCase(),
        actionKind,
        active:
          el.getAttribute("aria-selected") === "true" ||
          el.getAttribute("aria-pressed") === "true" ||
          el.getAttribute("aria-expanded") === "true" ||
          el.hasAttribute("aria-current") ||
          (el.matches("details") && el.hasAttribute("open")) ||
          (el.matches("input[type='checkbox'], input[type='radio']") && el.checked === true)
      };
    })
    .filter((entry) => Boolean(entry.selector))
    .filter((entry) => {
      if (seen.has(entry.selector)) return false;
      seen.add(entry.selector);
      return true;
    })
    .slice(0, 12);
})()"##
}

fn render_action_execution_script(selector: &str, action_kind: &str) -> String {
    let selector_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".to_string());
    let action_kind_json =
        serde_json::to_string(action_kind).unwrap_or_else(|_| "\"click\"".to_string());
    format!(
        r#"(() => {{
  const selector = {selector_json};
  const actionKind = {action_kind_json};
  const el = document.querySelector(selector);
  if (!el) {{
    throw new Error(`missing actionable selector: ${{selector}}`);
  }}
  if (actionKind === "select_next" && el.matches("select")) {{
    if (el.options.length < 2) return true;
    const nextIndex = el.selectedIndex >= 0 ? (el.selectedIndex + 1) % el.options.length : 0;
    el.selectedIndex = nextIndex;
    el.dispatchEvent(new Event("input", {{ bubbles: true }}));
    el.dispatchEvent(new Event("change", {{ bubbles: true }}));
    return true;
  }}
  if (actionKind === "input_step" && el.matches("input")) {{
    const current = Number(el.value || el.min || 0);
    const step = Number(el.step || 1) || 1;
    const next = Number.isFinite(current) ? current + step : step;
    el.value = String(next);
    el.dispatchEvent(new Event("input", {{ bubbles: true }}));
    el.dispatchEvent(new Event("change", {{ bubbles: true }}));
    return true;
  }}
  if (actionKind === "toggle_input" && el.matches("input")) {{
    el.click();
    return true;
  }}
  if (actionKind === "input_text" && (el.matches("input") || el.matches("textarea"))) {{
    const next = `${{el.value || ""}}x`;
    el.value = next;
    el.dispatchEvent(new Event("input", {{ bubbles: true }}));
    el.dispatchEvent(new Event("change", {{ bubbles: true }}));
    return true;
  }}
  el.click();
  return true;
}})()"#
    )
}

fn select_actionable_controls_for_probe(
    discovered: &[ActionableControl],
    max_affordance_probes: usize,
) -> Vec<ActionableControl> {
    let mut seen = HashSet::<String>::new();
    let mut candidates = if discovered.iter().any(|action| !action.active) {
        discovered
            .iter()
            .filter(|action| !action.active)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        discovered.to_vec()
    };
    candidates.retain(|action| seen.insert(action.selector.clone()));
    candidates.truncate(max_affordance_probes);
    candidates
}

fn build_execution_witnesses(
    witnesses: &[WitnessProbeResult],
) -> Vec<StudioArtifactExecutionWitness> {
    witnesses
        .iter()
        .enumerate()
        .map(|(index, witness)| StudioArtifactExecutionWitness {
            witness_id: format!("witness-{}", index + 1),
            obligation_id: Some("controls_execute_cleanly".to_string()),
            action_kind: witness.action.action_kind.clone(),
            status: witness.status,
            summary: witness.summary.clone(),
            detail: witness.detail.clone(),
            selector: Some(witness.action.selector.clone()),
            console_errors: witness.console_errors.clone(),
            state_changed: witness.state_changed,
        })
        .collect()
}

fn build_browser_acceptance_obligations(
    request: &StudioOutcomeArtifactRequest,
    observation: &StudioArtifactRenderObservation,
    acceptance_policy: &StudioArtifactRenderAcceptancePolicy,
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    interaction_expected: bool,
    boot_errors: &[String],
    execution_witnesses: &[StudioArtifactExecutionWitness],
) -> Vec<StudioArtifactAcceptanceObligation> {
    let requires_interaction_contract = request.renderer == StudioRendererKind::HtmlIframe
        && (request.artifact_class == ioi_types::app::StudioArtifactClass::InteractiveSingleFile
            || interaction_expected);
    let successful_witness_count = execution_witnesses
        .iter()
        .filter(|witness| witness.status == StudioArtifactExecutionWitnessStatus::Passed)
        .count();
    let failed_witness_count = execution_witnesses
        .iter()
        .filter(|witness| {
            matches!(
                witness.status,
                StudioArtifactExecutionWitnessStatus::Failed
                    | StudioArtifactExecutionWitnessStatus::Blocked
            )
        })
        .count();
    let witness_ids = execution_witnesses
        .iter()
        .map(|witness| witness.witness_id.clone())
        .collect::<Vec<_>>();
    let mut obligations = vec![
        StudioArtifactAcceptanceObligation {
            obligation_id: "document_complete".to_string(),
            family: "document_truth".to_string(),
            required: true,
            status: if desktop.capture.screenshot_byte_count > 0
                && mobile.capture.screenshot_byte_count > 0
            {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Blocked
            },
            summary: "Studio captured desktop and mobile first paint.".to_string(),
            detail: None,
            witness_ids: Vec::new(),
        },
        StudioArtifactAcceptanceObligation {
            obligation_id: "primary_surface_present".to_string(),
            family: "presentation_truth".to_string(),
            required: true,
            status: if (!acceptance_policy.require_primary_region
                || observation.primary_region_present)
                && observation.first_paint_visible_text_chars
                    >= acceptance_policy.minimum_first_paint_text_chars
            {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Failed
            },
            summary: "The primary artifact surface is visibly present on first paint.".to_string(),
            detail: Some(format!(
                "mainPresent={} desktopVisibleText={} mobileVisibleText={}",
                observation.primary_region_present,
                observation.first_paint_visible_text_chars,
                observation.mobile_visible_text_chars
            )),
            witness_ids: Vec::new(),
        },
        StudioArtifactAcceptanceObligation {
            obligation_id: "runtime_boot_clean".to_string(),
            family: "boot_truth".to_string(),
            required: true,
            status: if boot_errors.is_empty() {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Failed
            },
            summary: "No runtime witness errors were observed while validating the artifact."
                .to_string(),
            detail: if boot_errors.is_empty() {
                None
            } else {
                Some(boot_errors.join(" | "))
            },
            witness_ids: Vec::new(),
        },
        StudioArtifactAcceptanceObligation {
            obligation_id: "artifact_query_outcome_materialized".to_string(),
            family: "query_outcome_truth".to_string(),
            required: true,
            status: if desktop.capture.screenshot_byte_count > 0
                && (!acceptance_policy.require_primary_region || observation.primary_region_present)
            {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Blocked
            },
            summary: "The queried artifact outcome materialized into a renderable surface."
                .to_string(),
            detail: None,
            witness_ids: Vec::new(),
        },
    ];

    if requires_interaction_contract {
        obligations.push(StudioArtifactAcceptanceObligation {
            obligation_id: "controls_discovered".to_string(),
            family: "interaction_truth".to_string(),
            required: true,
            status: if !execution_witnesses.is_empty() {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Failed
            },
            summary: "Studio discovered surfaced controls to exercise.".to_string(),
            detail: Some(format!(
                "desktopActionableAffordances={} witnessedControls={}",
                observation.actionable_affordance_count,
                execution_witnesses.len()
            )),
            witness_ids: witness_ids.clone(),
        });
        if acceptance_policy.require_response_region_when_interactive {
            obligations.push(StudioArtifactAcceptanceObligation {
                obligation_id: "response_region_present".to_string(),
                family: "interaction_truth".to_string(),
                required: true,
                status: if observation.response_region_count > 0 {
                    StudioArtifactAcceptanceObligationStatus::Passed
                } else {
                    StudioArtifactAcceptanceObligationStatus::Failed
                },
                summary:
                    "A visible response or explanation region remains present during interaction."
                        .to_string(),
                detail: Some(format!(
                    "responseRegions={} evidenceSurfaces={}",
                    observation.response_region_count, observation.evidence_surface_count
                )),
                witness_ids: Vec::new(),
            });
        }
        obligations.push(StudioArtifactAcceptanceObligation {
            obligation_id: "default_state_visible".to_string(),
            family: "interaction_truth".to_string(),
            required: true,
            status: if observation.first_paint_visible_text_chars
                >= acceptance_policy.minimum_first_paint_text_chars
                && observation.actionable_affordance_count
                    >= acceptance_policy.minimum_actionable_affordances
            {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Failed
            },
            summary: "The artifact exposes a visible default interactive state on first paint."
                .to_string(),
            detail: Some(format!(
                "desktopVisibleText={} actionableAffordances={} responseRegions={}",
                observation.first_paint_visible_text_chars,
                observation.actionable_affordance_count,
                observation.response_region_count
            )),
            witness_ids: Vec::new(),
        });
        obligations.push(StudioArtifactAcceptanceObligation {
            obligation_id: "controls_execute_cleanly".to_string(),
            family: "interaction_truth".to_string(),
            required: true,
            status: if execution_witnesses.is_empty() {
                StudioArtifactAcceptanceObligationStatus::Failed
            } else if failed_witness_count == 0 {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Failed
            },
            summary: "Surfaced controls executed without runtime errors or no-op behavior."
                .to_string(),
            detail: Some(format!(
                "successfulWitnesses={} failedWitnesses={}",
                successful_witness_count, failed_witness_count
            )),
            witness_ids: witness_ids.clone(),
        });
        obligations.push(StudioArtifactAcceptanceObligation {
            obligation_id: "interaction_witnessed".to_string(),
            family: "interaction_truth".to_string(),
            required: true,
            status: if successful_witness_count > 0
                || !acceptance_policy.require_state_change_when_interactive
            {
                StudioArtifactAcceptanceObligationStatus::Passed
            } else {
                StudioArtifactAcceptanceObligationStatus::Failed
            },
            summary:
                "At least one surfaced interaction produced a meaningful visible state change."
                    .to_string(),
            detail: Some(format!(
                "successfulWitnesses={} failedWitnesses={}",
                successful_witness_count, failed_witness_count
            )),
            witness_ids,
        });
    }

    obligations
}

fn append_obligation_findings(
    findings: &mut Vec<StudioArtifactRenderFinding>,
    obligations: &[StudioArtifactAcceptanceObligation],
) {
    for obligation in obligations {
        if !obligation.required {
            continue;
        }
        let severity = match obligation.status {
            StudioArtifactAcceptanceObligationStatus::Passed
            | StudioArtifactAcceptanceObligationStatus::NotApplicable => continue,
            StudioArtifactAcceptanceObligationStatus::Failed
            | StudioArtifactAcceptanceObligationStatus::Blocked => {
                StudioArtifactRenderFindingSeverity::Blocked
            }
        };
        let summary = obligation
            .detail
            .as_ref()
            .map(|detail| format!("{} {}", obligation.summary, detail))
            .unwrap_or_else(|| obligation.summary.clone());
        if findings.iter().any(|finding| finding.summary == summary) {
            continue;
        }
        findings.push(StudioArtifactRenderFinding {
            code: obligation.obligation_id.clone(),
            severity,
            summary,
        });
    }
}

fn render_evaluation_summary(
    overall_score: u8,
    findings: &[StudioArtifactRenderFinding],
    obligations: &[StudioArtifactAcceptanceObligation],
) -> String {
    let cleared_required = obligations
        .iter()
        .filter(|obligation| obligation.required)
        .filter(|obligation| obligation.status == StudioArtifactAcceptanceObligationStatus::Passed)
        .count();
    let required_total = obligations
        .iter()
        .filter(|obligation| obligation.required)
        .count();
    if findings
        .iter()
        .any(|finding| finding.severity == StudioArtifactRenderFindingSeverity::Blocked)
    {
        return format!(
            "Render evaluation blocked the primary view after clearing {cleared_required}/{required_total} required obligations with an overall score of {overall_score}/25."
        );
    }
    if findings.is_empty() {
        return format!(
            "Render evaluation cleared {cleared_required}/{required_total} required obligations with an overall score of {overall_score}/25."
        );
    }
    format!(
        "Render evaluation found repairable issues after clearing {cleared_required}/{required_total} required obligations with an overall score of {overall_score}/25."
    )
}

fn analyze_screenshot(png: &[u8]) -> Result<ScreenshotAnalysis, String> {
    let image = image::load_from_memory(png)
        .map_err(|error| format!("failed to decode render-eval screenshot: {}", error))?;
    let rgba = image.to_rgba8();
    let mut total = 0f64;
    let mut luminance_sum = 0f64;
    let mut luminance_sq_sum = 0f64;
    let mut histogram = std::collections::HashMap::<(u8, u8, u8), usize>::new();

    for pixel in rgba.pixels().step_by(3) {
        let r = (pixel[0] / 16) * 16;
        let g = (pixel[1] / 16) * 16;
        let b = (pixel[2] / 16) * 16;
        *histogram.entry((r, g, b)).or_insert(0) += 1;
        let luma = (0.2126 * f64::from(pixel[0])
            + 0.7152 * f64::from(pixel[1])
            + 0.0722 * f64::from(pixel[2]))
            / 255.0;
        luminance_sum += luma;
        luminance_sq_sum += luma * luma;
        total += 1.0;
    }

    if total == 0.0 {
        return Ok(ScreenshotAnalysis {
            occupied_ratio: 0.0,
            luminance_stddev: 0.0,
        });
    }

    let dominant = histogram.values().copied().max().unwrap_or_default() as f64 / total;
    let mean = luminance_sum / total;
    let variance = (luminance_sq_sum / total) - mean.powi(2);
    Ok(ScreenshotAnalysis {
        occupied_ratio: (1.0 - dominant).clamp(0.0, 1.0),
        luminance_stddev: variance.max(0.0).sqrt(),
    })
}

fn build_render_observation(
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    interaction: Option<&ViewportCapture>,
    boot_errors: &[String],
    interaction_witnesses: &[WitnessProbeResult],
) -> StudioArtifactRenderObservation {
    StudioArtifactRenderObservation {
        primary_region_present: desktop.dom.main_present || mobile.dom.main_present,
        first_paint_visible_text_chars: desktop
            .capture
            .visible_text_chars
            .max(mobile.capture.visible_text_chars),
        mobile_visible_text_chars: mobile.capture.visible_text_chars,
        semantic_region_count: desktop.dom.section_count.max(mobile.dom.section_count),
        evidence_surface_count: desktop
            .dom
            .evidence_surface_count
            .max(mobile.dom.evidence_surface_count),
        response_region_count: desktop
            .dom
            .response_region_count
            .max(mobile.dom.response_region_count),
        actionable_affordance_count: desktop
            .dom
            .actionable_affordance_count
            .max(mobile.dom.actionable_affordance_count),
        active_affordance_count: desktop
            .dom
            .active_affordance_count
            .max(mobile.dom.active_affordance_count),
        runtime_error_count: boot_errors.len(),
        interaction_state_changed: interaction
            .map(|capture| capture.capture.screenshot_changed_from_previous)
            .unwrap_or(false)
            || interaction_witnesses
                .iter()
                .any(|witness| witness.state_changed),
    }
}

fn score_render_evaluation(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    interaction: Option<&ViewportCapture>,
    interaction_expected: bool,
    boot_errors: &[String],
    interaction_witnesses: &[WitnessProbeResult],
    acceptance_policy: StudioArtifactRenderAcceptancePolicy,
) -> StudioArtifactRenderEvaluation {
    let observation = build_render_observation(
        desktop,
        mobile,
        interaction,
        boot_errors,
        interaction_witnesses,
    );
    let scoring_policy = BrowserRenderScoringPolicy::default();
    let layout_density_score = score_layout_density(desktop, mobile, scoring_policy.layout_density);
    let spacing_alignment_score =
        score_spacing_alignment(desktop, mobile, scoring_policy.spacing_alignment);
    let typography_contrast_score = score_typography(desktop, mobile, scoring_policy.typography);
    let visual_hierarchy_score =
        score_visual_hierarchy(desktop, mobile, scoring_policy.visual_hierarchy);
    let blueprint_consistency_score = score_blueprint_consistency(
        brief,
        blueprint,
        artifact_ir,
        desktop,
        mobile,
        interaction,
        interaction_expected,
    );
    let overall_score = layout_density_score
        + spacing_alignment_score
        + typography_contrast_score
        + visual_hierarchy_score
        + blueprint_consistency_score;
    let execution_witnesses = build_execution_witnesses(interaction_witnesses);
    let acceptance_obligations = build_browser_acceptance_obligations(
        request,
        &observation,
        &acceptance_policy,
        desktop,
        mobile,
        interaction_expected,
        boot_errors,
        &execution_witnesses,
    );

    let mut findings = Vec::<StudioArtifactRenderFinding>::new();
    if desktop.capture.screenshot_byte_count == 0 || mobile.capture.screenshot_byte_count == 0 {
        findings.push(StudioArtifactRenderFinding {
            code: "capture_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: "Desktop and mobile render captures must both exist before Studio can trust the surfaced first paint."
                .to_string(),
        });
    }
    if layout_density_score <= 2 {
        findings.push(StudioArtifactRenderFinding {
            code: "layout_density_low".to_string(),
            severity: if observation.first_paint_visible_text_chars
                < acceptance_policy.minimum_first_paint_text_chars
            {
                StudioArtifactRenderFindingSeverity::Blocked
            } else {
                StudioArtifactRenderFindingSeverity::Warning
            },
            summary: "The first paint stays too sparse across captured viewports to qualify as a strong surfaced artifact."
                .to_string(),
        });
    }
    if spacing_alignment_score <= 2 {
        findings.push(StudioArtifactRenderFinding {
            code: "alignment_unstable".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Warning,
            summary: "Captured viewports show weak alignment or inconsistent spacing cadence."
                .to_string(),
        });
    }
    if typography_contrast_score <= 2 {
        findings.push(StudioArtifactRenderFinding {
            code: "typography_contrast_low".to_string(),
            severity: if matches!(
                request.renderer,
                StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed
            ) {
                StudioArtifactRenderFindingSeverity::Warning
            } else if desktop.dom.min_text_contrast < 2.8 {
                StudioArtifactRenderFindingSeverity::Blocked
            } else {
                StudioArtifactRenderFindingSeverity::Warning
            },
            summary: "Readable text contrast or typographic separation is still too weak in the captured render."
                .to_string(),
        });
    }
    if visual_hierarchy_score <= 2 {
        findings.push(StudioArtifactRenderFinding {
            code: "visual_hierarchy_flat".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Warning,
            summary: "The capture reads as visually flat instead of establishing a clear first-paint hierarchy."
                .to_string(),
        });
    }
    if blueprint_consistency_score <= 2 {
        findings.push(StudioArtifactRenderFinding {
            code: "blueprint_consistency_low".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: "The captured render does not satisfy enough of the typed blueprint and interaction contract."
                .to_string(),
        });
    }
    if !boot_errors.is_empty() {
        findings.push(StudioArtifactRenderFinding {
            code: "runtime_boot_errors".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: format!(
                "Runtime witness evaluation observed browser errors while validating the artifact. {}",
                boot_errors.join(" | ")
            ),
        });
    }
    if interaction_expected
        && acceptance_policy.require_state_change_when_interactive
        && interaction.is_none()
    {
        findings.push(StudioArtifactRenderFinding {
            code: "interaction_capture_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: "The artifact promised interactive behavior, but render evaluation could not confirm a visible state change."
                .to_string(),
        });
    } else if interaction_expected
        && acceptance_policy.require_state_change_when_interactive
        && interaction.is_some_and(|capture| !capture.capture.screenshot_changed_from_previous)
    {
        findings.push(StudioArtifactRenderFinding {
            code: "interaction_change_weak".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Warning,
            summary: "An interaction was captured, but it barely changed the rendered state."
                .to_string(),
        });
    }
    if request.renderer == StudioRendererKind::HtmlIframe
        && acceptance_policy.require_primary_region
        && !observation.primary_region_present
    {
        findings.push(StudioArtifactRenderFinding {
            code: "main_region_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: "HTML artifact render is missing a visible <main> region during capture."
                .to_string(),
        });
    }
    append_obligation_findings(&mut findings, &acceptance_obligations);

    let summary = render_evaluation_summary(overall_score, &findings, &acceptance_obligations);

    let mut captures = vec![desktop.capture.clone(), mobile.capture.clone()];
    if let Some(interaction) = interaction {
        captures.push(interaction.capture.clone());
    }

    StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: interaction_expected,
        captures,
        observation: Some(observation),
        acceptance_policy: Some(acceptance_policy),
        layout_density_score,
        spacing_alignment_score,
        typography_contrast_score,
        visual_hierarchy_score,
        blueprint_consistency_score,
        overall_score,
        findings,
        acceptance_obligations,
        execution_witnesses,
        summary,
    }
}

fn score_layout_density(
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    policy: LayoutDensityScorePolicy,
) -> u8 {
    let visible_elements = desktop
        .dom
        .visible_element_count
        .max(mobile.dom.visible_element_count);
    let visible_text = desktop
        .dom
        .visible_text_chars
        .max(mobile.dom.visible_text_chars);
    let occupied_ratio = desktop
        .analysis
        .occupied_ratio
        .max(mobile.analysis.occupied_ratio);
    let section_count = desktop.dom.section_count.max(mobile.dom.section_count);
    let mut score = 1;
    if visible_elements >= policy.medium_visible_elements
        || visible_text >= policy.medium_visible_text_chars
    {
        score += 1;
    }
    if occupied_ratio >= policy.medium_occupied_ratio
        || section_count >= policy.medium_section_count
    {
        score += 1;
    }
    if visible_elements >= policy.strong_visible_elements
        && visible_text >= policy.strong_visible_text_chars
        && occupied_ratio >= policy.strong_occupied_ratio
    {
        score += 1;
    }
    if visible_elements >= policy.full_visible_elements
        && visible_text >= policy.full_visible_text_chars
        && occupied_ratio >= policy.full_occupied_ratio
    {
        score += 1;
    }
    score
}

fn score_spacing_alignment(
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    policy: SpacingAlignmentScorePolicy,
) -> u8 {
    let dominant_alignment = desktop
        .dom
        .dominant_left_alignment_ratio
        .max(mobile.dom.dominant_left_alignment_ratio);
    let gap_consistency = desktop.dom.gap_consistency.max(mobile.dom.gap_consistency);
    let overlap_count = desktop.dom.overlap_count + mobile.dom.overlap_count;
    let mut score = 1;
    if overlap_count == 0 {
        score += 1;
    }
    if dominant_alignment >= policy.medium_alignment_ratio {
        score += 1;
    }
    if gap_consistency >= policy.strong_gap_consistency {
        score += 1;
    }
    if overlap_count == 0
        && dominant_alignment >= policy.full_alignment_ratio
        && gap_consistency >= policy.full_gap_consistency
    {
        score += 1;
    }
    score
}

fn score_typography(
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    policy: TypographyScorePolicy,
) -> u8 {
    let avg_contrast = desktop
        .dom
        .avg_text_contrast
        .max(mobile.dom.avg_text_contrast);
    let min_contrast = desktop
        .dom
        .min_text_contrast
        .max(mobile.dom.min_text_contrast);
    let heading_ratio = (desktop.dom.heading_font_size / desktop.dom.body_font_size.max(1.0))
        .max(mobile.dom.heading_font_size / mobile.dom.body_font_size.max(1.0));
    let font_family_count = desktop
        .dom
        .font_family_count
        .max(mobile.dom.font_family_count);
    let mut score = 1;
    if avg_contrast >= policy.medium_avg_contrast {
        score += 1;
    }
    if min_contrast >= policy.strong_min_contrast {
        score += 1;
    }
    if heading_ratio >= policy.strong_heading_ratio {
        score += 1;
    }
    if avg_contrast >= policy.full_avg_contrast
        && heading_ratio >= policy.full_heading_ratio
        && font_family_count >= 1
    {
        score += 1;
    }
    score
}

fn score_visual_hierarchy(
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    policy: VisualHierarchyScorePolicy,
) -> u8 {
    let heading_count = desktop.dom.heading_count.max(mobile.dom.heading_count);
    let heading_ratio = (desktop.dom.heading_font_size / desktop.dom.body_font_size.max(1.0))
        .max(mobile.dom.heading_font_size / mobile.dom.body_font_size.max(1.0));
    let evidence_surface_count = desktop
        .dom
        .evidence_surface_count
        .max(mobile.dom.evidence_surface_count);
    let luminance_stddev = desktop
        .analysis
        .luminance_stddev
        .max(mobile.analysis.luminance_stddev);
    let mut score = 1;
    if heading_count >= 1 {
        score += 1;
    }
    if heading_ratio >= policy.strong_heading_ratio {
        score += 1;
    }
    if evidence_surface_count >= policy.strong_evidence_surface_count
        || luminance_stddev >= policy.strong_luminance_stddev
    {
        score += 1;
    }
    if heading_count >= policy.full_heading_count
        && evidence_surface_count >= policy.full_evidence_surface_count
        && luminance_stddev >= policy.full_luminance_stddev
    {
        score += 1;
    }
    score
}

fn score_blueprint_consistency(
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    interaction: Option<&ViewportCapture>,
    interaction_expected: bool,
) -> u8 {
    let document_like_brief = matches!(
        blueprint.map(|value| value.renderer),
        Some(StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed)
    ) || (brief.required_interactions.is_empty()
        && brief
            .audience
            .trim()
            .to_ascii_lowercase()
            .starts_with("people reviewing the")
        && brief
            .artifact_thesis
            .trim()
            .to_ascii_lowercase()
            .contains(" document"));
    if document_like_brief {
        let captured_sections = desktop.dom.section_count.max(mobile.dom.section_count);
        let visible_text_chars = desktop
            .capture
            .visible_text_chars
            .max(mobile.capture.visible_text_chars);
        let ir_interaction_targets = artifact_ir
            .map(|value| value.interaction_graph.len())
            .unwrap_or_default();
        let mut score = 1;
        if desktop.dom.main_present && visible_text_chars >= 80 {
            score += 1;
        }
        if captured_sections >= 1 {
            score += 1;
        }
        if visible_text_chars >= 220 {
            score += 1;
        }
        if !interaction_expected || interaction.is_none() || ir_interaction_targets == 0 {
            score += 1;
        }
        return score;
    }

    let target_sections = blueprint
        .map(|value| value.section_plan.len())
        .unwrap_or_else(|| brief.required_concepts.len().max(2))
        .max(1);
    let captured_sections = desktop.dom.section_count.max(mobile.dom.section_count);
    let response_regions = desktop
        .dom
        .response_region_count
        .max(mobile.dom.response_region_count);
    let evidence_surfaces = desktop
        .dom
        .evidence_surface_count
        .max(mobile.dom.evidence_surface_count);
    let interaction_changed = interaction
        .map(|capture| capture.capture.screenshot_changed_from_previous)
        .unwrap_or(false);
    let ir_interaction_targets = artifact_ir
        .map(|value| value.interaction_graph.len())
        .unwrap_or_default();
    let mut score = 1;
    if desktop.dom.main_present && captured_sections >= 2 {
        score += 1;
    }
    if captured_sections >= target_sections.min(3) {
        score += 1;
    }
    if response_regions >= 1 || evidence_surfaces >= 2 {
        score += 1;
    }
    if !interaction_expected || interaction_changed || ir_interaction_targets == 0 {
        score += 1;
    }
    score
}

#[cfg(test)]
#[path = "studio_render/tests.rs"]
mod tests;

fn browser_error_to_string(error: BrowserError) -> String {
    error.to_string()
}
