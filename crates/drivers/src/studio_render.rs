use crate::browser::{BrowserDriver, BrowserError};
use async_trait::async_trait;
use ioi_api::studio::{
    StudioArtifactBlueprint, StudioArtifactBrief, StudioArtifactEditIntent, StudioArtifactIR,
    StudioArtifactRenderCapture, StudioArtifactRenderCaptureViewport,
    StudioArtifactRenderEvaluation, StudioArtifactRenderEvaluator, StudioArtifactRenderFinding,
    StudioArtifactRenderFindingSeverity, StudioGeneratedArtifactFile,
    StudioGeneratedArtifactPayload,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{StudioOutcomeArtifactRequest, StudioRendererKind};
use serde::Deserialize;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DESKTOP_VIEWPORT: (u32, u32) = (1440, 960);
const MOBILE_VIEWPORT: (u32, u32) = (390, 844);
const CAPTURE_SETTLE_MS: u64 = 140;

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
    detail_region_count: usize,
    evidence_surface_count: usize,
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

impl BrowserStudioArtifactRenderEvaluator {
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
    ) -> Result<ViewportCapture, String> {
        tokio::time::sleep(Duration::from_millis(CAPTURE_SETTLE_MS)).await;
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

    async fn maybe_capture_interaction(
        &self,
        interaction_expected: bool,
        previous_sha: Option<&str>,
    ) -> Result<Option<ViewportCapture>, String> {
        if !interaction_expected {
            return Ok(None);
        }
        let selector = self
            .browser
            .evaluate_js::<Option<String>>(render_primary_action_script())
            .await
            .map_err(browser_error_to_string)?;
        let Some(selector) = selector else {
            return Ok(None);
        };
        self.browser
            .click_selector(&selector)
            .await
            .map_err(browser_error_to_string)?;
        self.capture_viewport(
            StudioArtifactRenderCaptureViewport::Interaction,
            DESKTOP_VIEWPORT.0,
            DESKTOP_VIEWPORT.1,
            previous_sha,
        )
        .await
        .map(Some)
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
            )
            .await?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:mobile:ok bytes={} elapsed_ms={}",
            mobile.capture.screenshot_byte_count,
            started_at.elapsed().as_millis()
        ));
        let interaction_expected = !brief.required_interactions.is_empty()
            || blueprint
                .map(|value| !value.interaction_plan.is_empty())
                .unwrap_or(false)
            || artifact_ir
                .map(|value| !value.interaction_graph.is_empty())
                .unwrap_or(false);
        studio_render_trace(format!(
            "artifact_generation:render_eval:interaction:start expected={} elapsed_ms={}",
            interaction_expected,
            started_at.elapsed().as_millis()
        ));
        let interaction = self
            .maybe_capture_interaction(
                interaction_expected,
                Some(&desktop.capture.screenshot_sha256),
            )
            .await?;
        studio_render_trace(format!(
            "artifact_generation:render_eval:interaction:ok captured={} elapsed_ms={}",
            interaction.is_some(),
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
    "[role='tab']",
    "[data-view]",
    "[data-target]",
    "summary",
    "input:not([type='hidden'])",
    "select",
    "textarea",
    "a[href^='#']"
  ].join(",");
  const interactive = Array.from(document.querySelectorAll(interactiveSelector)).filter(visible);
  const tagged = interactive.find((el) => el.hasAttribute("data-studio-render-primary-action"));
  const actionTarget = tagged || interactive[0] || null;
  if (actionTarget && !actionTarget.hasAttribute("data-studio-render-primary-action")) {
    actionTarget.setAttribute("data-studio-render-primary-action", "true");
  }
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
  const detail = Array.from(document.querySelectorAll("aside, [data-detail], [data-studio-shared-detail='true']")).find(visible);
  const evidenceSurfaceCount = Array.from(document.querySelectorAll("[data-view-panel], [data-panel], [role='tabpanel'], svg, canvas, table, figure"))
    .filter(visible)
    .length;
  return {
    visibleElementCount: semanticElements.length,
    visibleTextChars: textChars,
    interactiveElementCount: interactive.length,
    sectionCount: Array.from(document.querySelectorAll("main, section, article, aside, nav, footer")).filter(visible).length,
    detailRegionCount: detail ? 1 : 0,
    evidenceSurfaceCount,
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
    primaryActionSelector: actionTarget ? "[data-studio-render-primary-action='true']" : null,
    detailCopy: detail ? (detail.innerText || "").trim() : null
  };
})()"#
}

fn render_primary_action_script() -> &'static str {
    r#"(() => {
  const el = document.querySelector("[data-studio-render-primary-action='true']");
  return el ? "[data-studio-render-primary-action='true']" : null;
})()"#
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

fn score_render_evaluation(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    desktop: &ViewportCapture,
    mobile: &ViewportCapture,
    interaction: Option<&ViewportCapture>,
    interaction_expected: bool,
) -> StudioArtifactRenderEvaluation {
    let layout_density_score = score_layout_density(desktop, mobile);
    let spacing_alignment_score = score_spacing_alignment(desktop, mobile);
    let typography_contrast_score = score_typography(desktop, mobile);
    let visual_hierarchy_score = score_visual_hierarchy(desktop, mobile);
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
            severity: if desktop.dom.visible_text_chars < 80 {
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
            severity: if desktop.dom.min_text_contrast < 2.8 {
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
    if interaction_expected && interaction.is_none() {
        findings.push(StudioArtifactRenderFinding {
            code: "interaction_capture_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: "The artifact promised interactive behavior, but render evaluation could not confirm a visible state change."
                .to_string(),
        });
    } else if interaction_expected
        && interaction.is_some_and(|capture| !capture.capture.screenshot_changed_from_previous)
    {
        findings.push(StudioArtifactRenderFinding {
            code: "interaction_change_weak".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Warning,
            summary: "An interaction was captured, but it barely changed the rendered state."
                .to_string(),
        });
    }
    if request.renderer == StudioRendererKind::HtmlIframe && !desktop.dom.main_present {
        findings.push(StudioArtifactRenderFinding {
            code: "main_region_missing".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: "HTML artifact render is missing a visible <main> region during capture."
                .to_string(),
        });
    }

    let summary = if findings
        .iter()
        .any(|finding| finding.severity == StudioArtifactRenderFindingSeverity::Blocked)
    {
        format!(
            "Render evaluation blocked the primary view after desktop/mobile capture with an overall score of {overall_score}/25."
        )
    } else if findings.is_empty() {
        format!(
            "Render evaluation cleared desktop/mobile capture with an overall score of {overall_score}/25."
        )
    } else {
        format!(
            "Render evaluation found repairable desktop/mobile issues with an overall score of {overall_score}/25."
        )
    };

    let mut captures = vec![desktop.capture.clone(), mobile.capture.clone()];
    if let Some(interaction) = interaction {
        captures.push(interaction.capture.clone());
    }

    StudioArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: interaction_expected,
        captures,
        layout_density_score,
        spacing_alignment_score,
        typography_contrast_score,
        visual_hierarchy_score,
        blueprint_consistency_score,
        overall_score,
        findings,
        summary,
    }
}

fn score_layout_density(desktop: &ViewportCapture, mobile: &ViewportCapture) -> u8 {
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
    if visible_elements >= 8 || visible_text >= 120 {
        score += 1;
    }
    if occupied_ratio >= 0.16 || section_count >= 3 {
        score += 1;
    }
    if visible_elements >= 16 && visible_text >= 220 && occupied_ratio >= 0.24 {
        score += 1;
    }
    if visible_elements >= 24 && visible_text >= 320 && occupied_ratio >= 0.32 {
        score += 1;
    }
    score
}

fn score_spacing_alignment(desktop: &ViewportCapture, mobile: &ViewportCapture) -> u8 {
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
    if dominant_alignment >= 0.35 {
        score += 1;
    }
    if gap_consistency >= 0.45 {
        score += 1;
    }
    if overlap_count == 0 && dominant_alignment >= 0.55 && gap_consistency >= 0.6 {
        score += 1;
    }
    score
}

fn score_typography(desktop: &ViewportCapture, mobile: &ViewportCapture) -> u8 {
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
    if avg_contrast >= 3.5 {
        score += 1;
    }
    if min_contrast >= 3.0 {
        score += 1;
    }
    if heading_ratio >= 1.45 {
        score += 1;
    }
    if avg_contrast >= 4.5 && heading_ratio >= 1.75 && font_family_count >= 1 {
        score += 1;
    }
    score
}

fn score_visual_hierarchy(desktop: &ViewportCapture, mobile: &ViewportCapture) -> u8 {
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
    if heading_ratio >= 1.6 {
        score += 1;
    }
    if evidence_surface_count >= 2 || luminance_stddev >= 0.14 {
        score += 1;
    }
    if heading_count >= 2 && evidence_surface_count >= 3 && luminance_stddev >= 0.18 {
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
    let target_sections = blueprint
        .map(|value| value.section_plan.len())
        .unwrap_or_else(|| brief.required_concepts.len().max(2))
        .max(1);
    let captured_sections = desktop.dom.section_count.max(mobile.dom.section_count);
    let detail_regions = desktop
        .dom
        .detail_region_count
        .max(mobile.dom.detail_region_count);
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
    if detail_regions >= 1 || evidence_surfaces >= 2 {
        score += 1;
    }
    if !interaction_expected || interaction_changed || ir_interaction_targets == 0 {
        score += 1;
    }
    score
}

fn browser_error_to_string(error: BrowserError) -> String {
    error.to_string()
}
