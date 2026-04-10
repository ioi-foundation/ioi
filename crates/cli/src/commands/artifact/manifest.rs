use anyhow::{bail, Context, Result};
use ioi_api::studio::{count_pdf_structural_sections, extract_searchable_pdf_text};
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactLifecycleState, StudioArtifactManifest,
    StudioArtifactManifestFile, StudioArtifactTabKind, StudioArtifactVerificationStatus,
    StudioOutcomePlanningPayload, StudioRendererKind, StudioRuntimeProvenance,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use super::types::{ArtifactInspection, ComposedVerifiedReply};

pub(super) fn run_inspect(manifest_path: &Path, json_output: bool) -> Result<()> {
    let manifest = load_manifest(manifest_path)?;
    let inspection = inspection_for_manifest(&manifest);
    let validation_errors = validate_manifest(&manifest);

    if json_output {
        #[derive(Serialize)]
        struct JsonOutput<'a> {
            inspection: &'a ArtifactInspection,
            valid: bool,
            validation_errors: &'a [String],
        }

        println!(
            "{}",
            serde_json::to_string_pretty(&JsonOutput {
                inspection: &inspection,
                valid: validation_errors.is_empty(),
                validation_errors: &validation_errors,
            })?
        );
        return Ok(());
    }

    println!("Artifact: {}", inspection.title);
    println!("  id: {}", inspection.artifact_id);
    println!("  class: {}", inspection.artifact_class);
    println!("  renderer: {}", inspection.renderer);
    println!(
        "  verification: {} / {} ({})",
        inspection.verification_status, inspection.lifecycle_state, inspection.verification_summary
    );
    println!("  primary tab: {}", inspection.primary_tab);
    println!(
        "  files: {} total, {} renderable, {} downloadable",
        inspection.file_count, inspection.renderable_file_count, inspection.downloadable_file_count
    );
    println!(
        "  primary stage: {} (render surface: {})",
        inspection.preferred_stage_mode,
        if inspection.render_surface_available {
            "verified"
        } else {
            "source-first"
        }
    );
    println!(
        "  package mode: {}",
        if inspection.repo_centric_package {
            "repo-centric"
        } else {
            "single-artifact"
        }
    );
    if let Some(provenance) = &inspection.production_provenance {
        println!(
            "  production provenance: {}",
            format_runtime_provenance(provenance)
        );
    }
    if let Some(provenance) = &inspection.acceptance_provenance {
        println!(
            "  acceptance provenance: {}",
            format_runtime_provenance(provenance)
        );
    }
    if let Some(failure) = &inspection.failure {
        println!("  failure: {} ({})", failure.message, failure.code);
    }

    if validation_errors.is_empty() {
        println!("  validation: OK");
    } else {
        println!("  validation: FAILED");
        for error in validation_errors {
            println!("    - {}", error);
        }
    }

    Ok(())
}

pub(super) fn run_validate(manifest_path: &Path, source_root: Option<&Path>) -> Result<()> {
    let manifest = load_manifest(manifest_path)?;
    let mut validation_errors = validate_manifest(&manifest);
    if let Some(source_root) = source_root {
        validation_errors.extend(validate_materialized_files(&manifest, source_root));
    }
    if validation_errors.is_empty() {
        let title = if manifest.title.trim().is_empty() {
            "untitled artifact"
        } else {
            manifest.title.trim()
        };
        println!("Artifact manifest '{}' is valid.", title);
        return Ok(());
    }

    for error in &validation_errors {
        eprintln!("- {}", error);
    }
    bail!(
        "Artifact manifest validation failed with {} error(s).",
        validation_errors.len()
    );
}

pub(super) fn run_materialize(
    manifest_path: &Path,
    source_root: &Path,
    output: &Path,
    force: bool,
) -> Result<()> {
    let manifest = load_manifest(manifest_path)?;
    let mut validation_errors = validate_manifest(&manifest);
    validation_errors.extend(validate_materialized_files(&manifest, source_root));
    if !validation_errors.is_empty() {
        bail!(
            "Artifact manifest is invalid and cannot be materialized:\n{}",
            validation_errors.join("\n")
        );
    }

    prepare_output_directory(output, force)?;

    for file in &manifest.files {
        if file.external_url.is_some() {
            bail!(
                "Cannot materialize '{}' because it is external-only. Export or fetch the source locally first.",
                file.path
            );
        }

        let source_path = source_root.join(&file.path);
        if !source_path.exists() {
            bail!(
                "Manifest file '{}' was not found under source root '{}'.",
                file.path,
                source_root.display()
            );
        }

        let target_path = output.join(&file.path);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent directory '{}' for '{}'.",
                    parent.display(),
                    target_path.display()
                )
            })?;
        }
        fs::copy(&source_path, &target_path).with_context(|| {
            format!(
                "Failed to copy '{}' into artifact package '{}'.",
                source_path.display(),
                target_path.display()
            )
        })?;
    }

    let packaged_manifest_path = output.join("artifact-manifest.json");
    fs::write(
        &packaged_manifest_path,
        serde_json::to_vec_pretty(&manifest).context("Failed to serialize artifact manifest.")?,
    )
    .with_context(|| {
        format!(
            "Failed to write packaged manifest '{}'.",
            packaged_manifest_path.display()
        )
    })?;

    let readme_path = output.join("README.md");
    fs::write(&readme_path, build_package_readme(&manifest)).with_context(|| {
        format!(
            "Failed to write artifact package README '{}'.",
            readme_path.display()
        )
    })?;

    println!(
        "Materialized artifact package '{}' into '{}'.",
        manifest.title,
        output.display()
    );
    println!(
        "Packaged {} file(s) and wrote '{}'.",
        manifest.files.len(),
        packaged_manifest_path.display()
    );
    Ok(())
}

pub(super) fn run_compose_reply(manifest_path: &Path, json_output: bool) -> Result<()> {
    let manifest = load_manifest(manifest_path)?;
    let reply = compose_verified_reply(&manifest);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&reply)?);
        return Ok(());
    }

    println!("{}", reply.title);
    println!("  status: {}", reply.status);
    println!("  lifecycle: {}", reply.lifecycle_state);
    println!("  summary: {}", reply.summary);
    if !reply.evidence.is_empty() {
        println!("  evidence:");
        for evidence in &reply.evidence {
            println!("    - {}", evidence);
        }
    }
    if let Some(provenance) = &reply.production_provenance {
        println!(
            "  production provenance: {}",
            format_runtime_provenance(provenance)
        );
    }
    if let Some(provenance) = &reply.acceptance_provenance {
        println!(
            "  acceptance provenance: {}",
            format_runtime_provenance(provenance)
        );
    }
    if let Some(failure) = &reply.failure {
        println!("  failure: {} ({})", failure.message, failure.code);
    }
    Ok(())
}

pub(super) fn load_manifest(path: &Path) -> Result<StudioArtifactManifest> {
    let bytes = fs::read(path)
        .with_context(|| format!("Failed to read artifact manifest '{}'.", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("Failed to parse artifact manifest '{}'.", path.display()))
}

pub(super) fn inspection_for_manifest(manifest: &StudioArtifactManifest) -> ArtifactInspection {
    ArtifactInspection {
        artifact_id: manifest.artifact_id.clone(),
        title: manifest.title.clone(),
        artifact_class: artifact_class_label(manifest.artifact_class),
        renderer: renderer_label(manifest.renderer),
        verification_status: verification_status_label(manifest),
        lifecycle_state: lifecycle_state_label(manifest.verification.lifecycle_state),
        verification_summary: manifest.verification.summary.clone(),
        primary_tab: manifest.primary_tab.clone(),
        tab_count: manifest.tabs.len(),
        file_count: manifest.files.len(),
        renderable_file_count: manifest.files.iter().filter(|file| file.renderable).count(),
        downloadable_file_count: manifest
            .files
            .iter()
            .filter(|file| file.downloadable)
            .count(),
        repo_centric_package: manifest.renderer == StudioRendererKind::WorkspaceSurface
            || manifest.files.len() > 1
            || matches!(
                manifest.artifact_class,
                StudioArtifactClass::WorkspaceProject
                    | StudioArtifactClass::CompoundBundle
                    | StudioArtifactClass::ReportBundle
            ),
        render_surface_available: render_surface_available_for_manifest(manifest),
        preferred_stage_mode: preferred_stage_mode_for_manifest(manifest).to_string(),
        production_provenance: manifest.verification.production_provenance.clone(),
        acceptance_provenance: manifest.verification.acceptance_provenance.clone(),
        failure: manifest.verification.failure.clone(),
    }
}

pub(super) fn validate_manifest(manifest: &StudioArtifactManifest) -> Vec<String> {
    let mut errors = Vec::new();

    if manifest.artifact_id.trim().is_empty() {
        errors.push("artifactId must not be empty.".to_string());
    }
    if manifest.title.trim().is_empty() {
        errors.push("title must not be empty.".to_string());
    }
    if manifest.tabs.is_empty() {
        errors.push("tabs must contain at least one entry.".to_string());
    }
    if manifest.files.is_empty()
        && matches!(
            manifest.verification.status,
            StudioArtifactVerificationStatus::Ready | StudioArtifactVerificationStatus::Partial
        )
    {
        errors.push(
            "files must contain at least one entry for ready or partial artifacts.".to_string(),
        );
    }

    let mut tab_ids = HashSet::new();
    let mut has_primary_tab = false;
    for tab in &manifest.tabs {
        if tab.id.trim().is_empty() {
            errors.push("tab id must not be empty.".to_string());
        }
        if !tab_ids.insert(tab.id.clone()) {
            errors.push(format!("duplicate tab id '{}'.", tab.id));
        }
        if tab.id == manifest.primary_tab {
            has_primary_tab = true;
        }
    }
    if !has_primary_tab {
        errors.push(format!(
            "primaryTab '{}' does not match any tab id.",
            manifest.primary_tab
        ));
    }

    let mut file_paths = HashSet::new();
    for file in &manifest.files {
        if file.path.trim().is_empty() {
            errors.push("file path must not be empty.".to_string());
        }
        if !file_paths.insert(file.path.clone()) {
            errors.push(format!("duplicate file path '{}'.", file.path));
        }
    }

    for tab in &manifest.tabs {
        if let Some(file_path) = &tab.file_path {
            if !file_paths.contains(file_path) {
                errors.push(format!(
                    "tab '{}' references missing file '{}'.",
                    tab.id, file_path
                ));
            }
        }
    }

    match manifest.renderer {
        StudioRendererKind::WorkspaceSurface
            if manifest.artifact_class != StudioArtifactClass::WorkspaceProject =>
        {
            errors.push(
                "workspace_surface renderer requires artifactClass=workspace_project.".to_string(),
            );
        }
        StudioRendererKind::BundleManifest
            if !matches!(
                manifest.artifact_class,
                StudioArtifactClass::CompoundBundle | StudioArtifactClass::ReportBundle
            ) =>
        {
            errors.push(
                "bundle_manifest renderer requires artifactClass=compound_bundle or report_bundle."
                    .to_string(),
            );
        }
        StudioRendererKind::DownloadCard if manifest.files.iter().any(|file| file.renderable) => {
            errors.push(
                "download_card renderer should not mark files as renderable in the manifest."
                    .to_string(),
            );
        }
        _ => {}
    }

    if manifest.renderer != StudioRendererKind::DownloadCard
        && !manifest.files.iter().any(|file| file.renderable)
        && !manifest_is_truthful_failure_envelope(manifest)
    {
        errors.push(
            "non-download_card renderers must include at least one renderable file.".to_string(),
        );
    }

    errors
}

pub(super) fn manifest_is_truthful_failure_envelope(manifest: &StudioArtifactManifest) -> bool {
    matches!(
        manifest.verification.status,
        StudioArtifactVerificationStatus::Blocked | StudioArtifactVerificationStatus::Failed
    ) && manifest.verification.failure.is_some()
        && manifest.primary_tab == "evidence"
        && manifest
            .tabs
            .iter()
            .any(|tab| tab.id == "evidence" && tab.kind == StudioArtifactTabKind::Evidence)
}

pub(super) fn validate_materialized_files(
    manifest: &StudioArtifactManifest,
    source_root: &Path,
) -> Vec<String> {
    let mut errors = Vec::new();
    for file in &manifest.files {
        if file.external_url.is_some() {
            continue;
        }
        let path = source_root.join(&file.path);
        if !path.exists() {
            errors.push(format!(
                "manifest file '{}' does not exist under '{}'.",
                file.path,
                source_root.display()
            ));
        }
    }

    if manifest_is_truthful_failure_envelope(manifest) {
        return errors;
    }

    let Some(primary_file) = primary_file_for_manifest(manifest) else {
        errors.push("could not resolve a primary file for renderer validation.".to_string());
        return errors;
    };
    let primary_path = source_root.join(&primary_file.path);
    if !primary_path.exists() {
        return errors;
    }

    match manifest.renderer {
        StudioRendererKind::Markdown => {
            validate_utf8_contains(&primary_path, &["#"], "markdown", &mut errors);
        }
        StudioRendererKind::HtmlIframe => {
            validate_utf8_contains(
                &primary_path,
                &["<html", "<!doctype html"],
                "HTML",
                &mut errors,
            );
        }
        StudioRendererKind::JsxSandbox => {
            validate_utf8_contains(
                &primary_path,
                &["export default", "return ("],
                "JSX sandbox",
                &mut errors,
            );
        }
        StudioRendererKind::Svg => {
            validate_utf8_contains(&primary_path, &["<svg"], "SVG", &mut errors);
        }
        StudioRendererKind::Mermaid => {
            validate_utf8_contains(
                &primary_path,
                &[
                    "flowchart",
                    "graph",
                    "sequenceDiagram",
                    "classDiagram",
                    "gantt",
                    "journey",
                ],
                "Mermaid",
                &mut errors,
            );
        }
        StudioRendererKind::PdfEmbed => match fs::read(&primary_path) {
            Ok(bytes) => {
                if !bytes.starts_with(b"%PDF-") {
                    errors.push(format!(
                        "PDF renderer contract failed for '{}': missing %PDF header.",
                        primary_file.path
                    ));
                }
            }
            Err(error) => errors.push(format!(
                "Failed to read PDF artifact '{}': {}",
                primary_file.path, error
            )),
        },
        StudioRendererKind::DownloadCard => {
            if primary_file.renderable {
                errors.push(
                    "download_card renderer contract failed: primary file must not be renderable."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::WorkspaceSurface => {
            let workspace_manifest = source_root.join("artifact-manifest.json");
            if !workspace_manifest.exists() {
                errors.push(format!(
                    "workspace_surface renderer contract failed: '{}' is missing.",
                    workspace_manifest.display()
                ));
            }
        }
        StudioRendererKind::BundleManifest => match fs::read_to_string(&primary_path) {
            Ok(raw) => {
                if serde_json::from_str::<serde_json::Value>(&raw).is_err() {
                    errors.push(format!(
                        "bundle_manifest renderer contract failed for '{}': invalid JSON.",
                        primary_file.path
                    ));
                }
            }
            Err(error) => errors.push(format!(
                "Failed to read bundle manifest '{}': {}",
                primary_file.path, error
            )),
        },
    }

    errors.extend(validate_presentation_quality(manifest, source_root));
    errors
}

#[derive(Debug, Clone)]
pub(super) struct MaterializedPresentationFile {
    pub(super) path: String,
    pub(super) mime: String,
    pub(super) renderable: bool,
    pub(super) downloadable: bool,
    pub(super) text_content: Option<String>,
}

pub(super) fn validate_presentation_quality(
    manifest: &StudioArtifactManifest,
    source_root: &Path,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut files = Vec::new();

    for file in &manifest.files {
        if file.external_url.is_some() {
            continue;
        }
        let path = source_root.join(&file.path);
        let text_content = if should_read_as_text(&file.path, &file.mime) {
            fs::read_to_string(&path).ok()
        } else if file.mime.eq_ignore_ascii_case("application/pdf")
            || file.path.to_ascii_lowercase().ends_with(".pdf")
        {
            fs::read(&path)
                .ok()
                .map(|bytes| extract_searchable_pdf_text(&bytes))
        } else {
            None
        };
        files.push(MaterializedPresentationFile {
            path: file.path.clone(),
            mime: file.mime.clone(),
            renderable: file.renderable,
            downloadable: file.downloadable,
            text_content,
        });
    }

    let primary_file = files
        .iter()
        .find(|file| file.renderable)
        .or_else(|| files.first());
    let primary_text = primary_file
        .and_then(|file| file.text_content.as_deref())
        .unwrap_or_default();
    let placeholder_hits = files
        .iter()
        .filter_map(|file| file.text_content.as_deref())
        .map(placeholder_marker_hits)
        .sum::<usize>();

    if placeholder_hits >= 2 {
        errors.push(
            "presentation contract failed: placeholder-grade copy is still present in the surfaced artifact."
                .to_string(),
        );
    }

    match manifest.renderer {
        StudioRendererKind::Markdown => {
            let headings = primary_text
                .lines()
                .filter(|line| line.trim_start().starts_with('#'))
                .count();
            if word_count(primary_text) < 45 || headings < 2 {
                errors.push(
                    "presentation contract failed: markdown artifact is too thin or weakly structured to lead the stage."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::HtmlIframe => {
            let lower = primary_text.to_ascii_lowercase();
            if word_count(primary_text) < 90 || count_html_nonempty_sectioning_elements(&lower) < 3
            {
                errors.push(
                    "presentation contract failed: HTML output is too skeletal to count as a successful surfaced artifact."
                        .to_string(),
                );
            }
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                errors.push(
                    "presentation contract failed: HTML sectioning regions are still empty first-paint shells."
                        .to_string(),
                );
            }
            if html_contains_placeholder_markers(&lower) {
                errors.push(
                    "presentation contract failed: HTML still contains placeholder-grade copy or comments."
                        .to_string(),
                );
            }
            if html_contains_placeholder_svg_regions(&lower) {
                errors.push(
                    "presentation contract failed: HTML chart or diagram regions are still empty placeholder shells."
                        .to_string(),
                );
            }
            if html_contains_unlabeled_chart_svg_regions(&lower) {
                errors.push(
                    "presentation contract failed: HTML chart or diagram SVG regions are still unlabeled shells."
                        .to_string(),
                );
            }
            if html_contains_empty_chart_container_regions(&lower) {
                errors.push(
                    "presentation contract failed: HTML chart or diagram containers are still empty placeholder shells."
                        .to_string(),
                );
            }
            if html_contains_empty_detail_regions(&lower) {
                errors.push(
                    "presentation contract failed: HTML shared detail or comparison regions are empty on first paint."
                        .to_string(),
                );
            }
            if html_references_missing_dom_ids(&lower) {
                errors.push(
                    "presentation contract failed: HTML interactions still target missing DOM ids."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::JsxSandbox => {
            let control_tokens = [
                "<button", "<input", "<select", "<form", "onClick", "onChange", "useState",
            ]
            .iter()
            .map(|needle| primary_text.matches(needle).count())
            .sum::<usize>();
            if word_count(primary_text) < 70
                || primary_text.matches('<').count() < 8
                || control_tokens < 2
            {
                errors.push(
                    "presentation contract failed: JSX artifact does not show enough structure or interactivity."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::Svg => {
            let lower = primary_text.to_ascii_lowercase();
            let shape_count = [
                "<path",
                "<rect",
                "<circle",
                "<ellipse",
                "<polygon",
                "<polyline",
                "<line",
                "<text",
            ]
            .iter()
            .map(|needle| lower.matches(needle).count())
            .sum::<usize>();
            if shape_count < 6 {
                errors.push(
                    "presentation contract failed: SVG output is too sparse to stand as the primary visual artifact."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::Mermaid => {
            let edges = primary_text.matches("-->").count()
                + primary_text.matches("==>").count()
                + primary_text.matches("-.->").count();
            let nodes = primary_text.matches('[').count()
                + primary_text.matches('(').count()
                + primary_text.matches('{').count();
            if edges < 3 || nodes < 4 {
                errors.push(
                    "presentation contract failed: Mermaid artifact is too small to deserve primary presentation."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::PdfEmbed => {
            if let Some(primary_file) = primary_file {
                let primary_path = source_root.join(&primary_file.path);
                if let Ok(bytes) = fs::read(primary_path) {
                    if bytes.len() < 800 {
                        errors.push(
                            "presentation contract failed: PDF bytes are too small for a credible surfaced brief."
                                .to_string(),
                        );
                    }
                }
            }
            if bracket_placeholder_hits(primary_text) > 0 {
                errors.push(
                    "presentation contract failed: placeholder-grade copy is still present in the surfaced artifact."
                        .to_string(),
                );
            }
            let sections = count_pdf_structural_sections(primary_text);
            if word_count(primary_text) < 90 {
                errors.push(
                    "presentation contract failed: PDF content is too short to pass as a primary launch brief or report."
                        .to_string(),
                );
            } else if sections < 4 {
                errors.push(
                    "presentation contract failed: PDF content should be broken into clearer sections before Render becomes primary."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::DownloadCard => {
            let downloadable_count = files.iter().filter(|file| file.downloadable).count();
            let has_readme = files.iter().any(|file| {
                file.path.to_ascii_lowercase().contains("readme")
                    || file.mime.eq_ignore_ascii_case("text/markdown")
            });
            if downloadable_count == 0 {
                errors.push(
                    "presentation contract failed: download-card artifacts require a real downloadable payload."
                        .to_string(),
                );
            } else if files.len() > 1 && !has_readme {
                errors.push(
                    "presentation contract failed: multi-file downloads need a README or orientation note."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::BundleManifest => {
            let has_json_manifest = files.iter().any(|file| {
                file.path.to_ascii_lowercase().ends_with(".json")
                    && file.mime.eq_ignore_ascii_case("application/json")
            });
            if !has_json_manifest || files.len() < 2 {
                errors.push(
                    "presentation contract failed: bundle manifests need a manifest plus supporting files."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::WorkspaceSurface => {
            if manifest.primary_tab == "preview" && !render_surface_available_for_manifest(manifest)
            {
                errors.push(
                    "presentation contract failed: workspace artifacts require a verified preview before Render becomes primary."
                        .to_string(),
                );
            }
        }
    }

    errors
}

pub(super) fn should_read_as_text(path: &str, mime: &str) -> bool {
    let lower_path = path.to_ascii_lowercase();
    let lower_mime = mime.to_ascii_lowercase();
    lower_mime.starts_with("text/")
        || lower_mime.contains("json")
        || lower_mime.contains("javascript")
        || lower_mime.contains("typescript")
        || lower_mime.contains("xml")
        || lower_mime.contains("yaml")
        || lower_mime.contains("svg")
        || lower_mime.contains("html")
        || lower_mime.contains("markdown")
        || lower_path.ends_with(".md")
        || lower_path.ends_with(".html")
        || lower_path.ends_with(".jsx")
        || lower_path.ends_with(".tsx")
        || lower_path.ends_with(".svg")
        || lower_path.ends_with(".mermaid")
        || lower_path.ends_with(".json")
}

pub(super) fn placeholder_marker_hits(text: &str) -> usize {
    let lower = text.to_ascii_lowercase();
    [
        "placeholder",
        "lorem ipsum",
        "todo",
        "tbd",
        "coming soon",
        "replace this",
        "sample text",
    ]
    .iter()
    .filter(|needle| lower.contains(**needle))
    .count()
}

pub(super) fn html_contains_placeholder_markers(html_lower: &str) -> bool {
    placeholder_marker_hits(html_lower) > 0
}

pub(super) fn count_html_svg_regions(html_lower: &str) -> usize {
    html_lower.matches("<svg").count()
}

pub(super) fn count_html_sectioning_elements(html_lower: &str) -> usize {
    ["<section", "<article", "<nav", "<aside", "<footer"]
        .iter()
        .map(|needle| html_lower.matches(needle).count())
        .sum()
}

pub(super) fn count_html_svg_content_elements(html_lower: &str) -> usize {
    [
        "<path",
        "<rect",
        "<circle",
        "<ellipse",
        "<polygon",
        "<polyline",
        "<line",
        "<text",
    ]
    .iter()
    .map(|needle| html_lower.matches(needle).count())
    .sum()
}

pub(super) fn count_html_svg_label_elements(html_lower: &str) -> usize {
    ["<text", "<title", "<desc", "aria-label="]
        .iter()
        .map(|needle| html_lower.matches(needle).count())
        .sum()
}

pub(super) fn html_contains_placeholder_svg_regions(html_lower: &str) -> bool {
    let svg_regions = count_html_svg_regions(html_lower);
    svg_regions > 0 && count_html_svg_content_elements(html_lower) < svg_regions
}

pub(super) fn html_contains_unlabeled_chart_svg_regions(html_lower: &str) -> bool {
    let svg_regions = count_html_svg_regions(html_lower);
    svg_regions > 0
        && chart_region_hint_present(html_lower)
        && count_html_svg_content_elements(html_lower) >= svg_regions
        && count_html_svg_label_elements(html_lower) < svg_regions
}

pub(super) fn chart_region_hint_present(fragment_lower: &str) -> bool {
    ["chart", "graph", "diagram", "plot", "viz", "visualization"]
        .iter()
        .any(|needle| fragment_lower.contains(needle))
}

pub(super) fn detail_region_hint_present(fragment_lower: &str) -> bool {
    [
        "detail",
        "compare",
        "comparison",
        "explain",
        "explanation",
        "summary",
        "panel",
    ]
    .iter()
    .any(|needle| fragment_lower.contains(needle))
}

pub(super) fn collect_html_attribute_ids(html_lower: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    for pattern in ["id=\"", "id='"] {
        let mut cursor = 0usize;
        let quote = pattern.chars().last().unwrap_or('"');
        while let Some(relative_start) = html_lower[cursor..].find(pattern) {
            let start = cursor + relative_start + pattern.len();
            let Some(relative_end) = html_lower[start..].find(quote) else {
                break;
            };
            let end = start + relative_end;
            let value = html_lower[start..end].trim();
            if !value.is_empty() {
                ids.insert(value.to_string());
            }
            cursor = end + 1;
        }
    }
    ids
}

pub(super) fn collect_call_argument_literals(
    html_lower: &str,
    pattern: &str,
    closing_quote: char,
) -> Vec<String> {
    let mut values = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative_start) = html_lower[cursor..].find(pattern) {
        let start = cursor + relative_start + pattern.len();
        let Some(relative_end) = html_lower[start..].find(closing_quote) else {
            break;
        };
        let end = start + relative_end;
        let value = html_lower[start..end].trim();
        if !value.is_empty() {
            values.push(value.to_string());
        }
        cursor = end + 1;
    }
    values
}

pub(super) fn extract_selector_ids(selector_lower: &str) -> Vec<String> {
    let bytes = selector_lower.as_bytes();
    let mut ids = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'#' {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() {
            let ch = bytes[end] as char;
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            ids.push(selector_lower[start..end].to_string());
        }
        index = end.max(start);
    }
    ids
}

pub(super) fn collect_html_referenced_ids(html_lower: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    for value in collect_call_argument_literals(html_lower, "getelementbyid(\"", '"')
        .into_iter()
        .chain(collect_call_argument_literals(
            html_lower,
            "getelementbyid('",
            '\'',
        ))
    {
        ids.insert(value);
    }
    for selector in collect_call_argument_literals(html_lower, "queryselector(\"", '"')
        .into_iter()
        .chain(collect_call_argument_literals(
            html_lower,
            "queryselector('",
            '\'',
        ))
        .chain(collect_call_argument_literals(
            html_lower,
            "queryselectorall(\"",
            '"',
        ))
        .chain(collect_call_argument_literals(
            html_lower,
            "queryselectorall('",
            '\'',
        ))
    {
        for id in extract_selector_ids(&selector) {
            ids.insert(id);
        }
    }
    ids
}

pub(super) fn html_references_missing_dom_ids(html_lower: &str) -> bool {
    let defined_ids = collect_html_attribute_ids(html_lower);
    collect_html_referenced_ids(html_lower)
        .into_iter()
        .any(|id| !defined_ids.contains(&id))
}

pub(super) fn html_fragment_is_comment_or_whitespace(fragment_lower: &str) -> bool {
    let mut cursor = 0usize;

    while let Some(relative_start) = fragment_lower[cursor..].find("<!--") {
        let start = cursor + relative_start;
        if !fragment_lower[cursor..start].trim().is_empty() {
            return false;
        }
        let Some(relative_end) = fragment_lower[start + 4..].find("-->") else {
            return false;
        };
        cursor = start + 4 + relative_end + 3;
    }

    fragment_lower[cursor..].trim().is_empty()
}

pub(super) fn strip_html_tags(fragment: &str) -> String {
    let mut plain = String::with_capacity(fragment.len());
    let mut in_tag = false;
    for ch in fragment.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => plain.push(ch),
            _ => {}
        }
    }
    plain
}

pub(super) fn html_fragment_has_first_paint_content(fragment_lower: &str) -> bool {
    if html_fragment_is_comment_or_whitespace(fragment_lower) {
        return false;
    }

    let mut cleaned = fragment_lower.to_string();
    for tag in ["script", "style"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        while let Some(start) = cleaned.find(&open_pattern) {
            let Some(open_end_rel) = cleaned[start..].find('>') else {
                cleaned.truncate(start);
                break;
            };
            let open_end = start + open_end_rel + 1;
            let end = cleaned[open_end..]
                .find(&close_pattern)
                .map(|offset| open_end + offset + close_pattern.len())
                .unwrap_or(open_end);
            cleaned.replace_range(start..end, "");
        }
    }

    if html_fragment_is_comment_or_whitespace(&cleaned) {
        return false;
    }

    if !strip_html_tags(&cleaned).trim().is_empty() {
        return true;
    }

    [
        "<svg",
        "<canvas",
        "<img",
        "<table",
        "<button",
        "<input",
        "<select",
        "<textarea",
        "<details",
        "<summary",
        "<figure",
        "<ul",
        "<ol",
        "<li",
    ]
    .iter()
    .any(|needle| cleaned.contains(needle))
}

pub(super) fn html_fragment_has_detail_content(fragment_lower: &str) -> bool {
    let mut cleaned = fragment_lower.to_string();
    for tag in [
        "script", "style", "h1", "h2", "h3", "h4", "h5", "h6", "header",
    ] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        while let Some(start) = cleaned.find(&open_pattern) {
            let Some(open_end_rel) = cleaned[start..].find('>') else {
                cleaned.truncate(start);
                break;
            };
            let open_end = start + open_end_rel + 1;
            let end = cleaned[open_end..]
                .find(&close_pattern)
                .map(|offset| open_end + offset + close_pattern.len())
                .unwrap_or(open_end);
            cleaned.replace_range(start..end, "");
        }
    }

    if html_fragment_is_comment_or_whitespace(&cleaned) {
        return false;
    }

    if !strip_html_tags(&cleaned).trim().is_empty() {
        return true;
    }

    [
        "<table",
        "<ul",
        "<ol",
        "<dl",
        "<figure",
        "<svg",
        "<meter",
        "<progress",
    ]
    .iter()
    .any(|needle| cleaned.contains(needle))
}

pub(super) fn count_empty_html_sectioning_elements(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["section", "article", "nav", "aside", "footer"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = html_lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = html_lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;

            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                total += 1;
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if !html_fragment_has_first_paint_content(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn count_html_nonempty_sectioning_elements(html_lower: &str) -> usize {
    count_html_sectioning_elements(html_lower)
        .saturating_sub(count_empty_html_sectioning_elements(html_lower))
}

pub(super) fn count_empty_html_chart_container_regions(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["div", "section", "article", "figure", "aside", "canvas"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = html_lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = html_lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;
            let open_tag = &html_lower[start..open_end];
            if !chart_region_hint_present(open_tag) {
                cursor = open_end;
                continue;
            }

            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                total += 1;
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if html_fragment_is_comment_or_whitespace(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn html_contains_empty_chart_container_regions(html_lower: &str) -> bool {
    if html_lower.contains("studio-inline-chart-fallback") {
        return false;
    }
    count_empty_html_chart_container_regions(html_lower) > 0
}

pub(super) fn count_empty_html_detail_regions(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["aside", "section", "article", "div"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = html_lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = html_lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;
            let open_tag = &html_lower[start..open_end];
            if !detail_region_hint_present(open_tag) {
                cursor = open_end;
                continue;
            }

            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                total += 1;
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if !html_fragment_has_detail_content(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn html_contains_empty_detail_regions(html_lower: &str) -> bool {
    count_empty_html_detail_regions(html_lower) > 0
}

pub(super) fn word_count(text: &str) -> usize {
    text.split_whitespace()
        .filter(|word| !word.trim().is_empty())
        .count()
}

pub(super) fn bracket_placeholder_hits(text: &str) -> usize {
    let mut hits = 0usize;
    let mut cursor = 0usize;

    while let Some(relative_start) = text[cursor..].find('[') {
        let start = cursor + relative_start;
        let Some(relative_end) = text[start + 1..].find(']') else {
            break;
        };
        let end = start + 1 + relative_end;
        let next_char = text[end + 1..].chars().next();
        let candidate = text[start + 1..end].trim();

        if next_char != Some('(')
            && candidate.split_whitespace().count() >= 2
            && candidate.chars().any(|ch| ch.is_ascii_alphabetic())
        {
            hits += 1;
        }

        cursor = end + 1;
    }

    hits
}

pub(super) fn validate_utf8_contains(
    path: &Path,
    needles: &[&str],
    label: &str,
    errors: &mut Vec<String>,
) {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let lower = raw.to_ascii_lowercase();
            if !needles
                .iter()
                .any(|needle| lower.contains(&needle.to_ascii_lowercase()))
            {
                errors.push(format!(
                    "{} renderer contract failed for '{}'.",
                    label,
                    path.display()
                ));
            }
        }
        Err(error) => errors.push(format!(
            "Failed to read {} artifact '{}': {}",
            label,
            path.display(),
            error
        )),
    }
}

pub(super) fn primary_file_for_manifest(
    manifest: &StudioArtifactManifest,
) -> Option<&StudioArtifactManifestFile> {
    manifest
        .tabs
        .iter()
        .find(|tab| tab.id == manifest.primary_tab)
        .and_then(|tab| tab.file_path.as_ref())
        .and_then(|file_path| manifest.files.iter().find(|file| &file.path == file_path))
        .or_else(|| manifest.files.iter().find(|file| file.renderable))
        .or_else(|| manifest.files.first())
}

pub(super) fn prepare_output_directory(output: &Path, force: bool) -> Result<()> {
    if !output.exists() {
        fs::create_dir_all(output).with_context(|| {
            format!("Failed to create output directory '{}'.", output.display())
        })?;
        return Ok(());
    }

    if !force {
        bail!(
            "Output directory '{}' already exists. Re-run with --force to replace it.",
            output.display()
        );
    }

    if output.is_dir() {
        fs::remove_dir_all(output)
            .with_context(|| format!("Failed to remove '{}'.", output.display()))?;
    } else {
        fs::remove_file(output)
            .with_context(|| format!("Failed to remove '{}'.", output.display()))?;
    }
    fs::create_dir_all(output).with_context(|| {
        format!(
            "Failed to recreate output directory '{}'.",
            output.display()
        )
    })?;
    Ok(())
}

pub(super) fn build_package_readme(manifest: &StudioArtifactManifest) -> String {
    format!(
        "# {}\n\n\
Artifact ID: `{}`\n\
Class: `{}`\n\
Renderer: `{}`\n\
Verification: `{}`\n\
Lifecycle: `{}`\n\n\
This package was materialized from a Studio artifact manifest so it can be inspected,\n\
reproduced, and moved through CLI-native workflows.\n",
        manifest.title,
        manifest.artifact_id,
        artifact_class_label(manifest.artifact_class),
        renderer_label(manifest.renderer),
        manifest.verification.summary,
        lifecycle_state_label(manifest.verification.lifecycle_state),
    )
}

pub(super) fn compose_verified_reply(manifest: &StudioArtifactManifest) -> ComposedVerifiedReply {
    ComposedVerifiedReply {
        status: verification_status_label(manifest),
        lifecycle_state: lifecycle_state_label(manifest.verification.lifecycle_state),
        title: format!("Studio outcome: {}", manifest.title),
        summary: format!("{} {}", manifest.title, manifest.verification.summary),
        evidence: manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
        production_provenance: manifest.verification.production_provenance.clone(),
        acceptance_provenance: manifest.verification.acceptance_provenance.clone(),
        failure: manifest.verification.failure.clone(),
    }
}

pub(super) fn format_runtime_provenance(provenance: &StudioRuntimeProvenance) -> String {
    let mut parts = vec![
        format!("{:?}", provenance.kind).to_lowercase(),
        provenance.label.clone(),
    ];
    if let Some(model) = provenance.model.as_ref() {
        parts.push(model.clone());
    }
    parts.join(" | ")
}

pub(super) fn artifact_class_label(artifact_class: StudioArtifactClass) -> String {
    match artifact_class {
        StudioArtifactClass::Document => "document",
        StudioArtifactClass::Visual => "visual",
        StudioArtifactClass::InteractiveSingleFile => "interactive_single_file",
        StudioArtifactClass::DownloadableFile => "downloadable_file",
        StudioArtifactClass::WorkspaceProject => "workspace_project",
        StudioArtifactClass::CompoundBundle => "compound_bundle",
        StudioArtifactClass::CodePatch => "code_patch",
        StudioArtifactClass::ReportBundle => "report_bundle",
    }
    .to_string()
}

pub(super) fn renderer_label(renderer: StudioRendererKind) -> String {
    match renderer {
        StudioRendererKind::Markdown => "markdown",
        StudioRendererKind::HtmlIframe => "html_iframe",
        StudioRendererKind::JsxSandbox => "jsx_sandbox",
        StudioRendererKind::Svg => "svg",
        StudioRendererKind::Mermaid => "mermaid",
        StudioRendererKind::PdfEmbed => "pdf_embed",
        StudioRendererKind::DownloadCard => "download_card",
        StudioRendererKind::WorkspaceSurface => "workspace_surface",
        StudioRendererKind::BundleManifest => "bundle_manifest",
    }
    .to_string()
}

pub(super) fn outcome_kind_label(route: &StudioOutcomePlanningPayload) -> &'static str {
    match route.outcome_kind {
        ioi_types::app::StudioOutcomeKind::Conversation => "conversation",
        ioi_types::app::StudioOutcomeKind::ToolWidget => "tool_widget",
        ioi_types::app::StudioOutcomeKind::Visualizer => "visualizer",
        ioi_types::app::StudioOutcomeKind::Artifact => "artifact",
    }
}

pub(super) fn lifecycle_state_label(state: StudioArtifactLifecycleState) -> String {
    match state {
        StudioArtifactLifecycleState::Draft => "draft",
        StudioArtifactLifecycleState::Planned => "planned",
        StudioArtifactLifecycleState::Materializing => "materializing",
        StudioArtifactLifecycleState::Rendering => "rendering",
        StudioArtifactLifecycleState::Implementing => "implementing",
        StudioArtifactLifecycleState::Verifying => "verifying",
        StudioArtifactLifecycleState::Ready => "ready",
        StudioArtifactLifecycleState::Partial => "partial",
        StudioArtifactLifecycleState::Blocked => "blocked",
        StudioArtifactLifecycleState::Failed => "failed",
    }
    .to_string()
}

pub(super) fn verification_status_label(manifest: &StudioArtifactManifest) -> String {
    match manifest.verification.status {
        StudioArtifactVerificationStatus::Pending => "pending",
        StudioArtifactVerificationStatus::Ready => "ready",
        StudioArtifactVerificationStatus::Blocked => "blocked",
        StudioArtifactVerificationStatus::Failed => "failed",
        StudioArtifactVerificationStatus::Partial => "partial",
    }
    .to_string()
}

pub(super) fn render_surface_available_for_manifest(manifest: &StudioArtifactManifest) -> bool {
    if manifest.verification.status != StudioArtifactVerificationStatus::Ready {
        return false;
    }

    match manifest.renderer {
        StudioRendererKind::WorkspaceSurface => manifest
            .tabs
            .iter()
            .any(|tab| tab.id == manifest.primary_tab && tab.kind == StudioArtifactTabKind::Render),
        StudioRendererKind::DownloadCard => manifest.files.iter().any(|file| file.downloadable),
        _ => manifest.files.iter().any(|file| file.renderable),
    }
}

pub(super) fn preferred_stage_mode_for_manifest(manifest: &StudioArtifactManifest) -> &'static str {
    if render_surface_available_for_manifest(manifest) {
        "render"
    } else {
        "source"
    }
}
