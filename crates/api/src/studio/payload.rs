use super::html::*;
use super::*;

pub fn parse_studio_generated_artifact_payload(
    raw: &str,
) -> Result<StudioGeneratedArtifactPayload, String> {
    parse_studio_generated_artifact_payload_json(raw)
        .or_else(|_| {
            let extracted = extract_first_json_object(raw).ok_or_else(|| {
                "Studio artifact materialization output missing JSON payload".to_string()
            })?;
            parse_studio_generated_artifact_payload_json(&extracted)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            format!(
                "Failed to parse Studio artifact materialization payload: {}",
                error
            )
        })
}

fn parse_studio_generated_artifact_payload_json(
    raw: &str,
) -> Result<StudioGeneratedArtifactPayload, serde_json::Error> {
    let mut value = serde_json::from_str::<serde_json::Value>(raw)?;
    normalize_generated_artifact_payload_value(&mut value);
    serde_json::from_value::<StudioGeneratedArtifactPayload>(value)
}

fn csv_escape_cell(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_header_columns(body: &str) -> Vec<String> {
    body.lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| {
            line.split(',')
                .map(|column| column.trim().trim_matches('"'))
                .filter(|column| !column.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["record".to_string(), "detail".to_string()])
}

fn csv_body_looks_complete(body: &str) -> bool {
    let lines = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    lines.len() >= 3
        && lines.first().is_some_and(|line| line.contains(','))
        && lines.iter().skip(1).all(|line| line.contains(','))
}

fn synthesize_download_bundle_csv_body(
    summary: &str,
    notes: &[String],
    file_hints: &[(String, String)],
) -> String {
    let mut rows = vec![("summary".to_string(), summary.trim().to_string())];

    rows.extend(
        notes
            .iter()
            .filter(|note| !note.trim().is_empty())
            .take(2)
            .enumerate()
            .map(|(index, note)| (format!("note_{}", index + 1), note.trim().to_string())),
    );

    if rows.len() < 3 {
        rows.extend(
            file_hints
                .iter()
                .filter(|(path, _)| !path.eq_ignore_ascii_case("README.md"))
                .take(3 - rows.len())
                .map(|(path, mime)| {
                    (
                        path.clone(),
                        format!("Included in the requested downloadable bundle as {mime}."),
                    )
                }),
        );
    }

    while rows.len() < 3 {
        rows.push((
            format!("item_{}", rows.len()),
            "Request-grounded bundle detail.".to_string(),
        ));
    }

    let mut lines = vec!["record,detail".to_string()];
    lines.extend(rows.into_iter().take(3).map(|(record, detail)| {
        format!("{},{}", csv_escape_cell(&record), csv_escape_cell(&detail))
    }));
    lines.join("\n")
}

fn synthesize_download_bundle_readme_body(
    summary: &str,
    notes: &[String],
    file_hints: &[(String, String)],
    csv_columns: Vec<String>,
) -> String {
    let heading = if summary.trim().is_empty() {
        "Download bundle"
    } else {
        summary.trim()
    };
    let mut lines = vec![
        format!("# {heading}"),
        String::new(),
        "This bundle contains the requested downloadable files and a short explanation of how to use them.".to_string(),
        String::new(),
        "## Files".to_string(),
    ];

    for (path, mime) in file_hints {
        let purpose = if path.eq_ignore_ascii_case("README.md") {
            "Bundle overview, file mapping, and CSV column notes."
        } else if path.to_ascii_lowercase().ends_with(".csv") || mime == "text/csv" {
            "Structured CSV export for the requested bundle."
        } else {
            "Requested downloadable bundle asset."
        };
        lines.push(format!("- `{path}`: {purpose}"));
    }

    if !csv_columns.is_empty() {
        lines.push(String::new());
        lines.push("## CSV columns".to_string());
        for column in csv_columns {
            let description = match column.as_str() {
                "record" => "Label for the bundle record described in the export.",
                "detail" => "Request-grounded detail for that record.",
                _ => "Request-grounded value included in the export.",
            };
            lines.push(format!("- `{column}`: {description}"));
        }
    }

    if !notes.is_empty() {
        lines.push(String::new());
        lines.push("## Notes".to_string());
        for note in notes.iter().take(3) {
            lines.push(format!("- {}", note.trim()));
        }
    }

    lines.join("\n")
}

fn normalize_generated_artifact_payload_value(value: &mut serde_json::Value) {
    let summary = value
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .unwrap_or("Download bundle")
        .to_string();
    let notes = value
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .map(|notes| {
            notes
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|note| !note.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let file_hints = value
        .get("files")
        .and_then(serde_json::Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(|file| {
                    let map = file.as_object()?;
                    let path = map.get("path")?.as_str()?.trim();
                    let mime = map
                        .get("mime")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .trim();
                    if path.is_empty() {
                        return None;
                    }
                    Some((path.to_string(), mime.to_string()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let synthesized_csv = synthesize_download_bundle_csv_body(&summary, &notes, &file_hints);
    let synthesized_readme = synthesize_download_bundle_readme_body(
        &summary,
        &notes,
        &file_hints,
        csv_header_columns(&synthesized_csv),
    );
    let Some(files) = value
        .get_mut("files")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };

    for file in files {
        let Some(map) = file.as_object_mut() else {
            continue;
        };

        let has_non_empty_body = map
            .get("body")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|body| !body.trim().is_empty());
        if has_non_empty_body {
            continue;
        }

        let aliased_body = ["content", "contents", "text", "data"]
            .into_iter()
            .find_map(|key| {
                map.get(key)
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_string)
            });

        if let Some(body) = aliased_body {
            map.insert("body".to_string(), serde_json::Value::String(body));
            continue;
        }

        let path = map
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let mime = map
            .get("mime")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if path == "readme.md" || mime == "text/markdown" {
            map.insert(
                "body".to_string(),
                serde_json::Value::String(synthesized_readme.clone()),
            );
        } else if path.ends_with(".csv") || mime == "text/csv" {
            map.insert(
                "body".to_string(),
                serde_json::Value::String(synthesized_csv.clone()),
            );
        }
    }
}

pub fn validate_generated_artifact_payload(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) -> Result<(), String> {
    if payload.summary.trim().is_empty() {
        return Err("Studio artifact materialization summary must not be empty.".to_string());
    }
    if payload.files.is_empty() {
        return Err("Studio artifact materialization must contain at least one file.".to_string());
    }
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return Err(
            "workspace_surface artifacts must be materialized through the workspace renderer path."
                .to_string(),
        );
    }

    let mut paths = HashSet::new();
    for file in &payload.files {
        if file.path.trim().is_empty() {
            return Err("Generated artifact file path must not be empty.".to_string());
        }
        if !paths.insert(file.path.clone()) {
            return Err(format!(
                "Generated artifact file path '{}' is duplicated.",
                file.path
            ));
        }
        if file.body.trim().is_empty() {
            return Err(format!(
                "Generated artifact file '{}' must not have an empty body.",
                file.path
            ));
        }
    }

    let primary_file = payload
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
            )
        })
        .ok_or_else(|| {
            "Generated artifact payload must include a primary or export file.".to_string()
        })?;

    match request.renderer {
        StudioRendererKind::Markdown => {
            validate_exact_primary_file(primary_file, ".md", "text/markdown", true)?;
        }
        StudioRendererKind::HtmlIframe => {
            validate_exact_primary_file(primary_file, ".html", "text/html", true)?;
            let html = primary_file.body.as_str();
            let lower = html.to_ascii_lowercase();
            if !(lower.contains("<html") || lower.contains("<!doctype html")) {
                return Err("HTML iframe artifacts must contain an HTML document.".to_string());
            }
            if let Some(failure) = html_document_completeness_failure(html, &lower) {
                return Err(failure.to_string());
            }
            if studio_modal_first_html_enabled() {
                if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                    && !contains_html_interaction_hooks(&lower)
                {
                    return Err(
                        "Interactive HTML iframe artifacts must contain real interactive controls or handlers."
                            .to_string(),
                    );
                }
                return Ok(());
            }
            if !lower.contains("<main") {
                return Err("HTML iframe artifacts must contain a <main> region.".to_string());
            }
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                return Err(
                    "HTML iframe artifacts must contain at least three sectioning elements with first-paint content."
                        .to_string(),
                );
            }
            if lower.contains("alert(") {
                return Err(
                    "HTML iframe artifacts must not use alert() as the surfaced interaction."
                        .to_string(),
                );
            }
            if html_uses_external_runtime_dependency(&lower) {
                return Err(
                    "HTML iframe artifacts must not depend on external libraries or undefined globals."
                        .to_string(),
                );
            }
            if html_contains_placeholder_markers(&lower) {
                return Err(
                    "HTML iframe artifacts must not contain placeholder-grade copy, comments, or TODO markers in the surfaced artifact."
                        .to_string(),
                );
            }
            if html_has_duplicate_mapped_view_tokens(&lower) {
                return Err(
                    "HTML iframe artifacts must not duplicate mapped view-panel tokens across pre-rendered evidence regions."
                        .to_string(),
                );
            }
            if html_has_invalid_mapped_view_default_state(html) {
                return Err(
                    "HTML iframe artifacts with mapped evidence panels must keep exactly one populated panel visible on first paint."
                        .to_string(),
                );
            }
            if html_contains_placeholder_svg_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint."
                        .to_string(),
                );
            }
            if html_contains_unlabeled_chart_svg_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint."
                        .to_string(),
                );
            }
            if html_contains_empty_chart_container_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint."
                        .to_string(),
                );
            }
            if html_contains_empty_detail_regions(&lower) {
                return Err(
                    "HTML iframe artifacts that include shared detail or comparison regions must populate them on first paint."
                        .to_string(),
                );
            }
            if html_references_missing_dom_ids(&lower) {
                return Err(
                    "HTML iframe artifacts must not target missing DOM ids from their surfaced controls or scripts."
                        .to_string(),
                );
            }
            if html_interactions_are_navigation_only(&lower) {
                return Err(
                    "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log."
                        .to_string(),
                );
            }
            if html_uses_custom_font_family_without_loading(&lower) {
                return Err(
                    "HTML iframe artifacts that declare custom font families must load them with a real stylesheet or @font-face rule."
                        .to_string(),
                );
            }
            if html_has_unfocusable_rollover_marks(&lower) {
                return Err(
                    "HTML iframe artifacts that wire focus-based detail behavior must make their data-detail marks keyboard-focusable."
                        .to_string(),
                );
            }
            if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && !contains_html_interaction_hooks(&lower)
            {
                return Err(
                    "Interactive HTML iframe artifacts must contain real interactive controls or handlers."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::JsxSandbox => {
            if !(primary_file.path.ends_with(".jsx") || primary_file.path.ends_with(".tsx")) {
                return Err("JSX sandbox artifacts must end with .jsx or .tsx.".to_string());
            }
            if !primary_file.renderable {
                return Err("JSX sandbox artifacts must be renderable.".to_string());
            }
            if !(primary_file.body.contains("export default")
                || primary_file.body.contains("return ("))
            {
                return Err(
                    "JSX sandbox artifacts must contain a default export or renderable component."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::Svg => {
            validate_exact_primary_file(primary_file, ".svg", "image/svg+xml", true)?;
            if !primary_file.body.contains("<svg") {
                return Err("SVG artifacts must contain an <svg element.".to_string());
            }
        }
        StudioRendererKind::Mermaid => {
            if !primary_file.path.ends_with(".mermaid") && !primary_file.path.ends_with(".mmd") {
                return Err("Mermaid artifacts must end with .mermaid or .mmd.".to_string());
            }
            if !primary_file.renderable {
                return Err("Mermaid artifacts must be renderable.".to_string());
            }
        }
        StudioRendererKind::PdfEmbed => {
            validate_exact_primary_file(primary_file, ".pdf", "application/pdf", true)?;
            if let Some(failure) = pdf_source_contract_failure(&primary_file.body) {
                return Err(failure.to_string());
            }
        }
        StudioRendererKind::DownloadCard => {
            if payload.files.iter().any(|file| file.renderable) {
                return Err(
                    "Download-card artifacts must not mark files as renderable.".to_string()
                );
            }
        }
        StudioRendererKind::BundleManifest => {
            if !primary_file.path.ends_with(".json") {
                return Err(
                    "Bundle-manifest artifacts must include a primary .json file.".to_string(),
                );
            }
            if serde_json::from_str::<serde_json::Value>(&primary_file.body).is_err() {
                return Err("Bundle-manifest primary file must contain valid JSON.".to_string());
            }
            if !matches!(
                request.artifact_class,
                StudioArtifactClass::CompoundBundle | StudioArtifactClass::ReportBundle
            ) {
                return Err(
                    "bundle_manifest renderer requires compound_bundle or report_bundle."
                        .to_string(),
                );
            }
        }
        StudioRendererKind::WorkspaceSurface => {}
    }

    Ok(())
}

fn html_document_completeness_failure<'a>(html: &'a str, lower: &'a str) -> Option<&'static str> {
    if !lower.contains("</body>") || !lower.contains("</html>") {
        return Some("HTML iframe artifacts must contain a fully closed </body></html> document.");
    }
    if lower.contains("<main") && !lower.contains("</main>") {
        return Some("HTML iframe artifacts must contain a closed <main> region.");
    }
    if html_has_trailing_unclosed_tag_fragment(html) {
        return Some(
            "HTML iframe artifacts must not end with an unfinished tag or trailing fragment.",
        );
    }
    None
}

fn html_has_trailing_unclosed_tag_fragment(html: &str) -> bool {
    let trimmed = html.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    let Some(last_gt) = trimmed.rfind('>') else {
        return true;
    };
    !trimmed[last_gt + 1..].trim().is_empty()
}

pub(crate) fn parse_and_validate_generated_artifact_payload(
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let synthesized_from_raw =
        synthesize_generated_artifact_payload_from_raw_document(raw, request);
    let parsed_payload = parse_studio_generated_artifact_payload(raw).ok();
    let mut generated = parsed_payload
        .clone()
        .or_else(|| synthesized_from_raw.clone())
        .ok_or_else(|| {
            "Failed to parse Studio artifact materialization payload: Studio artifact materialization output missing JSON payload".to_string()
        })?;

    match normalize_and_validate_generated_payload(&mut generated, raw, request) {
        Ok(payload) => Ok(payload),
        Err(primary_error) => {
            let Some(mut recovered) = synthesized_from_raw else {
                return Err(primary_error);
            };
            let recovered_matches_primary = primary_generated_artifact_file(&generated)
                .zip(primary_generated_artifact_file(&recovered))
                .is_some_and(|(existing, candidate)| {
                    existing.body.trim() == candidate.body.trim()
                        && existing.path.trim() == candidate.path.trim()
                });
            if recovered_matches_primary {
                return Err(primary_error);
            }
            normalize_and_validate_generated_payload(&mut recovered, raw, request)
                .or(Err(primary_error))
        }
    }
}

fn normalize_and_validate_generated_payload(
    payload: &mut StudioGeneratedArtifactPayload,
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioGeneratedArtifactPayload, String> {
    repair_primary_html_body_from_raw_output(payload, raw, request);
    normalize_generated_artifact_file_paths(payload, request);
    normalize_generated_artifact_payload(payload, request);
    if let Err(error) = validate_generated_artifact_payload(payload, request) {
        if studio_artifact_soft_validation_error(&error) {
            payload.notes.push(format!("soft validation: {error}"));
        } else {
            return Err(error);
        }
    }
    Ok(payload.clone())
}

fn primary_generated_artifact_file(
    payload: &StudioGeneratedArtifactPayload,
) -> Option<&StudioGeneratedArtifactFile> {
    payload.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        )
    })
}

fn repair_primary_html_body_from_raw_output(
    payload: &mut StudioGeneratedArtifactPayload,
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
) {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter_mut().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    }) else {
        return;
    };

    let current_body = primary_html.body.trim();
    let current_lower = current_body.to_ascii_lowercase();
    if current_lower.contains("<!doctype html") || current_lower.contains("<html") {
        return;
    }

    let Some(extracted_html) = extract_authored_html_document(raw) else {
        return;
    };
    if extracted_html.is_empty() {
        return;
    }

    primary_html.body = extracted_html;
}

fn synthesize_generated_artifact_payload_from_raw_document(
    raw: &str,
    request: &StudioOutcomeArtifactRequest,
) -> Option<StudioGeneratedArtifactPayload> {
    let body = extract_authored_document_body(raw, request.renderer)?;
    let mime = direct_authored_document_mime(request.renderer)?;
    Some(StudioGeneratedArtifactPayload {
        summary: direct_authored_document_summary(request.renderer).to_string(),
        notes: vec![format!(
            "normalized from raw {} output",
            direct_authored_document_label(request.renderer)
        )],
        files: vec![StudioGeneratedArtifactFile {
            path: default_generated_artifact_file_path(request.renderer, mime),
            mime: mime.to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body,
        }],
    })
}

fn extract_authored_html_document(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let html_start = lower
        .find("<!doctype html")
        .or_else(|| lower.find("<html"))?;
    let html_slice = trimmed.get(html_start..)?.trim();
    if html_slice.is_empty() {
        return None;
    }

    let html_lower = html_slice.to_ascii_lowercase();
    let html_end = html_lower
        .rfind("</html>")
        .map(|index| index + "</html>".len());
    let extracted = match html_end {
        Some(end) => html_slice.get(..end).unwrap_or(html_slice).trim(),
        None => html_slice,
    };
    if extracted.is_empty() {
        return None;
    }

    Some(extracted.to_string())
}

fn extract_authored_svg_document(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let svg_start = lower.find("<svg")?;
    let svg_slice = trimmed.get(svg_start..)?.trim();
    if svg_slice.is_empty() {
        return None;
    }

    let svg_lower = svg_slice.to_ascii_lowercase();
    let svg_end = svg_lower
        .rfind("</svg>")
        .map(|index| index + "</svg>".len());
    let extracted = match svg_end {
        Some(end) => svg_slice.get(..end).unwrap_or(svg_slice).trim(),
        None => svg_slice,
    };
    if extracted.is_empty() || !extracted.to_ascii_lowercase().contains("<svg") {
        return None;
    }

    Some(extracted.to_string())
}

fn extract_authored_document_body(raw: &str, renderer: StudioRendererKind) -> Option<String> {
    match renderer {
        StudioRendererKind::HtmlIframe => extract_authored_html_document(raw),
        StudioRendererKind::Svg => extract_authored_svg_document(raw),
        StudioRendererKind::Markdown => {
            extract_authored_text_document(raw, &["markdown", "md", ""])
        }
        StudioRendererKind::Mermaid => extract_authored_text_document(raw, &["mermaid", "mmd", ""]),
        StudioRendererKind::PdfEmbed => extract_authored_text_document(raw, &["text", ""]),
        _ => None,
    }
}

fn extract_authored_text_document(raw: &str, accepted_fence_labels: &[&str]) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(fenced) = extract_single_fenced_block(trimmed, accepted_fence_labels) {
        if !fenced.trim().is_empty() {
            return Some(fenced.trim().to_string());
        }
    }

    Some(trimmed.to_string())
}

fn extract_single_fenced_block(raw: &str, accepted_labels: &[&str]) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("```") {
        return None;
    }

    let after_ticks = trimmed.strip_prefix("```")?;
    let newline_index = after_ticks.find('\n')?;
    let label = after_ticks[..newline_index].trim().to_ascii_lowercase();
    if !accepted_labels
        .iter()
        .any(|candidate| label == candidate.to_ascii_lowercase())
    {
        return None;
    }

    let rest = &after_ticks[newline_index + 1..];
    let end_index = rest.rfind("```")?;
    let trailing = rest[end_index + 3..].trim();
    if !trailing.is_empty() {
        return None;
    }

    Some(rest[..end_index].trim().to_string())
}

fn direct_authored_document_label(renderer: StudioRendererKind) -> &'static str {
    match renderer {
        StudioRendererKind::Markdown => "markdown document",
        StudioRendererKind::HtmlIframe => "html document",
        StudioRendererKind::Svg => "svg document",
        StudioRendererKind::Mermaid => "mermaid diagram",
        StudioRendererKind::PdfEmbed => "pdf source document",
        _ => "document",
    }
}

fn direct_authored_document_summary(renderer: StudioRendererKind) -> &'static str {
    match renderer {
        StudioRendererKind::Markdown => "Markdown artifact",
        StudioRendererKind::HtmlIframe => "Interactive HTML artifact",
        StudioRendererKind::Svg => "SVG artifact",
        StudioRendererKind::Mermaid => "Mermaid artifact",
        StudioRendererKind::PdfEmbed => "PDF artifact",
        _ => "Document artifact",
    }
}

fn direct_authored_document_mime(renderer: StudioRendererKind) -> Option<&'static str> {
    match renderer {
        StudioRendererKind::Markdown => Some("text/markdown"),
        StudioRendererKind::HtmlIframe => Some("text/html"),
        StudioRendererKind::Svg => Some("image/svg+xml"),
        StudioRendererKind::Mermaid => Some("text/plain"),
        StudioRendererKind::PdfEmbed => Some("application/pdf"),
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_generated_artifact_payload_against_brief(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> Result<(), String> {
    validate_generated_artifact_payload_against_brief_with_edit_intent(
        payload, request, brief, None,
    )
}

pub(crate) fn validate_generated_artifact_payload_against_brief_with_edit_intent(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
) -> Result<(), String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return Ok(());
    }
    if studio_modal_first_html_enabled() {
        return Ok(());
    }

    let Some(primary_file) = payload.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        )
    }) else {
        return Ok(());
    };
    let lower = primary_file.body.to_ascii_lowercase();
    let detail_regions = count_populated_html_detail_regions(&lower);
    let chart_regions = count_populated_html_chart_regions(&lower);
    let evidence_regions = count_populated_html_evidence_regions(&lower);
    let selection_scoped_patch = edit_intent.is_some_and(|intent| {
        intent.patch_existing_artifact && !intent.selected_targets.is_empty()
    });
    let has_chart_surface = chart_regions > 0
        || count_html_svg_regions(&lower) > 0
        || html_contains_empty_chart_container_regions(&lower);

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && !brief.required_interactions.is_empty()
        && detail_regions == 0
    {
        return Err(
            "HTML iframe briefs with required interactions must include a populated shared detail or comparison region on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && html_has_static_view_mapping_markers(&lower)
        && !html_contains_view_switching_control_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must wire controls to change panel visibility or selection state on click."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && !html_contains_explicit_view_mapping(&lower)
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must map at least two controls to pre-rendered view panels with explicit static selectors."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && count_empty_html_mapped_view_panels(&lower) > 0
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must keep every mapped evidence panel pre-rendered with first-paint content."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && !html_has_visible_populated_mapped_view_panel(&lower)
    {
        return Err(
            "HTML iframe briefs that call for clickable view switching must keep one populated mapped evidence panel visible on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && count_html_rollover_detail_marks(&lower) < 3
    {
        return Err(
            "HTML iframe briefs that call for rollover detail must surface at least three visible data-detail marks or cards on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && !html_contains_rollover_detail_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for rollover detail must wire hover or focus handlers on visible marks to update shared detail on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
        && has_chart_surface
        && brief.required_interactions.len() >= 2
        && evidence_regions < 2
        && !selection_scoped_patch
    {
        return Err(
            "HTML iframe briefs with charted evidence must surface at least two populated evidence views on first paint."
                .to_string(),
        );
    }

    Ok(())
}

fn studio_artifact_soft_validation_error(error: &str) -> bool {
    [
        "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint.",
        "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint.",
        "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint.",
        "HTML iframe artifacts must contain at least three sectioning elements with first-paint content.",
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

pub(crate) fn normalize_generated_artifact_payload(
    payload: &mut StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) {
    if request.renderer == StudioRendererKind::DownloadCard {
        for file in &mut payload.files {
            file.renderable = false;
        }

        let file_hints = payload
            .files
            .iter()
            .map(|file| (file.path.clone(), file.mime.clone()))
            .collect::<Vec<_>>();
        let synthesized_csv =
            synthesize_download_bundle_csv_body(&payload.summary, &payload.notes, &file_hints);
        for file in &mut payload.files {
            let path = file.path.to_ascii_lowercase();
            if (path.ends_with(".csv") || file.mime == "text/csv")
                && !csv_body_looks_complete(&file.body)
            {
                file.body = synthesized_csv.clone();
            }
        }

        let csv_columns = payload
            .files
            .iter()
            .find(|file| {
                file.path.to_ascii_lowercase().ends_with(".csv") || file.mime == "text/csv"
            })
            .map(|file| csv_header_columns(&file.body))
            .unwrap_or_else(|| vec!["record".to_string(), "detail".to_string()]);
        let synthesized_readme = synthesize_download_bundle_readme_body(
            &payload.summary,
            &payload.notes,
            &file_hints,
            csv_columns,
        );
        for file in &mut payload.files {
            let path = file.path.to_ascii_lowercase();
            if (path == "readme.md" || file.mime == "text/markdown") && file.body.trim().is_empty()
            {
                file.body = synthesized_readme.clone();
            }
        }
        return;
    }

    if request.renderer != StudioRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter_mut().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    }) else {
        return;
    };

    if let Some(decoded_body) = decode_json_escaped_html_body(&primary_html.body) {
        primary_html.body = decoded_body;
    }
    if let Some(unwrapped_body) = extract_nested_primary_html_body(&primary_html.body) {
        primary_html.body = unwrapped_body;
    }
    if let Some(extracted_html) = extract_authored_html_document(&primary_html.body) {
        primary_html.body = extracted_html;
    }
    primary_html.body = strip_html_comments(&primary_html.body);
    primary_html.body = normalize_html_terminal_closure(&primary_html.body);
    primary_html.body = normalize_html_custom_font_family_fallbacks(&primary_html.body);
    primary_html.body = normalize_html_semantic_structure(&primary_html.body);
    if request.artifact_class == StudioArtifactClass::InteractiveSingleFile {
        primary_html.body = normalize_html_interactions(&primary_html.body);
    }
}

fn decode_json_escaped_html_body(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }

    let decode_candidate = |candidate: &str| -> Option<String> {
        let decoded = serde_json::from_str::<String>(candidate).ok()?;
        let decoded_trimmed = decoded.trim();
        let decoded_lower = decoded_trimmed.to_ascii_lowercase();
        if decoded_trimmed.is_empty()
            || !(decoded_lower.contains("<html") || decoded_lower.contains("<!doctype html"))
            || decoded_trimmed == trimmed
        {
            return None;
        }
        Some(decoded_trimmed.to_string())
    };

    if trimmed.starts_with('"') {
        if let Some(decoded) = decode_candidate(trimmed) {
            return Some(decoded);
        }
    }

    if !trimmed.contains("\\n")
        && !trimmed.contains("\\t")
        && !trimmed.contains("\\r")
        && !trimmed.contains("\\\"")
        && !trimmed.contains("\\/")
    {
        return None;
    }

    decode_candidate(&format!("\"{trimmed}\""))
}

fn extract_nested_primary_html_body(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() || (!trimmed.starts_with('{') && !trimmed.starts_with("```")) {
        return None;
    }

    let nested_payload = parse_studio_generated_artifact_payload(trimmed).ok()?;
    let nested_primary = nested_payload.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    })?;
    let nested_body = nested_primary.body.trim();
    if nested_body.is_empty() || nested_body == trimmed {
        return None;
    }

    let nested_lower = nested_body.to_ascii_lowercase();
    if !(nested_lower.contains("<html") || nested_lower.contains("<!doctype html")) {
        return None;
    }

    Some(nested_body.to_string())
}

fn normalize_generated_artifact_file_paths(
    payload: &mut StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) {
    for file in &mut payload.files {
        file.mime = normalize_generated_artifact_file_mime(&file.mime);
        file.path =
            normalize_generated_artifact_file_path(&file.path, request.renderer, &file.mime);
    }
}

fn normalize_generated_artifact_file_mime(mime: &str) -> String {
    let trimmed = mime.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }

    let canonical = trimmed
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or(trimmed)
        .to_ascii_lowercase();

    match canonical.as_str() {
        "text/html" => "text/html".to_string(),
        "text/markdown" => "text/markdown".to_string(),
        "image/svg+xml" => "image/svg+xml".to_string(),
        "application/pdf" => "application/pdf".to_string(),
        _ => canonical,
    }
}

fn normalize_generated_artifact_file_path(
    path: &str,
    renderer: StudioRendererKind,
    mime: &str,
) -> String {
    let normalized = path.replace('\\', "/");
    let segments = normalized
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
        .collect::<Vec<_>>();
    let candidate = if segments.is_empty() {
        default_generated_artifact_file_path(renderer, mime)
    } else {
        segments.join("/")
    };
    if candidate.trim().is_empty() {
        default_generated_artifact_file_path(renderer, mime)
    } else {
        candidate
    }
}

fn default_generated_artifact_file_path(renderer: StudioRendererKind, mime: &str) -> String {
    match renderer {
        StudioRendererKind::Markdown => "artifact.md".to_string(),
        StudioRendererKind::HtmlIframe => "index.html".to_string(),
        StudioRendererKind::JsxSandbox => "artifact.jsx".to_string(),
        StudioRendererKind::Svg => "artifact.svg".to_string(),
        StudioRendererKind::Mermaid => "diagram.mermaid".to_string(),
        StudioRendererKind::PdfEmbed => "artifact.pdf".to_string(),
        StudioRendererKind::BundleManifest => "bundle-manifest.json".to_string(),
        StudioRendererKind::DownloadCard => {
            if mime.eq_ignore_ascii_case("application/pdf") {
                "download.pdf".to_string()
            } else {
                "download.bin".to_string()
            }
        }
        StudioRendererKind::WorkspaceSurface => "artifact".to_string(),
    }
}

pub(crate) fn enrich_generated_artifact_payload(
    payload: &mut StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) {
    match request.renderer {
        StudioRendererKind::Svg => {
            let Some(primary_svg) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
                ) && (file.mime == "image/svg+xml" || file.path.ends_with(".svg"))
            }) else {
                return;
            };

            primary_svg.body = ensure_svg_accessibility_metadata(&primary_svg.body, brief);
        }
        StudioRendererKind::HtmlIframe => {
            if studio_modal_first_html_enabled() {
                return;
            }
            let Some(primary_html) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
                ) && (file.mime == "text/html" || file.path.ends_with(".html"))
            }) else {
                return;
            };

            primary_html.body =
                ensure_minimum_brief_rollover_detail_marks(&primary_html.body, brief);
            primary_html.body = ensure_focusable_html_rollover_marks(&primary_html.body);
            primary_html.body = ensure_html_rollover_detail_contract(&primary_html.body);
        }
        _ => {}
    }
}

fn renderer_primary_view_contract_failure(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate: &StudioGeneratedArtifactPayload,
) -> Option<&'static str> {
    let primary_file = candidate.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        )
    })?;

    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            let lower = primary_file.body.to_ascii_lowercase();
            if let Some(failure) = html_document_completeness_failure(&primary_file.body, &lower) {
                return Some(failure);
            }
            if studio_modal_first_html_enabled() {
                return None;
            }
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                Some("HTML sectioning regions are empty shells on first paint.")
            } else if html_contains_placeholder_markers(&lower) {
                Some("HTML still contains placeholder-grade copy or comments on first paint.")
            } else if html_interactions_are_navigation_only(&lower) {
                Some("HTML interactions are navigation-only and do not update shared detail state.")
            } else if html_contains_empty_chart_container_regions(&lower) {
                Some("HTML chart containers are empty placeholder shells on first paint.")
            } else if html_contains_empty_detail_regions(&lower) {
                Some("HTML shared detail or comparison regions are empty on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && html_has_static_view_mapping_markers(&lower)
                && !html_contains_view_switching_control_behavior(&lower)
            {
                Some(
                    "HTML clickable navigation renders mapped panels but does not change panel visibility or selection state."
                )
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && !html_contains_explicit_view_mapping(&lower)
            {
                Some("HTML clickable navigation does not map controls to pre-rendered views.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && count_empty_html_mapped_view_panels(&lower) > 0
            {
                Some("HTML clickable navigation maps controls to empty pre-rendered panels.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && !html_has_visible_populated_mapped_view_panel(&lower)
            {
                Some(
                    "HTML clickable navigation does not keep a populated mapped evidence panel visible on first paint."
                )
            } else if html_contains_unlabeled_chart_svg_regions(&lower) {
                Some("HTML chart SVG regions are unlabeled on first paint.")
            } else if html_contains_placeholder_svg_regions(&lower) {
                Some("HTML chart regions are empty placeholder shells on first paint.")
            } else if html_references_missing_dom_ids(&lower) {
                Some("HTML interactions target missing DOM ids in the surfaced artifact.")
            } else if html_has_unfocusable_rollover_marks(&lower) {
                Some("HTML rollover detail marks are not keyboard-focusable.")
            } else if count_html_repair_shim_markers(&lower) >= 5 {
                Some("HTML still depends on too many Studio repair shims to qualify as native output.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && !brief.required_interactions.is_empty()
                && count_populated_html_detail_regions(&lower) == 0
            {
                Some("HTML required interactions do not surface a shared detail panel on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && (count_populated_html_chart_regions(&lower) > 0
                    || count_html_svg_regions(&lower) > 0
                    || html_contains_empty_chart_container_regions(&lower))
                && brief.required_interactions.len() >= 2
                && count_populated_html_chart_regions(&lower)
                    + count_populated_html_detail_regions(&lower)
                    < 2
            {
                Some("HTML only surfaces one evidence view on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief.required_interactions.iter().any(|interaction| {
                    let lower = interaction.to_ascii_lowercase();
                    lower.contains("rollover") || lower.contains("hover")
                })
                && count_html_rollover_detail_marks(&lower) < 3
            {
                Some("HTML only surfaces sparse rollover detail targets on first paint.")
            } else if request.artifact_class == StudioArtifactClass::InteractiveSingleFile
                && brief.required_interactions.iter().any(|interaction| {
                    let lower = interaction.to_ascii_lowercase();
                    lower.contains("rollover") || lower.contains("hover")
                })
                && !html_contains_rollover_detail_behavior(&lower)
            {
                Some("HTML lacks hover or focus detail behavior for rollover interactions.")
            } else {
                None
            }
        }
        StudioRendererKind::Svg => svg_primary_view_contract_failure(&primary_file.body),
        StudioRendererKind::PdfEmbed => pdf_source_contract_failure(&primary_file.body),
        _ => None,
    }
}

pub(crate) fn enforce_renderer_judge_contract(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate: &StudioGeneratedArtifactPayload,
    mut judge: StudioArtifactJudgeResult,
) -> StudioArtifactJudgeResult {
    neutralize_false_sequence_browsing_penalty(brief, &mut judge);

    let Some(contradiction) = renderer_primary_view_contract_failure(request, brief, candidate)
    else {
        return judge;
    };

    if judge.classification != StudioArtifactJudgeClassification::Blocked {
        judge.classification = StudioArtifactJudgeClassification::Repairable;
    }
    judge.interaction_relevance = judge.interaction_relevance.min(2);
    judge.layout_coherence = judge.layout_coherence.min(2);
    judge.visual_hierarchy = judge.visual_hierarchy.min(2);
    judge.completeness = judge.completeness.min(2);
    judge.trivial_shell_detected = true;
    judge.deserves_primary_artifact_view = false;
    judge.strongest_contradiction = Some(contradiction.to_string());
    judge.rationale =
        "Renderer contract failures keep the first paint from qualifying as primary output."
            .to_string();
    if !judge
        .issue_classes
        .iter()
        .any(|value| value == "renderer_contract")
    {
        judge.issue_classes.push("renderer_contract".to_string());
    }
    if !judge
        .blocked_reasons
        .iter()
        .any(|value| value == contradiction)
    {
        judge.blocked_reasons.push(contradiction.to_string());
    }
    if !judge
        .file_findings
        .iter()
        .any(|value| value.contains("renderer contract failure"))
    {
        let file_path = candidate
            .files
            .iter()
            .find(|file| file.renderable)
            .map(|file| file.path.clone())
            .unwrap_or_else(|| "primary-surface".to_string());
        judge
            .file_findings
            .push(format!("{file_path}: renderer contract failure"));
    }
    if !judge
        .repair_hints
        .iter()
        .any(|value| value.contains("pre-rendered"))
    {
        judge.repair_hints.push(
            "Repair the first paint with pre-rendered panels, populated evidence surfaces, and a visible default detail state.".to_string(),
        );
    }
    judge.aesthetic_verdict =
        "Renderer contract failure keeps the surface below the artifact presentation bar."
            .to_string();
    judge.interaction_verdict =
        "Interaction contract does not hold on first paint yet.".to_string();
    if judge.truthfulness_warnings.is_empty() {
        judge.truthfulness_warnings.push(
            "The surfaced artifact is still relying on incomplete or structurally misleading first-paint output."
                .to_string(),
        );
    }
    judge.recommended_next_pass = Some("structural_repair".to_string());
    judge
}

fn neutralize_false_sequence_browsing_penalty(
    brief: &StudioArtifactBrief,
    judge: &mut StudioArtifactJudgeResult,
) {
    if brief_requires_sequence_browsing(brief)
        || !judge_false_positive_sequence_penalty(judge)
        || judge.generic_shell_detected
        || judge.trivial_shell_detected
        || !judge.deserves_primary_artifact_view
        || judge.request_faithfulness < 4
        || judge.concept_coverage < 4
        || judge.layout_coherence < 4
        || judge.visual_hierarchy < 4
    {
        return;
    }

    judge.classification = StudioArtifactJudgeClassification::Pass;
    judge.interaction_relevance = judge.interaction_relevance.max(4);
    judge.completeness = judge.completeness.max(4);
    judge.strongest_contradiction = None;
    if judge
        .rationale
        .to_ascii_lowercase()
        .contains("sequence browsing")
        || judge.rationale.to_ascii_lowercase().contains("timeline")
    {
        judge.rationale =
            "Complies with the interaction contract and stays request-faithful.".to_string();
    }
}

fn pdf_source_contract_failure(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    let words = artifact_word_count(body);
    let sections = count_pdf_structural_sections(body);

    if lower.contains("\\documentclass")
        || lower.contains("\\begin{document}")
        || lower.contains("\\section")
        || lower.contains("\\usepackage")
    {
        Some("PDF source content must be plain document text, not LaTeX source.")
    } else if bracket_placeholder_hits(body) > 0 {
        Some("PDF source content must not contain bracketed placeholder copy.")
    } else if words < 90 {
        Some("PDF source content is too short to lead the artifact stage.")
    } else if sections < 4 {
        Some("PDF source content needs clearer sections before it can lead the artifact stage.")
    } else {
        None
    }
}

fn svg_primary_view_contract_failure(body: &str) -> Option<&'static str> {
    if count_svg_primary_marks(body) < 6 {
        Some("SVG output is too sparse to stand as the primary visual artifact.")
    } else {
        None
    }
}

fn count_svg_primary_marks(body: &str) -> usize {
    let lower = body.to_ascii_lowercase();
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
    .map(|needle| lower.matches(needle).count())
    .sum()
}

fn artifact_word_count(text: &str) -> usize {
    text.split_whitespace()
        .filter(|word| !word.trim().is_empty())
        .count()
}

fn bracket_placeholder_hits(text: &str) -> usize {
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

fn judge_false_positive_sequence_penalty(judge: &StudioArtifactJudgeResult) -> bool {
    let contradiction = judge
        .strongest_contradiction
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rationale = judge.rationale.to_ascii_lowercase();
    [contradiction.as_str(), rationale.as_str()]
        .iter()
        .any(|text| {
            text.contains("sequence browsing")
                || text.contains("timeline traversal")
                || text.contains("scrolling through staged evidence")
                || text.contains("progression mechanism")
                || text.contains("timeline")
        })
}

fn validate_exact_primary_file(
    file: &StudioGeneratedArtifactFile,
    extension: &str,
    mime: &str,
    renderable: bool,
) -> Result<(), String> {
    if !file.path.ends_with(extension) {
        return Err(format!(
            "Primary artifact file '{}' must end with '{}'.",
            file.path, extension
        ));
    }
    if file.mime != mime {
        return Err(format!(
            "Primary artifact file '{}' must use mime '{}'.",
            file.path, mime
        ));
    }
    if file.renderable != renderable {
        return Err(format!(
            "Primary artifact file '{}' renderable must be {}.",
            file.path, renderable
        ));
    }
    Ok(())
}

pub(crate) fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                return Some(raw[start..start + idx + 1].to_string());
            }
        }
    }
    None
}
