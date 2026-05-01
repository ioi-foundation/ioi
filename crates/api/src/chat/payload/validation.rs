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
    let inferred_format =
        infer_download_bundle_export_format(&summary, &notes, &file_hints, None, None);
    let synthesized_csv = synthesize_download_bundle_csv_body(&summary, &notes, &file_hints);
    let (synthesized_export_encoding, synthesized_export_body) =
        synthesize_download_bundle_export_body(
            inferred_format,
            &summary,
            &notes,
            &file_hints,
            None,
        );
    let synthesized_readme = synthesize_download_bundle_readme_body(
        &summary,
        &notes,
        &file_hints,
        if inferred_format == DownloadBundleExportFormat::Csv {
            csv_header_columns(&synthesized_csv)
        } else {
            Vec::new()
        },
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
        let format = infer_download_bundle_export_format_from_path_and_mime(&path, &mime)
            .unwrap_or(inferred_format);
        if path == "readme.md" || mime == "text/markdown" {
            map.insert(
                "body".to_string(),
                serde_json::Value::String(synthesized_readme.clone()),
            );
            map.insert(
                "encoding".to_string(),
                serde_json::Value::String("utf8".to_string()),
            );
        } else if path.ends_with(".csv") || mime == "text/csv" {
            map.insert(
                "body".to_string(),
                serde_json::Value::String(synthesized_csv.clone()),
            );
            map.insert(
                "encoding".to_string(),
                serde_json::Value::String("utf8".to_string()),
            );
        } else if map
            .get("downloadable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            || infer_download_bundle_export_format_from_path_and_mime(&path, &mime).is_some()
        {
            let encoding = match format {
                DownloadBundleExportFormat::Csv => "utf8",
                _ => match synthesized_export_encoding {
                    ChatGeneratedArtifactEncoding::Utf8 => "utf8",
                    ChatGeneratedArtifactEncoding::Base64 => "base64",
                },
            };
            map.insert(
                "body".to_string(),
                serde_json::Value::String(match format {
                    DownloadBundleExportFormat::Csv => synthesized_csv.clone(),
                    _ => synthesized_export_body.clone(),
                }),
            );
            map.insert(
                "encoding".to_string(),
                serde_json::Value::String(encoding.to_string()),
            );
        }
    }
}

pub fn validate_generated_artifact_payload(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) -> Result<(), String> {
    if payload.summary.trim().is_empty() {
        return Err("Chat artifact materialization summary must not be empty.".to_string());
    }
    if payload.files.is_empty() {
        return Err("Chat artifact materialization must contain at least one file.".to_string());
    }
    if request.renderer == ChatRendererKind::WorkspaceSurface {
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
                ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
            )
        })
        .ok_or_else(|| {
            "Generated artifact payload must include a primary or export file.".to_string()
        })?;

    match request.renderer {
        ChatRendererKind::Markdown => {
            validate_exact_primary_file(primary_file, ".md", "text/markdown", true)?;
        }
        ChatRendererKind::HtmlIframe => {
            validate_exact_primary_file(primary_file, ".html", "text/html", true)?;
            let html = primary_file.body.as_str();
            let lower = html.to_ascii_lowercase();
            if !(lower.contains("<html") || lower.contains("<!doctype html")) {
                return Err("HTML iframe artifacts must contain an HTML document.".to_string());
            }
            if let Some(failure) =
                renderer_document_completeness_failure(request.renderer, html, &lower)
            {
                return Err(failure.to_string());
            }
            if chat_modal_first_html_enabled() {
                if let Some(failure) =
                    modal_first_html_interaction_contract_failure(request, &lower)
                {
                    return Err(failure.to_string());
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
            if html_has_unfocusable_rollover_marks(&lower) {
                return Err(
                    "HTML iframe artifacts that wire focus-based detail behavior must make their data-detail marks keyboard-focusable."
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
            if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && !contains_html_interaction_hooks(&lower)
            {
                return Err(
                    "Interactive HTML iframe artifacts must contain real interactive controls or handlers."
                        .to_string(),
                );
            }
        }
        ChatRendererKind::JsxSandbox => {
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
        ChatRendererKind::Svg => {
            validate_exact_primary_file(primary_file, ".svg", "image/svg+xml", true)?;
            let svg = primary_file.body.as_str();
            let lower = svg.to_ascii_lowercase();
            if !lower.contains("<svg") {
                return Err("SVG artifacts must contain an <svg element.".to_string());
            }
            if let Some(failure) =
                renderer_document_completeness_failure(request.renderer, svg, &lower)
            {
                return Err(failure.to_string());
            }
        }
        ChatRendererKind::Mermaid => {
            if !primary_file.path.ends_with(".mermaid") && !primary_file.path.ends_with(".mmd") {
                return Err("Mermaid artifacts must end with .mermaid or .mmd.".to_string());
            }
            if !primary_file.renderable {
                return Err("Mermaid artifacts must be renderable.".to_string());
            }
        }
        ChatRendererKind::PdfEmbed => {
            validate_exact_primary_file(primary_file, ".pdf", "application/pdf", true)?;
            if let Some(failure) = pdf_source_contract_failure(&primary_file.body) {
                return Err(failure.to_string());
            }
        }
        ChatRendererKind::DownloadCard => {
            if payload.files.iter().any(|file| file.renderable) {
                return Err(
                    "Download-card artifacts must not mark files as renderable.".to_string()
                );
            }
        }
        ChatRendererKind::BundleManifest => {
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
                ChatArtifactClass::CompoundBundle | ChatArtifactClass::ReportBundle
            ) {
                return Err(
                    "bundle_manifest renderer requires compound_bundle or report_bundle."
                        .to_string(),
                );
            }
        }
        ChatRendererKind::WorkspaceSurface => {}
    }

    Ok(())
}

pub(crate) fn renderer_document_completeness_failure(
    renderer: ChatRendererKind,
    document: &str,
    lower: &str,
) -> Option<&'static str> {
    match renderer {
        ChatRendererKind::HtmlIframe => html_document_completeness_failure(document, lower),
        ChatRendererKind::Svg => svg_document_completeness_failure(document, lower),
        _ => None,
    }
}

fn html_document_completeness_failure<'a>(html: &'a str, lower: &'a str) -> Option<&'static str> {
    if lower.contains("<main") && !lower.contains("</main>") {
        return Some("HTML iframe artifacts must contain a closed <main> region.");
    }
    if markup_has_trailing_unclosed_tag_fragment(html) {
        return Some(
            "HTML iframe artifacts must not end with an unfinished tag or trailing fragment.",
        );
    }
    if markup_has_unclosed_non_void_elements(
        html,
        html_is_void_tag,
        html_has_optional_closing_behavior,
        html_is_raw_text_tag,
    ) {
        return Some(
            "HTML iframe artifacts must not close the document while non-void HTML elements remain unclosed.",
        );
    }
    None
}

fn svg_document_completeness_failure(svg: &str, lower: &str) -> Option<&'static str> {
    if !lower.contains("</svg>") {
        return Some("SVG artifacts must contain a closing </svg> document.");
    }
    if markup_has_trailing_unclosed_tag_fragment(svg) {
        return Some("SVG artifacts must not end with an unfinished tag or trailing fragment.");
    }
    if markup_has_unclosed_non_void_elements(
        svg,
        svg_is_void_tag,
        svg_has_optional_closing_behavior,
        svg_is_raw_text_tag,
    ) {
        return Some(
            "SVG artifacts must not close the document while SVG elements remain unclosed.",
        );
    }
    None
}

fn markup_has_trailing_unclosed_tag_fragment(source: &str) -> bool {
    let trimmed = source.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    let Some(last_gt) = trimmed.rfind('>') else {
        return true;
    };
    !trimmed[last_gt + 1..].trim().is_empty()
}

fn markup_tag_end_index(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut quote: Option<u8> = None;
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(active) if byte == active => quote = None,
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None if byte == b'>' => return Some(index),
            None => {}
        }
        index += 1;
    }
    None
}

fn markup_tag_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'_')
}

fn html_is_void_tag(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn html_has_optional_closing_behavior(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "html"
            | "head"
            | "body"
            | "p"
            | "li"
            | "dt"
            | "dd"
            | "option"
            | "optgroup"
            | "thead"
            | "tbody"
            | "tfoot"
            | "tr"
            | "td"
            | "th"
            | "colgroup"
            | "caption"
            | "rb"
            | "rt"
            | "rtc"
            | "rp"
    )
}

fn html_is_raw_text_tag(tag_name: &str) -> bool {
    matches!(tag_name, "script" | "style" | "textarea" | "title")
}

fn svg_is_void_tag(_tag_name: &str) -> bool {
    false
}

fn svg_has_optional_closing_behavior(_tag_name: &str) -> bool {
    false
}

fn svg_is_raw_text_tag(tag_name: &str) -> bool {
    matches!(tag_name, "script" | "style")
}

fn markup_has_unclosed_non_void_elements(
    source: &str,
    is_void_tag: fn(&str) -> bool,
    has_optional_closing_behavior: fn(&str) -> bool,
    is_raw_text_tag: fn(&str) -> bool,
) -> bool {
    let lower = source.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut stack = Vec::<String>::new();
    let mut index = 0usize;

    while index < bytes.len() {
        let Some(relative_lt) = lower[index..].find('<') else {
            break;
        };
        index += relative_lt;

        if lower[index..].starts_with("<!--") {
            let Some(comment_end) = lower[index + 4..].find("-->") else {
                return true;
            };
            index += 4 + comment_end + 3;
            continue;
        }

        if lower[index..].starts_with("<!") || lower[index..].starts_with("<?") {
            let Some(tag_end) = markup_tag_end_index(source, index + 2) else {
                return true;
            };
            index = tag_end + 1;
            continue;
        }

        let mut cursor = index + 1;
        let is_closing = bytes.get(cursor) == Some(&b'/');
        if is_closing {
            cursor += 1;
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let name_start = cursor;
        while cursor < bytes.len() && markup_tag_name_char(bytes[cursor]) {
            cursor += 1;
        }
        if cursor == name_start {
            index += 1;
            continue;
        }

        let tag_name = &lower[name_start..cursor];
        let Some(tag_end) = markup_tag_end_index(source, cursor) else {
            return true;
        };
        let tag_fragment = lower[index..=tag_end].trim_end();
        let self_closing = tag_fragment.ends_with("/>") || tag_fragment.ends_with("?>");

        if is_closing {
            if is_void_tag(tag_name) || has_optional_closing_behavior(tag_name) {
                index = tag_end + 1;
                continue;
            }
            match stack.pop() {
                Some(open_tag) if open_tag == tag_name => {}
                Some(_) | None => return true,
            }
            index = tag_end + 1;
            continue;
        }

        if !self_closing && !is_void_tag(tag_name) && !has_optional_closing_behavior(tag_name) {
            stack.push(tag_name.to_string());
            if is_raw_text_tag(tag_name) {
                let close_pattern = format!("</{tag_name}");
                let Some(close_relative) = lower[tag_end + 1..].find(&close_pattern) else {
                    return true;
                };
                index = tag_end + 1 + close_relative;
                continue;
            }
        }

        index = tag_end + 1;
    }

    !stack.is_empty()
}

pub(crate) fn parse_and_validate_generated_artifact_payload(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Result<ChatGeneratedArtifactPayload, String> {
    let synthesized_from_raw =
        synthesize_generated_artifact_payload_from_raw_document(raw, request);
    let parsed_payload = parse_chat_generated_artifact_payload(raw).ok();
    let mut generated = parsed_payload
        .clone()
        .or_else(|| synthesized_from_raw.clone())
        .ok_or_else(|| {
            "Failed to parse Chat artifact materialization payload: Chat artifact materialization output missing JSON payload".to_string()
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
    payload: &mut ChatGeneratedArtifactPayload,
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Result<ChatGeneratedArtifactPayload, String> {
    repair_primary_html_body_from_raw_output(payload, raw, request);
    normalize_generated_artifact_file_paths(payload, request);
    normalize_generated_artifact_payload(payload, request);
    if let Err(error) = validate_generated_artifact_payload(payload, request) {
        if chat_artifact_soft_validation_error(&error) {
            payload.notes.push(format!("soft validation: {error}"));
        } else {
            return Err(error);
        }
    }
    Ok(payload.clone())
}

fn primary_generated_artifact_file(
    payload: &ChatGeneratedArtifactPayload,
) -> Option<&ChatGeneratedArtifactFile> {
    payload.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        )
    })
}

fn repair_primary_html_body_from_raw_output(
    payload: &mut ChatGeneratedArtifactPayload,
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter_mut().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
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

pub(crate) fn synthesize_generated_artifact_payload_from_raw_document(
    raw: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Option<ChatGeneratedArtifactPayload> {
    let body = extract_authored_document_body(raw, request.renderer)?;
    let mime = direct_authored_document_mime(request.renderer)?;
    Some(ChatGeneratedArtifactPayload {
        summary: direct_authored_document_summary(request.renderer).to_string(),
        notes: vec![format!(
            "normalized from raw {} output",
            direct_authored_document_label(request.renderer)
        )],
        files: vec![ChatGeneratedArtifactFile {
            path: default_generated_artifact_file_path(request.renderer, mime),
            mime: mime.to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body,
        }],
    })
}

pub(crate) fn extract_authored_html_document(raw: &str) -> Option<String> {
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

pub(crate) fn extract_authored_document_body(
    raw: &str,
    renderer: ChatRendererKind,
) -> Option<String> {
    match renderer {
        ChatRendererKind::HtmlIframe => extract_authored_html_document(raw),
        ChatRendererKind::Svg => extract_authored_svg_document(raw),
        ChatRendererKind::Markdown => extract_authored_text_document(raw, &["markdown", "md", ""]),
        ChatRendererKind::Mermaid => extract_authored_text_document(raw, &["mermaid", "mmd", ""]),
        ChatRendererKind::PdfEmbed => extract_authored_text_document(raw, &["text", ""]),
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

fn direct_authored_document_label(renderer: ChatRendererKind) -> &'static str {
    match renderer {
        ChatRendererKind::Markdown => "markdown document",
        ChatRendererKind::HtmlIframe => "html document",
        ChatRendererKind::Svg => "svg document",
        ChatRendererKind::Mermaid => "mermaid diagram",
        ChatRendererKind::PdfEmbed => "pdf source document",
        _ => "document",
    }
}

fn direct_authored_document_summary(renderer: ChatRendererKind) -> &'static str {
    match renderer {
        ChatRendererKind::Markdown => "Markdown artifact",
        ChatRendererKind::HtmlIframe => "Interactive HTML artifact",
        ChatRendererKind::Svg => "SVG artifact",
        ChatRendererKind::Mermaid => "Mermaid artifact",
        ChatRendererKind::PdfEmbed => "PDF artifact",
        _ => "Document artifact",
    }
}

fn modal_first_html_interaction_contract_failure(
    request: &ChatOutcomeArtifactRequest,
    lower: &str,
) -> Option<&'static str> {
    if request.artifact_class != ChatArtifactClass::InteractiveSingleFile {
        return None;
    }

    if !contains_html_interaction_hooks(lower) {
        return Some(
            "Interactive HTML iframe artifacts must contain real interactive controls or handlers.",
        );
    }

    let uses_native_details_toggle = lower.contains("<details") && lower.contains("<summary");
    if !uses_native_details_toggle
        && !html_contains_stateful_interaction_behavior(lower)
        && !modal_first_visible_form_state_exception(lower)
    {
        return Some(
            "Interactive HTML iframe artifacts must update on-page state or shared detail, not only surface inert controls.",
        );
    }

    if html_interactions_are_navigation_only(lower) {
        return Some(
            "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
        );
    }

    None
}

fn modal_first_visible_form_state_exception(lower: &str) -> bool {
    let has_form_control = lower.contains("<select")
        || (lower.contains("<input")
            && (lower.contains("type=\"range\"")
                || lower.contains("type='range'")
                || lower.contains("type=\"number\"")
                || lower.contains("type='number'")));
    has_form_control
        && count_populated_html_response_regions(lower) > 0
        && (lower.contains("calculator")
            || lower.contains("estimator")
            || lower.contains("payment")
            || lower.contains("adjust the inputs"))
}

fn direct_authored_document_mime(renderer: ChatRendererKind) -> Option<&'static str> {
    match renderer {
        ChatRendererKind::Markdown => Some("text/markdown"),
        ChatRendererKind::HtmlIframe => Some("text/html"),
        ChatRendererKind::Svg => Some("image/svg+xml"),
        ChatRendererKind::Mermaid => Some("text/plain"),
        ChatRendererKind::PdfEmbed => Some("application/pdf"),
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_generated_artifact_payload_against_brief(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
) -> Result<(), String> {
    validate_generated_artifact_payload_against_brief_with_edit_intent(
        payload, request, brief, None,
    )
}

pub(crate) fn validate_generated_artifact_payload_against_brief_with_edit_intent(
    payload: &ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    edit_intent: Option<&ChatArtifactEditIntent>,
) -> Result<(), String> {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return Ok(());
    }
    if chat_modal_first_html_enabled() {
        return Ok(());
    }

    let Some(primary_file) = payload.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        )
    }) else {
        return Ok(());
    };
    let lower = primary_file.body.to_ascii_lowercase();
    let response_regions = count_populated_html_response_regions(&lower);
    let chart_regions = count_populated_html_chart_regions(&lower);
    let evidence_regions = count_populated_html_evidence_regions(&lower);
    let actionable_affordances = count_html_actionable_affordances(&lower);
    let required_interaction_goals = brief_required_interaction_goal_count(brief);
    let single_control_detail_exception = actionable_affordances == 1
        && html_contains_rollover_detail_behavior(&lower)
        && (required_interaction_goals <= 1
            || lower.contains("calculator")
            || lower.contains("estimator")
            || lower.contains("payment"));
    let selection_scoped_patch = edit_intent.is_some_and(|intent| {
        intent.patch_existing_artifact && !intent.selected_targets.is_empty()
    });
    let has_chart_surface = chart_regions > 0
        || count_html_svg_regions(&lower) > 0
        || html_contains_empty_chart_container_regions(&lower);

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && required_interaction_goals > 0
        && brief_requires_response_region(brief)
        && response_regions == 0
    {
        return Err(
            "HTML iframe briefs with interactive query goals must include a populated response or comparison region on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && actionable_affordances < 2
    {
        return Err(
            "HTML iframe briefs that call for state switching must surface at least two actionable controls on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && !html_contains_state_transition_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for state switching must wire controls to produce a visible on-page state change."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_view_switching(brief)
        && evidence_regions + chart_regions < 2
    {
        return Err(
            "HTML iframe briefs that call for state switching must keep at least two evidence surfaces or authored states available on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && ((actionable_affordances < 2 && !single_control_detail_exception)
            || (actionable_affordances < 3 && !html_contains_rollover_detail_behavior(&lower)))
    {
        return Err(
            "HTML iframe briefs that call for inspection detail must surface at least three actionable evidence marks or controls on first paint."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && brief_requires_rollover_detail(brief)
        && !html_contains_rollover_detail_behavior(&lower)
    {
        return Err(
            "HTML iframe briefs that call for inspection detail must wire hover, focus, or equivalent handlers to update visible on-page context."
                .to_string(),
        );
    }

    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
        && has_chart_surface
        && required_interaction_goals >= 2
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

fn chat_artifact_soft_validation_error(error: &str) -> bool {
    [
        "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint.",
        "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint.",
        "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint.",
        "HTML iframe artifacts must contain at least three sectioning elements with first-paint content.",
        "Interactive HTML iframe artifacts must update on-page state or visible response context, not only scroll, jump, or log.",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

pub(crate) fn normalize_generated_artifact_payload(
    payload: &mut ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
) {
    if request.renderer == ChatRendererKind::DownloadCard {
        let mut file_hints = payload
            .files
            .iter()
            .map(|file| (file.path.clone(), file.mime.clone()))
            .collect::<Vec<_>>();
        let inferred_format = infer_download_bundle_export_format(
            &payload.summary,
            &payload.notes,
            &file_hints,
            None,
            None,
        );
        if !payload
            .files
            .iter()
            .any(|file| file.path.eq_ignore_ascii_case("README.md"))
        {
            payload.files.push(ChatGeneratedArtifactFile {
                path: "README.md".to_string(),
                mime: "text/markdown".to_string(),
                role: ChatArtifactFileRole::Supporting,
                renderable: false,
                downloadable: true,
                encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                body: String::new(),
            });
        }
        if !payload.files.iter().any(|file| {
            !is_download_bundle_readme_file(&file.path, &file.mime)
                && infer_download_bundle_export_format_from_path_and_mime(&file.path, &file.mime)
                    .is_some()
        }) {
            payload.files.push(ChatGeneratedArtifactFile {
                path: default_download_bundle_export_path(inferred_format, &payload.summary),
                mime: default_download_bundle_export_mime(inferred_format).to_string(),
                role: ChatArtifactFileRole::Export,
                renderable: false,
                downloadable: true,
                encoding: Some(download_bundle_export_encoding(inferred_format)),
                body: String::new(),
            });
        }

        for file in &mut payload.files {
            file.renderable = false;
            file.downloadable = true;
        }
        file_hints = payload
            .files
            .iter()
            .map(|file| (file.path.clone(), file.mime.clone()))
            .collect::<Vec<_>>();
        let synthesized_csv =
            synthesize_download_bundle_csv_body(&payload.summary, &payload.notes, &file_hints);
        let (synthesized_export_encoding, synthesized_export_body) =
            synthesize_download_bundle_export_body(
                inferred_format,
                &payload.summary,
                &payload.notes,
                &file_hints,
                None,
            );
        for file in &mut payload.files {
            let path = file.path.to_ascii_lowercase();
            let format =
                infer_download_bundle_export_format_from_path_and_mime(&file.path, &file.mime)
                    .unwrap_or(inferred_format);
            if !download_bundle_export_body_looks_complete(format, &file.body) {
                if path == "readme.md" || file.mime == "text/markdown" {
                    continue;
                }
                match format {
                    DownloadBundleExportFormat::Csv => {
                        file.body = synthesized_csv.clone();
                        file.encoding = Some(ChatGeneratedArtifactEncoding::Utf8);
                    }
                    _ => {
                        file.body = synthesized_export_body.clone();
                        file.encoding = Some(synthesized_export_encoding);
                    }
                }
                file.role = ChatArtifactFileRole::Export;
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
            if inferred_format == DownloadBundleExportFormat::Csv {
                csv_columns
            } else {
                Vec::new()
            },
        );
        for file in &mut payload.files {
            let path = file.path.to_ascii_lowercase();
            if (path == "readme.md" || file.mime == "text/markdown")
                && !download_bundle_readme_looks_complete(&file.body)
            {
                file.body = synthesized_readme.clone();
                file.encoding = Some(ChatGeneratedArtifactEncoding::Utf8);
                file.role = ChatArtifactFileRole::Supporting;
            }
        }
        return;
    }

    if request.renderer != ChatRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter_mut().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
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
    if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
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

    let nested_payload = parse_chat_generated_artifact_payload(trimmed).ok()?;
    let nested_primary = nested_payload.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
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
    payload: &mut ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
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
    renderer: ChatRendererKind,
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

fn default_generated_artifact_file_path(renderer: ChatRendererKind, mime: &str) -> String {
    match renderer {
        ChatRendererKind::Markdown => "artifact.md".to_string(),
        ChatRendererKind::HtmlIframe => "index.html".to_string(),
        ChatRendererKind::JsxSandbox => "artifact.jsx".to_string(),
        ChatRendererKind::Svg => "artifact.svg".to_string(),
        ChatRendererKind::Mermaid => "diagram.mermaid".to_string(),
        ChatRendererKind::PdfEmbed => "artifact.pdf".to_string(),
        ChatRendererKind::BundleManifest => "bundle-manifest.json".to_string(),
        ChatRendererKind::DownloadCard => {
            if mime.eq_ignore_ascii_case("application/pdf") {
                "download.pdf".to_string()
            } else {
                "download.bin".to_string()
            }
        }
        ChatRendererKind::WorkspaceSurface => "artifact".to_string(),
    }
}

pub(crate) fn enrich_generated_artifact_payload(
    payload: &mut ChatGeneratedArtifactPayload,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
) {
    match request.renderer {
        ChatRendererKind::Svg => {
            let Some(primary_svg) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
                ) && (file.mime == "image/svg+xml" || file.path.ends_with(".svg"))
            }) else {
                return;
            };

            primary_svg.body = ensure_svg_accessibility_metadata(&primary_svg.body, brief);
        }
        ChatRendererKind::HtmlIframe => {
            if chat_modal_first_html_enabled() {
                return;
            }
            let Some(primary_html) = payload.files.iter_mut().find(|file| {
                matches!(
                    file.role,
                    ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
                ) && (file.mime == "text/html" || file.path.ends_with(".html"))
            }) else {
                return;
            };

            primary_html.body = ensure_html_button_accessibility_contract(&primary_html.body);
            primary_html.body = ensure_html_mapped_panels_define_referenced_ids(&primary_html.body);
            primary_html.body = ensure_html_view_switch_contract(&primary_html.body);
            primary_html.body = ensure_first_visible_mapped_view_panel(&primary_html.body);
            primary_html.body = ensure_minimum_html_shared_detail_region(&primary_html.body);
            primary_html.body = ensure_minimum_html_mapped_panel_content(&primary_html.body);
            primary_html.body =
                ensure_minimum_brief_rollover_detail_marks(&primary_html.body, brief);
            primary_html.body = ensure_minimum_html_rollover_detail_payloads(&primary_html.body);
            primary_html.body = ensure_grouped_html_rollover_detail_marks(&primary_html.body);
            primary_html.body = ensure_focusable_html_rollover_marks(&primary_html.body);
            primary_html.body = ensure_html_interaction_polish_styles(&primary_html.body);
            primary_html.body = ensure_html_rollover_detail_contract(&primary_html.body);
        }
        _ => {}
    }
}

pub(crate) fn renderer_primary_view_contract_failure(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate: &ChatGeneratedArtifactPayload,
) -> Option<&'static str> {
    let primary_file = candidate.files.iter().find(|file| {
        matches!(
            file.role,
            ChatArtifactFileRole::Primary | ChatArtifactFileRole::Export
        )
    })?;

    let lower = primary_file.body.to_ascii_lowercase();
    if let Some(failure) =
        renderer_document_completeness_failure(request.renderer, &primary_file.body, &lower)
    {
        return Some(failure);
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if chat_modal_first_html_enabled() {
                if let Some(failure) =
                    modal_first_html_interaction_contract_failure(request, &lower)
                {
                    return Some(failure);
                }
            }
            let response_regions = count_populated_html_response_regions(&lower);
            let evidence_surfaces = count_populated_html_evidence_regions(&lower)
                + count_populated_html_chart_regions(&lower);
            let actionable_affordances = count_html_actionable_affordances(&lower);
            let required_interaction_goals = brief_required_interaction_goal_count(brief);
            let single_control_detail_exception = actionable_affordances == 1
                && html_contains_rollover_detail_behavior(&lower)
                && (required_interaction_goals <= 1
                    || lower.contains("calculator")
                    || lower.contains("estimator")
                    || lower.contains("payment"));
            if count_html_nonempty_sectioning_elements(&lower) < 3 {
                Some("HTML sectioning regions are empty shells on first paint.")
            } else if html_contains_placeholder_markers(&lower) {
                Some("HTML still contains placeholder-grade copy or comments on first paint.")
            } else if html_interactions_are_navigation_only(&lower) {
                Some("HTML interactions are navigation-only and do not update visible response state.")
            } else if html_contains_empty_chart_container_regions(&lower) {
                Some("HTML chart containers are empty placeholder shells on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_response_region(brief)
                && response_regions == 0
            {
                Some("HTML interactive query goals do not surface a populated response region on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && actionable_affordances < 2
            {
                Some("HTML state switching does not surface enough actionable controls on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && !html_contains_state_transition_behavior(&lower)
            {
                Some(
                    "HTML state switching does not wire controls to produce visible state changes.",
                )
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_view_switching(brief)
                && evidence_surfaces < 2
            {
                Some("HTML state switching does not keep enough authored evidence surfaces available on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && required_interaction_goals >= 2
                && actionable_affordances < 2
                && !(actionable_affordances == 1
                    && response_regions > 0
                    && html_contains_state_transition_behavior(&lower))
            {
                Some("HTML multi-step interaction briefs must surface at least two actionable controls on first paint.")
            } else if html_contains_unlabeled_chart_svg_regions(&lower) {
                Some("HTML chart SVG regions are unlabeled on first paint.")
            } else if html_contains_placeholder_svg_regions(&lower) {
                Some("HTML chart regions are empty placeholder shells on first paint.")
            } else if html_references_missing_dom_ids(&lower) {
                Some("HTML interactions target missing DOM ids in the surfaced artifact.")
            } else if html_has_unfocusable_rollover_marks(&lower) {
                Some("HTML interactive detail affordances are not keyboard-focusable.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && required_interaction_goals > 0
                && response_regions == 0
            {
                Some("HTML required interactions do not surface a visible response region on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && (count_populated_html_chart_regions(&lower) > 0
                    || count_html_svg_regions(&lower) > 0
                    || html_contains_empty_chart_container_regions(&lower))
                && required_interaction_goals >= 2
                && evidence_surfaces < 2
            {
                Some("HTML only surfaces one evidence view on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_rollover_detail(brief)
                && ((actionable_affordances < 2 && !single_control_detail_exception)
                    || (actionable_affordances < 3
                        && !html_contains_rollover_detail_behavior(&lower)))
            {
                Some("HTML only surfaces sparse inspection affordances on first paint.")
            } else if request.artifact_class == ChatArtifactClass::InteractiveSingleFile
                && brief_requires_rollover_detail(brief)
                && !html_contains_rollover_detail_behavior(&lower)
            {
                Some("HTML lacks hover, focus, or equivalent inspection behavior for the requested detail interactions.")
            } else {
                None
            }
        }
        ChatRendererKind::Svg => svg_primary_view_contract_failure(&primary_file.body),
        ChatRendererKind::PdfEmbed => pdf_source_contract_failure(&primary_file.body),
        _ => None,
    }
}

pub(crate) fn enforce_renderer_validation_contract(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    candidate: &ChatGeneratedArtifactPayload,
    mut validation: ChatArtifactValidationResult,
) -> ChatArtifactValidationResult {
    neutralize_false_sequence_browsing_penalty(brief, &mut validation);

    let Some(contradiction) = renderer_primary_view_contract_failure(request, brief, candidate)
    else {
        return validation;
    };

    if validation.classification != ChatArtifactValidationStatus::Blocked {
        validation.classification = ChatArtifactValidationStatus::Repairable;
    }
    validation.interaction_relevance = validation.interaction_relevance.min(2);
    validation.layout_coherence = validation.layout_coherence.min(2);
    validation.visual_hierarchy = validation.visual_hierarchy.min(2);
    validation.completeness = validation.completeness.min(2);
    validation.trivial_shell_detected = true;
    validation.deserves_primary_artifact_view = false;
    validation.strongest_contradiction = Some(contradiction.to_string());
    validation.rationale =
        "Renderer contract failures keep the first paint from qualifying as primary output."
            .to_string();
    if !validation
        .issue_classes
        .iter()
        .any(|value| value == "renderer_contract")
    {
        validation
            .issue_classes
            .push("renderer_contract".to_string());
    }
    if !validation
        .blocked_reasons
        .iter()
        .any(|value| value == contradiction)
    {
        validation.blocked_reasons.push(contradiction.to_string());
    }
    if !validation
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
        validation
            .file_findings
            .push(format!("{file_path}: renderer contract failure"));
    }
    if !validation
        .repair_hints
        .iter()
        .any(|value| value.contains("pre-rendered"))
    {
        validation.repair_hints.push(
            "Repair the first paint with pre-rendered panels, populated evidence surfaces, and a visible default detail state.".to_string(),
        );
    }
    validation.aesthetic_verdict =
        "Renderer contract failure keeps the surface below the artifact presentation bar."
            .to_string();
    validation.interaction_verdict =
        "Interaction contract does not hold on first paint yet.".to_string();
    if validation.truthfulness_warnings.is_empty() {
        validation.truthfulness_warnings.push(
            "The surfaced artifact is still relying on incomplete or structurally misleading first-paint output."
                .to_string(),
        );
    }
    validation.recommended_next_pass = Some("structural_repair".to_string());
    validation
}

fn neutralize_false_sequence_browsing_penalty(
    brief: &ChatArtifactBrief,
    validation: &mut ChatArtifactValidationResult,
) {
    if brief_requires_sequence_browsing(brief)
        || !validation_false_positive_sequence_penalty(validation)
        || validation.generic_shell_detected
        || validation.trivial_shell_detected
        || !validation.deserves_primary_artifact_view
        || validation.request_faithfulness < 4
        || validation.concept_coverage < 4
        || validation.layout_coherence < 4
        || validation.visual_hierarchy < 4
    {
        return;
    }

    validation.classification = ChatArtifactValidationStatus::Pass;
    validation.interaction_relevance = validation.interaction_relevance.max(4);
    validation.completeness = validation.completeness.max(4);
    validation.strongest_contradiction = None;
    if validation
        .rationale
        .to_ascii_lowercase()
        .contains("sequence browsing")
        || validation
            .rationale
            .to_ascii_lowercase()
            .contains("timeline")
    {
        validation.rationale =
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

fn validation_false_positive_sequence_penalty(validation: &ChatArtifactValidationResult) -> bool {
    let contradiction = validation
        .strongest_contradiction
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rationale = validation.rationale.to_ascii_lowercase();
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
    file: &ChatGeneratedArtifactFile,
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
