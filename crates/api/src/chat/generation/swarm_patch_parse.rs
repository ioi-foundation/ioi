use super::*;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChatArtifactPatchOperationKind {
    CreateFile,
    ReplaceFile,
    ReplaceRegion,
    DeleteFile,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChatArtifactPatchOperation {
    pub(crate) kind: ChatArtifactPatchOperationKind,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) region_id: Option<String>,
    #[serde(default)]
    pub(crate) mime: Option<String>,
    #[serde(default)]
    pub(crate) role: Option<ChatArtifactFileRole>,
    #[serde(default)]
    pub(crate) renderable: Option<bool>,
    #[serde(default)]
    pub(crate) downloadable: Option<bool>,
    #[serde(default)]
    pub(crate) encoding: Option<ChatGeneratedArtifactEncoding>,
    #[serde(default)]
    pub(crate) body: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChatArtifactPatchEnvelope {
    #[serde(default)]
    pub(crate) summary: Option<String>,
    #[serde(default)]
    pub(crate) notes: Vec<String>,
    #[serde(default)]
    pub(crate) operations: Vec<ChatArtifactPatchOperation>,
}

pub(super) fn parse_chat_artifact_patch_envelope(
    raw: &str,
) -> Result<ChatArtifactPatchEnvelope, String> {
    serde_json::from_str::<ChatArtifactPatchEnvelope>(raw)
        .or_else(|_| {
            let sanitized = sanitize_loose_json_string_literals(raw);
            serde_json::from_str::<ChatArtifactPatchEnvelope>(&sanitized)
                .map_err(|error| error.to_string())
        })
        .or_else(|_| {
            let extracted = extract_first_json_object(raw)
                .ok_or_else(|| "Chat swarm worker output missing JSON object.".to_string())?;
            serde_json::from_str::<ChatArtifactPatchEnvelope>(&extracted)
                .map_err(|error| error.to_string())
        })
        .or_else(|_| {
            let extracted = extract_first_json_object(raw)
                .ok_or_else(|| "Chat swarm worker output missing JSON object.".to_string())?;
            let sanitized = sanitize_loose_json_string_literals(&extracted);
            serde_json::from_str::<ChatArtifactPatchEnvelope>(&sanitized)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| format!("Failed to parse Chat swarm patch envelope: {error}"))
}

pub(super) fn extract_relaxed_json_string_field(raw: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let start = raw.find(&needle)?;
    let mut index = start + needle.len();
    let bytes = raw.as_bytes();
    while let Some(byte) = bytes.get(index) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        index += 1;
    }
    if bytes.get(index).copied()? != b':' {
        return None;
    }
    index += 1;
    while let Some(byte) = bytes.get(index) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        index += 1;
    }
    if bytes.get(index).copied()? != b'"' {
        return None;
    }
    index += 1;

    let mut encoded = String::new();
    let mut escaped = false;
    for ch in raw[index..].chars() {
        if escaped {
            encoded.push('\\');
            encoded.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
            }
            '"' => {
                return serde_json::from_str::<String>(&format!("\"{encoded}\"")).ok();
            }
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            _ => encoded.push(ch),
        }
    }

    None
}

pub(super) fn extract_html_tag_block(raw: &str, tag: &str) -> Option<String> {
    let start_pattern = format!("<{tag}");
    let end_pattern = format!("</{tag}>");
    let start = raw.find(&start_pattern)?;
    if let Some(end) = raw[start..].rfind(&end_pattern) {
        let end_index = start + end + end_pattern.len();
        return Some(raw[start..end_index].trim().to_string());
    }
    let mut block = raw[start..].trim().to_string();
    if !block.ends_with(&end_pattern) {
        block.push('\n');
        block.push_str(&end_pattern);
    }
    Some(block)
}

pub(super) fn extract_html_document_block(raw: &str) -> Option<String> {
    let start = raw.find("<!DOCTYPE html").or_else(|| raw.find("<html"))?;
    if let Some(end) = raw[start..].rfind("</html>") {
        let end_index = start + end + "</html>".len();
        return Some(raw[start..end_index].trim().to_string());
    }
    let mut block = raw[start..].trim().to_string();
    if !block.contains("</body>") {
        block.push_str("\n</body>");
    }
    if !block.ends_with("</html>") {
        block.push_str("\n</html>");
    }
    Some(block)
}

pub(super) fn extract_section_like_block(raw: &str) -> Option<String> {
    for tag in ["section", "article", "main", "div"] {
        if let Some(block) = extract_html_tag_block(raw, tag) {
            return Some(block);
        }
    }
    None
}

pub(super) fn looks_like_css_source(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.contains(":root")
        || trimmed.contains("--")
        || trimmed.contains("@media")
        || trimmed.contains('@')
        || (trimmed.contains('{')
            && trimmed.contains('}')
            && trimmed.contains(':')
            && (trimmed.contains('.') || trimmed.contains('#')))
}

pub(super) fn looks_like_js_source(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.contains("addEventListener")
        || trimmed.contains("querySelector")
        || trimmed.contains("document.")
        || trimmed.contains("window.")
        || trimmed.contains("const ")
        || trimmed.contains("let ")
        || trimmed.contains("function ")
        || trimmed.contains("=>")
}

pub(super) fn salvage_chat_swarm_patch_envelope(
    request: &ChatOutcomeArtifactRequest,
    work_item: &ChatArtifactWorkItem,
    raw: &str,
) -> Option<ChatArtifactPatchEnvelope> {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return None;
    }

    let decoded_raw = decode_html_transport_escapes(raw);

    let summary = extract_relaxed_json_string_field(raw, "summary");
    let notes = vec!["Recovered the bounded worker change from malformed JSON.".to_string()];

    let infer_repair_region_id = || {
        extract_relaxed_json_string_field(raw, "regionId")
            .and_then(|candidate| {
                work_item
                    .write_regions
                    .iter()
                    .find(|region| html_swarm_region_ids_match(region, &candidate))
                    .cloned()
                    .or_else(|| Some(candidate))
            })
            .or_else(|| {
                let lowered = raw.to_ascii_lowercase();
                if lowered.contains("<script") {
                    work_item
                        .write_regions
                        .iter()
                        .find(|region| html_swarm_region_ids_match(region, "interaction"))
                        .cloned()
                } else if lowered.contains("<style") {
                    work_item
                        .write_regions
                        .iter()
                        .find(|region| html_swarm_region_ids_match(region, "style-system"))
                        .cloned()
                } else {
                    work_item
                        .write_regions
                        .iter()
                        .find(|region| region.starts_with("section:"))
                        .cloned()
                }
            })
            .or_else(|| work_item.write_regions.first().cloned())
    };

    match work_item.role {
        ChatArtifactWorkerRole::Skeleton => {
            let body = extract_relaxed_json_string_field(raw, "body")
                .or_else(|| extract_html_document_block(raw))?;
            Some(ChatArtifactPatchEnvelope {
                summary,
                notes,
                operations: vec![ChatArtifactPatchOperation {
                    kind: ChatArtifactPatchOperationKind::CreateFile,
                    path: "index.html".to_string(),
                    region_id: None,
                    mime: Some("text/html".to_string()),
                    role: Some(ChatArtifactFileRole::Primary),
                    renderable: Some(true),
                    downloadable: Some(true),
                    encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                    body: Some(body),
                }],
            })
        }
        ChatArtifactWorkerRole::SectionContent
        | ChatArtifactWorkerRole::StyleSystem
        | ChatArtifactWorkerRole::Interaction
        | ChatArtifactWorkerRole::Integrator
        | ChatArtifactWorkerRole::Repair => {
            let body = match work_item.role {
                ChatArtifactWorkerRole::SectionContent => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_section_like_block(&decoded_raw))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            (!trimmed.is_empty())
                                .then(|| format!("<section>\n{}\n</section>", trimmed))
                        })?
                }
                ChatArtifactWorkerRole::StyleSystem => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_html_tag_block(&decoded_raw, "style"))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            looks_like_css_source(trimmed)
                                .then(|| format!("<style>\n{}\n</style>", trimmed))
                        })?
                }
                ChatArtifactWorkerRole::Interaction => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_html_tag_block(&decoded_raw, "script"))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            looks_like_js_source(trimmed)
                                .then(|| format!("<script>\n{}\n</script>", trimmed))
                        })?
                }
                ChatArtifactWorkerRole::Integrator => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_html_tag_block(&decoded_raw, "script"))
                        .or_else(|| extract_html_tag_block(&decoded_raw, "style"))
                        .or_else(|| extract_section_like_block(&decoded_raw))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            if looks_like_js_source(trimmed) {
                                Some(format!("<script>\n{}\n</script>", trimmed))
                            } else if looks_like_css_source(trimmed) {
                                Some(format!("<style>\n{}\n</style>", trimmed))
                            } else if !trimmed.is_empty() {
                                Some(format!("<section>\n{}\n</section>", trimmed))
                            } else {
                                None
                            }
                        })?
                }
                ChatArtifactWorkerRole::Repair => extract_relaxed_json_string_field(raw, "body")
                    .or_else(|| extract_html_tag_block(&decoded_raw, "script"))
                    .or_else(|| extract_html_tag_block(&decoded_raw, "style"))
                    .or_else(|| extract_section_like_block(&decoded_raw))
                    .or_else(|| {
                        let trimmed = decoded_raw.trim();
                        if looks_like_js_source(trimmed) {
                            Some(format!("<script>\n{}\n</script>", trimmed))
                        } else if looks_like_css_source(trimmed) {
                            Some(format!("<style>\n{}\n</style>", trimmed))
                        } else if !trimmed.is_empty() {
                            Some(format!("<section>\n{}\n</section>", trimmed))
                        } else {
                            None
                        }
                    })?,
                _ => return None,
            };
            let region_id = if matches!(
                work_item.role,
                ChatArtifactWorkerRole::Integrator | ChatArtifactWorkerRole::Repair
            ) {
                infer_repair_region_id()?
            } else {
                work_item.write_regions.first()?.clone()
            };
            Some(ChatArtifactPatchEnvelope {
                summary,
                notes,
                operations: vec![ChatArtifactPatchOperation {
                    kind: ChatArtifactPatchOperationKind::ReplaceRegion,
                    path: "index.html".to_string(),
                    region_id: Some(region_id),
                    mime: Some("text/html".to_string()),
                    role: Some(ChatArtifactFileRole::Primary),
                    renderable: Some(true),
                    downloadable: Some(true),
                    encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
                    body: Some(body),
                }],
            })
        }
        _ => None,
    }
}

pub(super) fn sanitize_loose_json_string_literals(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len() + 64);
    let mut in_string = false;
    let mut escaped = false;

    for ch in raw.chars() {
        if in_string {
            match ch {
                '"' if !escaped => {
                    in_string = false;
                    sanitized.push(ch);
                    escaped = false;
                }
                '\\' if !escaped => {
                    sanitized.push(ch);
                    escaped = true;
                }
                '\n' if !escaped => {
                    sanitized.push_str("\\n");
                }
                '\r' if !escaped => {
                    sanitized.push_str("\\r");
                }
                _ => {
                    sanitized.push(ch);
                    escaped = false;
                }
            }
        } else {
            if ch == '"' {
                in_string = true;
            }
            sanitized.push(ch);
        }
    }

    sanitized
}

pub(super) fn swarm_patch_schema_contract() -> &'static str {
    "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string | null>,\n  \"notes\": [<string>],\n  \"operations\": [\n    {\n      \"kind\": \"create_file\" | \"replace_file\" | \"replace_region\" | \"delete_file\",\n      \"path\": <string>,\n      \"regionId\": <string | null>,\n      \"mime\": <string | null>,\n      \"role\": null | \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean | null>,\n      \"downloadable\": <boolean | null>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string | null>\n    }\n  ]\n}\nRules:\n1) Output JSON only.\n2) Only touch the allowed paths and regions.\n3) Use replace_region when the work item owns a region, not replace_file.\n4) Preserve strong authored structure outside the assigned scope.\n5) Do not emit placeholder copy, TODO markers, or HTML comments unless they are the required STUDIO_REGION markers in the HTML skeleton worker."
}

pub(super) fn html_swarm_region_marker_start(region_id: &str) -> String {
    format!("<!-- STUDIO_REGION_START:{region_id} -->")
}

pub(super) fn html_swarm_region_marker_end(region_id: &str) -> String {
    format!("<!-- STUDIO_REGION_END:{region_id} -->")
}

pub(super) fn html_swarm_region_id_variants(region_id: &str) -> Vec<String> {
    let mut variants = vec![region_id.to_string()];
    if let Some(stripped) = region_id.strip_prefix("section:") {
        if !stripped.is_empty() && !variants.iter().any(|value| value == stripped) {
            variants.push(stripped.to_string());
        }
    } else if !region_id.is_empty() {
        let prefixed = format!("section:{region_id}");
        if !variants.iter().any(|value| value == &prefixed) {
            variants.push(prefixed);
        }
    }
    variants
}

pub(super) fn html_swarm_region_ids_match(left: &str, right: &str) -> bool {
    html_swarm_region_id_variants(left).iter().any(|candidate| {
        html_swarm_region_id_variants(right)
            .iter()
            .any(|other| other == candidate)
    })
}

pub(super) fn html_swarm_region_default_insert_index(body: &str, region_id: &str) -> usize {
    if region_id == "style-system" {
        return body.find("</head>").unwrap_or(0);
    }
    if region_id == "interaction" {
        return body.find("</body>").unwrap_or(body.len());
    }

    body.find("</main>")
        .or_else(|| body.find("</body>"))
        .unwrap_or(body.len())
}

pub(super) fn ensure_html_swarm_region_marker_pair(body: &str, region_id: &str) -> String {
    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        let end_marker = html_swarm_region_marker_end(&candidate);
        if body.contains(&start_marker) && body.contains(&end_marker) {
            return body.to_string();
        }
    }

    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        if let Some(start_index) = body.find(&start_marker) {
            let content_start = start_index + start_marker.len();
            let insert_at = body[content_start..]
                .find("<!-- STUDIO_REGION_START:")
                .map(|offset| content_start + offset)
                .unwrap_or_else(|| html_swarm_region_default_insert_index(body, region_id));
            let mut rebuilt = String::with_capacity(body.len() + candidate.len() + 48);
            rebuilt.push_str(&body[..insert_at]);
            if !rebuilt.ends_with('\n') {
                rebuilt.push('\n');
            }
            rebuilt.push_str(&html_swarm_region_marker_end(&candidate));
            rebuilt.push('\n');
            rebuilt.push_str(&body[insert_at..]);
            return rebuilt;
        }
    }

    let insert_at = html_swarm_region_default_insert_index(body, region_id);
    let mut rebuilt = String::with_capacity(body.len() + region_id.len() * 2 + 64);
    rebuilt.push_str(&body[..insert_at]);
    if !rebuilt.ends_with('\n') {
        rebuilt.push('\n');
    }
    rebuilt.push_str(&html_swarm_region_marker_start(region_id));
    rebuilt.push('\n');
    rebuilt.push_str(&html_swarm_region_marker_end(region_id));
    rebuilt.push('\n');
    rebuilt.push_str(&body[insert_at..]);
    rebuilt
}

pub(super) fn normalize_html_swarm_skeleton_markers(
    body: &str,
    expected_regions: &[String],
) -> String {
    expected_regions
        .iter()
        .fold(body.to_string(), |current, region| {
            ensure_html_swarm_region_marker_pair(&current, region)
        })
}

pub(super) fn decode_html_transport_escapes(body: &str) -> String {
    if !body.contains("\\n")
        && !body.contains("\\r")
        && !body.contains("\\t")
        && !body.contains("\\\"")
        && !body.contains("\\/")
    {
        return body.to_string();
    }

    body.replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\/", "/")
}

pub(super) fn unwrap_custom_html_region_wrapper(body: &str, region_id: &str) -> String {
    let trimmed = body.trim();
    let (custom_tag, canonical_tag) = match region_id {
        "style-system" => ("style-system", "style"),
        "interaction" => ("interaction", "script"),
        _ => return trimmed.to_string(),
    };
    let start_pattern = format!("<{custom_tag}");
    let end_pattern = format!("</{custom_tag}>");
    if !trimmed.starts_with(&start_pattern) {
        return trimmed.to_string();
    }

    let Some(open_end) = trimmed.find('>') else {
        return trimmed.to_string();
    };
    let inner_end = trimmed.rfind(&end_pattern).unwrap_or(trimmed.len());
    let mut inner = trimmed[open_end + 1..inner_end].trim().to_string();
    if inner.starts_with("<!--") && inner.ends_with("-->") {
        inner = inner
            .trim_start_matches("<!--")
            .trim_end_matches("-->")
            .trim()
            .to_string();
    }
    format!("<{canonical_tag}>\n{}\n</{canonical_tag}>", inner.trim())
}

pub(super) fn normalize_html_swarm_region_replacement(
    region_id: &str,
    replacement: &str,
) -> String {
    let decoded = decode_html_transport_escapes(replacement);
    let unwrapped = unwrap_custom_html_region_wrapper(&decoded, region_id);
    let trimmed = unwrapped.trim();
    match region_id {
        "style-system" => {
            if trimmed.starts_with("<style") {
                trimmed.to_string()
            } else {
                format!("<style>\n{}\n</style>", trimmed)
            }
        }
        "interaction" => {
            if trimmed.starts_with("<script") {
                trimmed.to_string()
            } else {
                format!("<script>\n{}\n</script>", trimmed)
            }
        }
        _ => trimmed.to_string(),
    }
}

pub(super) fn ensure_html_swarm_visible_main_shell(body: &str) -> String {
    if body.contains("<main") {
        return body.to_string();
    }

    let Some(body_start) = body.find("<body") else {
        return body.to_string();
    };
    let Some(open_end_rel) = body[body_start..].find('>') else {
        return body.to_string();
    };
    let content_start = body_start + open_end_rel + 1;
    let script_start = body[content_start..]
        .find("<script")
        .map(|offset| content_start + offset);
    let body_end = body[content_start..]
        .find("</body>")
        .map(|offset| content_start + offset)
        .unwrap_or(body.len());
    let content_end = script_start.unwrap_or(body_end);
    if content_end <= content_start {
        return body.to_string();
    }

    let inner = body[content_start..content_end].trim();
    if inner.is_empty() {
        return body.to_string();
    }

    let mut rebuilt = String::with_capacity(body.len() + 32);
    rebuilt.push_str(&body[..content_start]);
    if !rebuilt.ends_with('\n') {
        rebuilt.push('\n');
    }
    rebuilt.push_str("<main id=\"artifact-main\">\n");
    rebuilt.push_str(inner);
    rebuilt.push_str("\n</main>\n");
    rebuilt.push_str(&body[content_end..]);
    rebuilt
}

pub(super) fn normalize_html_swarm_document(body: &str) -> String {
    let decoded = decode_html_transport_escapes(body);
    let normalized_wrappers = decoded
        .replace("<style-system>", "<style>")
        .replace("</style-system>", "</style>")
        .replace("<interaction>", "<script>")
        .replace("</interaction>", "</script>");
    ensure_html_swarm_visible_main_shell(&normalized_wrappers)
}

pub(super) fn replace_html_swarm_region(
    body: &str,
    region_id: &str,
    replacement: &str,
) -> Result<String, String> {
    let normalized_replacement = normalize_html_swarm_region_replacement(region_id, replacement);
    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        let end_marker = html_swarm_region_marker_end(&candidate);
        let Some(start_index) = body.find(&start_marker) else {
            continue;
        };
        let content_start = start_index + start_marker.len();
        let Some(relative_end_index) = body[content_start..].find(&end_marker) else {
            return Err(format!(
                "Region marker end '{candidate}' is missing from the canonical artifact."
            ));
        };
        let end_index = content_start + relative_end_index;
        let mut rebuilt = String::with_capacity(body.len() + normalized_replacement.len() + 8);
        rebuilt.push_str(&body[..content_start]);
        rebuilt.push('\n');
        rebuilt.push_str(normalized_replacement.trim());
        rebuilt.push('\n');
        rebuilt.push_str(&body[end_index..]);
        return Ok(rebuilt);
    }
    Err(format!(
        "Region marker '{region_id}' is missing from the canonical artifact."
    ))
}

pub(super) fn strip_html_swarm_region_markers(body: &str) -> String {
    body.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !(trimmed.starts_with("<!-- STUDIO_REGION_START:")
                || trimmed.starts_with("<!-- STUDIO_REGION_END:"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}
