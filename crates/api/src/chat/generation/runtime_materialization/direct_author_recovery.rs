
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChatDirectAuthorRecoveryMode {
    Suffix,
    FullDocument,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ChatDirectAuthorRecoveryPayload {
    mode: ChatDirectAuthorRecoveryMode,
    content: String,
}

fn parse_chat_direct_author_recovery_payload(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Result<ChatDirectAuthorRecoveryPayload, String> {
    let parse_json =
        |candidate: &str| -> Result<ChatDirectAuthorRecoveryPayload, serde_json::Error> {
            serde_json::from_str(candidate)
        };

    let payload = match parse_json(raw).or_else(|_| {
        let extracted = super::extract_first_json_object(raw)
            .ok_or_else(|| "Chat direct-author recovery output missing JSON payload".to_string())?;
        parse_json(&extracted).map_err(|error| error.to_string())
    }) {
        Ok(payload) => payload,
        Err(error) => coerce_direct_author_recovery_payload_from_raw_output(request, raw)
            .ok_or_else(|| {
                format!("Failed to parse Chat direct-author recovery payload: {error}")
            })?,
    };

    if payload.content.trim().is_empty() {
        return Err("Chat direct-author recovery payload content was empty".to_string());
    }

    Ok(payload)
}

fn coerce_direct_author_recovery_payload_from_raw_output(
    request: &ChatOutcomeArtifactRequest,
    raw: &str,
) -> Option<ChatDirectAuthorRecoveryPayload> {
    let raw_document = strip_single_markdown_code_fence(raw).unwrap_or(raw).trim();
    if raw_document.is_empty() {
        return None;
    }

    if !direct_author_uses_raw_document(request) {
        return None;
    }

    let content = if let Some(extracted_document) =
        extract_authored_document_body(raw_document, request.renderer)
    {
        if request.renderer == ChatRendererKind::HtmlIframe {
            direct_author_renderable_html_prefix(request, &extracted_document)
                .unwrap_or(extracted_document)
        } else {
            extracted_document
        }
    } else {
        raw_document.to_string()
    };

    let mode = if content.len() != raw_document.len()
        || matches!(
            request.renderer,
            ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed
        )
        || matches!(request.renderer, ChatRendererKind::HtmlIframe)
            && content.to_ascii_lowercase().contains("<html")
        || matches!(request.renderer, ChatRendererKind::Svg)
            && content.to_ascii_lowercase().contains("<svg")
    {
        ChatDirectAuthorRecoveryMode::FullDocument
    } else {
        ChatDirectAuthorRecoveryMode::Suffix
    };

    if mode == ChatDirectAuthorRecoveryMode::FullDocument && content.len() != raw_document.len() {
        chat_generation_trace(format!(
            "artifact_generation:direct_author_recovery:extracted_full_document renderer={:?} raw_bytes={} extracted_bytes={}",
            request.renderer,
            raw_document.len(),
            content.len()
        ));
    }

    Some(ChatDirectAuthorRecoveryPayload { mode, content })
}

fn strip_single_markdown_code_fence(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("```") {
        return None;
    }

    let first_newline = trimmed.find('\n')?;
    let remainder = &trimmed[first_newline + 1..];
    let closing_fence = remainder.rfind("```")?;
    let suffix = remainder[closing_fence + 3..].trim();
    if !suffix.is_empty() {
        return None;
    }

    Some(remainder[..closing_fence].trim())
}

fn apply_direct_author_recovery_payload(
    existing_document: &str,
    payload: &ChatDirectAuthorRecoveryPayload,
) -> String {
    match payload.mode {
        ChatDirectAuthorRecoveryMode::Suffix => {
            merge_direct_author_document(existing_document, &payload.content)
        }
        ChatDirectAuthorRecoveryMode::FullDocument => payload.content.clone(),
    }
}
