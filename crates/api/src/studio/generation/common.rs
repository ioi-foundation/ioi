use super::*;

pub(super) fn studio_generation_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StudioCandidateMaterializationError {
    pub(crate) message: String,
    pub(crate) raw_output_preview: Option<String>,
}

impl From<String> for StudioCandidateMaterializationError {
    fn from(message: String) -> Self {
        Self {
            message,
            raw_output_preview: None,
        }
    }
}

pub(super) fn truncate_candidate_failure_preview(raw: &str, max_chars: usize) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut preview = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        preview.push_str("...");
    }
    Some(preview)
}

pub(super) fn live_token_stream_preview_text(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let chars = trimmed.chars().collect::<Vec<_>>();
    if chars.len() <= max_chars {
        return trimmed.to_string();
    }

    let tail = chars[chars.len().saturating_sub(max_chars)..]
        .iter()
        .collect::<String>();
    format!("[showing latest streamed output]\n{tail}")
}

pub(super) fn trace_html_contract_state(
    stage: &str,
    request: &StudioOutcomeArtifactRequest,
    candidate_id: &str,
    payload: &StudioGeneratedArtifactPayload,
) {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    }) else {
        return;
    };

    let lower = primary_html.body.to_ascii_lowercase();
    studio_generation_trace(format!(
        "{stage} id={} rollover_marks={} detail_regions={} has_rollover_behavior={} unfocusable_rollover={} rollover_chip_rail={} repair_shims={}",
        candidate_id,
        count_html_rollover_detail_marks(&lower),
        count_populated_html_detail_regions(&lower),
        html_contains_rollover_detail_behavior(&lower),
        html_has_unfocusable_rollover_marks(&lower),
        lower.contains("data-studio-rollover-chip-rail=\"true\""),
        count_html_repair_shim_markers(&lower),
    ));
}

pub(super) fn serialize_materialization_prompt_json<T: serde::Serialize>(
    value: &T,
    label: &str,
    compact: bool,
) -> Result<String, String> {
    if compact {
        serde_json::to_string(value)
            .map_err(|error| format!("Failed to serialize {label}: {error}"))
    } else {
        serde_json::to_string_pretty(value)
            .map_err(|error| format!("Failed to serialize {label}: {error}"))
    }
}

pub(super) fn truncate_materialization_focus_text(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut clipped = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        clipped.push_str("...");
    }
    clipped
}
