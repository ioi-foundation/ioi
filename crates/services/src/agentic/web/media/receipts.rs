use super::*;

pub(crate) fn media_tool_receipt_path(tool_home: &Path) -> PathBuf {
    tool_home
        .join(MEDIA_RECEIPT_DIR_NAME)
        .join(MEDIA_RECEIPT_FILE_NAME)
}

pub(crate) fn media_provider_candidate_receipt(
    provider_id: &str,
    request_url: &str,
    selected: bool,
    success: bool,
    challenge_reason: Option<String>,
) -> MediaTranscriptProviderCandidate {
    media_provider_candidate_receipt_with_modality(
        provider_id,
        request_url,
        "transcript",
        selected,
        success,
        challenge_reason,
    )
}

pub(super) fn media_provider_candidate_receipt_with_modality(
    provider_id: &str,
    request_url: &str,
    modality: &str,
    selected: bool,
    success: bool,
    challenge_reason: Option<String>,
) -> MediaProviderCandidate {
    MediaProviderCandidate {
        provider_id: provider_id.to_string(),
        modality: Some(modality.to_string()),
        source_count: if success { 1 } else { 0 },
        selected,
        success,
        execution_attempted: None,
        execution_satisfied: None,
        execution_failure_reason: None,
        request_url: Some(request_url.to_string()),
        challenge_reason,
        affordances: vec![WebRetrievalAffordance::DetailDocument],
    }
}

pub(super) fn write_run_receipt(
    tool_home: &Path,
    receipt: &MediaTranscriptRunReceipt,
) -> Result<()> {
    let receipt_path = media_tool_receipt_path(tool_home);
    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(receipt).context("serialize media transcript receipt")?,
    )
    .with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to write media receipt {}",
            receipt_path.display()
        )
    })
}

pub(super) fn write_multimodal_run_receipt(
    tool_home: &Path,
    receipt: &MediaMultimodalRunReceipt,
) -> Result<()> {
    let receipt_path = media_tool_receipt_path(tool_home);
    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(receipt).context("serialize media multimodal receipt")?,
    )
    .with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to write media receipt {}",
            receipt_path.display()
        )
    })
}
