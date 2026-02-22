use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::RecordedMessage;
use ioi_types::codec;
use ioi_types::error::TransactionError;

/// Performs the "Refactoring Notes" process:
/// 1. Reads raw thoughts from the current epoch.
/// 2. Summarizes them into an Overlay.
/// 3. Rotates the epoch (shredding keys for raw thoughts).
/// 4. Prunes the old epoch key explicitly.
pub async fn perform_cognitive_compaction(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let scs_mutex = service
        .scs
        .as_ref()
        .ok_or(TransactionError::Invalid("SCS required".into()))?;

    let raw_thoughts: Vec<String> = {
        let store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;
        let current_epoch = store.current_epoch;

        if let Some(frame_ids) = store.session_index.get(&session_id) {
            frame_ids
                .iter()
                .filter_map(|&fid| {
                    let frame = store.toc.frames.get(fid as usize)?;
                    if frame.frame_type == ioi_scs::FrameType::Thought
                        && frame.epoch_id == current_epoch
                    {
                        if let Ok(bytes) = store.read_frame_payload(fid) {
                            if let Ok(message) =
                                codec::from_bytes_canonical::<RecordedMessage>(&bytes)
                            {
                                let content = if message.scrubbed_for_scs.is_empty() {
                                    message.scrubbed_for_model
                                } else {
                                    message.scrubbed_for_scs
                                };
                                return Some(format!("{}: {}", message.role, content));
                            }
                        }
                    }
                    None
                })
                .collect()
        } else {
            vec![]
        }
    };

    if raw_thoughts.is_empty() {
        return Ok(());
    }

    log::info!(
        "Cognitive Compaction: Summarizing {} thoughts...",
        raw_thoughts.len()
    );

    let prompt = format!(
        "SYSTEM: Summarize the following stream of consciousness into a concise set of facts, decisions, and skills learned.\n\
         Discard transient errors, retries, and verbose logs. Keep only the final working logic and key outcomes.\n\n\
         RAW LOGS:\n{:?}",
        raw_thoughts
    );

    let options = ioi_types::app::agentic::InferenceOptions {
        temperature: 0.0,
        ..Default::default()
    };

    let summary_bytes = service
        .reasoning_inference
        .execute_inference(
            [0u8; 32],
            &service
                .prepare_cloud_inference_input(
                    Some(session_id),
                    "desktop_agent",
                    "model_hash:0000000000000000000000000000000000000000000000000000000000000000",
                    prompt.as_bytes(),
                )
                .await?,
            options,
        )
        .await
        .map_err(|e| TransactionError::Invalid(format!("Compaction inference failed: {}", e)))?;

    {
        let mut store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;

        let _overlay_id = store
            .append_frame(
                ioi_scs::FrameType::Overlay,
                &summary_bytes,
                0,
                [0u8; 32],
                session_id,
                ioi_scs::RetentionClass::Archival,
            )
            .map_err(|e: anyhow::Error| TransactionError::Invalid(e.to_string()))?;

        let _manifest = store
            .rotate_epoch()
            .map_err(|e: anyhow::Error| TransactionError::Invalid(e.to_string()))?;

        let old_epoch = store.current_epoch.saturating_sub(1);
        store.prune_epoch(old_epoch);
    }

    log::info!(
        "Cognitive Compaction Complete: Epoch rotated, raw thoughts shredded, Overlay preserved."
    );
    Ok(())
}
