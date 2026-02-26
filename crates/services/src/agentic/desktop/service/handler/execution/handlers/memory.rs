use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::RecordedMessage;
use ioi_scs::FrameType;
use ioi_types::codec;
use serde_json::json;

pub(crate) async fn handle_memory_search_tool(
    service: &DesktopAgentService,
    query: &str,
) -> ActionExecutionOutcome {
    if service.scs.is_none() {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=ToolUnavailable memory__search requires an SCS-backed memory store."
                    .to_string(),
            ),
        );
    }

    let trimmed = query.trim();
    if trimmed.is_empty() {
        return no_visual(
            false,
            None,
            Some(
                "ERROR_CLASS=TargetNotFound memory__search requires a non-empty query.".to_string(),
            ),
        );
    }

    let out = service.retrieve_context_hybrid(trimmed, None).await;
    let out = if out.trim().is_empty() {
        "No matching memories found.".to_string()
    } else {
        out
    };

    no_visual(true, Some(out), None)
}

pub(crate) async fn handle_memory_inspect_tool(
    service: &DesktopAgentService,
    frame_id: u64,
) -> ActionExecutionOutcome {
    let scs_mutex = match service.scs.as_ref() {
        Some(m) => m,
        None => {
            return no_visual(
                false,
                None,
                Some(
                    "ERROR_CLASS=ToolUnavailable memory__inspect requires an SCS-backed memory store."
                        .to_string(),
                ),
            );
        }
    };

    let frame_type = {
        let store = match scs_mutex.lock() {
            Ok(store) => store,
            Err(_) => {
                return no_visual(
                    false,
                    None,
                    Some("ERROR_CLASS=UnexpectedState SCS lock poisoned.".to_string()),
                );
            }
        };

        match store.toc.frames.get(frame_id as usize) {
            Some(frame) => frame.frame_type,
            None => {
                return no_visual(
                    false,
                    None,
                    Some(format!(
                        "ERROR_CLASS=TargetNotFound Frame {} not found in memory store.",
                        frame_id
                    )),
                );
            }
        }
    };

    match frame_type {
        FrameType::Observation => match service.inspect_frame(frame_id).await {
            Ok(desc) => no_visual(true, Some(desc), None),
            Err(e) => no_visual(
                false,
                None,
                Some(format!(
                    "ERROR_CLASS=UnexpectedState memory__inspect failed: {}",
                    e
                )),
            ),
        },
        FrameType::Thought | FrameType::Action => {
            let payload = {
                let store = match scs_mutex.lock() {
                    Ok(store) => store,
                    Err(_) => {
                        return no_visual(
                            false,
                            None,
                            Some("ERROR_CLASS=UnexpectedState SCS lock poisoned.".to_string()),
                        );
                    }
                };

                match store.read_frame_payload(frame_id) {
                    Ok(payload) => payload,
                    Err(e) => {
                        return no_visual(
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=UnexpectedState Failed to read frame payload: {}",
                                e
                            )),
                        );
                    }
                }
            };

            match codec::from_bytes_canonical::<RecordedMessage>(&payload) {
                Ok(recorded) => {
                    let content = if recorded.scrubbed_for_model.is_empty() {
                        recorded.scrubbed_for_scs
                    } else {
                        recorded.scrubbed_for_model
                    };
                    let out = json!({
                        "frame_id": frame_id,
                        "frame_type": format!("{:?}", frame_type),
                        "role": recorded.role,
                        "timestamp_ms": recorded.timestamp_ms,
                        "content": content,
                    })
                    .to_string();
                    no_visual(true, Some(out), None)
                }
                Err(_) => no_visual(
                    true,
                    Some(format!(
                        "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Non-Recorded Payload>\"}}",
                        frame_id, frame_type
                    )),
                    None,
                ),
            }
        }
        _ => no_visual(
            true,
            Some(format!(
                "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Unsupported Frame Type>\"}}",
                frame_id, frame_type
            )),
            None,
        ),
    }
}
