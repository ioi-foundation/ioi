use crate::models::{AppState, VoiceInputTranscriptionRequest, VoiceInputTranscriptionResult};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ioi_api::vm::inference::{InferenceRuntime, TranscriptionRequest};
use std::sync::{Arc, Mutex};
use tauri::State;

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn decode_audio_base64(audio_base64: &str) -> Result<Vec<u8>, String> {
    let trimmed = audio_base64.trim();
    if trimmed.is_empty() {
        return Err("Voice input requires a non-empty audio clip.".to_string());
    }

    BASE64_STANDARD
        .decode(trimmed)
        .map_err(|error| format!("Failed to decode voice input audio: {}", error))
        .and_then(|bytes| {
            if bytes.is_empty() {
                Err("Voice input requires a non-empty audio clip.".to_string())
            } else {
                Ok(bytes)
            }
        })
}

async fn transcribe_voice_input_with_runtime(
    inference: Arc<dyn InferenceRuntime>,
    request: VoiceInputTranscriptionRequest,
) -> Result<VoiceInputTranscriptionResult, String> {
    let audio_bytes = decode_audio_base64(&request.audio_base64)?;
    let mime_type = request
        .mime_type
        .trim()
        .to_string()
        .chars()
        .collect::<String>();
    let mime_type = if mime_type.trim().is_empty() {
        "audio/webm".to_string()
    } else {
        mime_type
    };

    let result = inference
        .transcribe_audio(TranscriptionRequest {
            audio_bytes,
            mime_type: mime_type.clone(),
            language: normalize_optional_text(request.language),
            model_id: None,
        })
        .await
        .map_err(|error| format!("Voice transcription failed: {}", error))?;

    Ok(VoiceInputTranscriptionResult {
        text: result.text,
        mime_type,
        file_name: normalize_optional_text(request.file_name),
        language: result.language,
        model_id: result.model_id,
    })
}

#[tauri::command]
pub async fn transcribe_voice_input(
    state: State<'_, Mutex<AppState>>,
    request: VoiceInputTranscriptionRequest,
) -> Result<VoiceInputTranscriptionResult, String> {
    let inference = state
        .lock()
        .map_err(|_| "Failed to lock app state.".to_string())?
        .inference_runtime
        .clone()
        .ok_or_else(|| "Inference runtime unavailable for voice transcription.".to_string())?;
    transcribe_voice_input_with_runtime(inference, request).await
}

#[cfg(test)]
#[path = "voice/tests.rs"]
mod tests;
