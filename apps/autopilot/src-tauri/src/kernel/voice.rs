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
mod tests {
    use super::{decode_audio_base64, transcribe_voice_input_with_runtime};
    use crate::models::VoiceInputTranscriptionRequest;
    use async_trait::async_trait;
    use ioi_api::vm::inference::{InferenceRuntime, TranscriptionRequest, TranscriptionResult};
    use ioi_types::app::agentic::InferenceOptions;
    use ioi_types::app::{StudioRuntimeProvenance, StudioRuntimeProvenanceKind};
    use ioi_types::error::VmError;
    use std::path::Path;
    use std::sync::Arc;

    struct VoiceTestRuntime;

    #[async_trait]
    impl InferenceRuntime for VoiceTestRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("not used".to_string()))
        }

        async fn transcribe_audio(
            &self,
            request: TranscriptionRequest,
        ) -> Result<TranscriptionResult, VmError> {
            Ok(TranscriptionResult {
                text: format!("transcribed {} bytes", request.audio_bytes.len()),
                language: request.language.or_else(|| Some("en".to_string())),
                model_id: Some("voice-test-runtime".to_string()),
            })
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }

        fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
            StudioRuntimeProvenance {
                kind: StudioRuntimeProvenanceKind::FixtureRuntime,
                label: "voice-test-runtime".to_string(),
                model: Some("voice-test-runtime".to_string()),
                endpoint: None,
            }
        }
    }

    #[test]
    fn decode_audio_base64_rejects_empty_input() {
        let error = decode_audio_base64("").expect_err("empty audio should fail");
        assert!(error.contains("non-empty audio clip"));
    }

    #[tokio::test]
    async fn transcribe_voice_input_uses_runtime_result() {
        let result = transcribe_voice_input_with_runtime(
            Arc::new(VoiceTestRuntime),
            VoiceInputTranscriptionRequest {
                audio_base64: "aGVsbG8=".to_string(),
                mime_type: "audio/wav".to_string(),
                file_name: Some("sample.wav".to_string()),
                language: Some("en".to_string()),
            },
        )
        .await
        .expect("voice transcription should succeed");

        assert_eq!(result.text, "transcribed 5 bytes");
        assert_eq!(result.mime_type, "audio/wav");
        assert_eq!(result.file_name.as_deref(), Some("sample.wav"));
        assert_eq!(result.language.as_deref(), Some("en"));
        assert_eq!(result.model_id.as_deref(), Some("voice-test-runtime"));
    }
}
