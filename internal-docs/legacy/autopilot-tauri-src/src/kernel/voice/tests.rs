use super::{decode_audio_base64, transcribe_voice_input_with_runtime};
use crate::models::VoiceInputTranscriptionRequest;
use async_trait::async_trait;
use ioi_api::vm::inference::{InferenceRuntime, TranscriptionRequest, TranscriptionResult};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{ChatRuntimeProvenance, ChatRuntimeProvenanceKind};
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

    fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
        ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::FixtureRuntime,
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
