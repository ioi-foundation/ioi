use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct VoiceInputTranscriptionRequest {
    pub audio_base64: String,
    pub mime_type: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct VoiceInputTranscriptionResult {
    pub text: String,
    pub mime_type: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
}
