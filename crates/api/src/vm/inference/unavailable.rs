use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{ChatRuntimeProvenance, ChatRuntimeProvenanceKind};
use ioi_types::error::VmError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UnavailableInferenceRuntime {
    message: String,
    provenance: ChatRuntimeProvenance,
}

impl UnavailableInferenceRuntime {
    pub fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            provenance: ChatRuntimeProvenance {
                kind: ChatRuntimeProvenanceKind::InferenceUnavailable,
                label: "inference unavailable".to_string(),
                model: None,
                endpoint: None,
            },
            message,
        }
    }

    fn error(&self) -> VmError {
        VmError::HostError(self.message.clone())
    }
}

#[async_trait]
impl InferenceRuntime for UnavailableInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Err(self.error())
    }

    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        Err(self.error())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Err(self.error())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Err(self.error())
    }

    fn chat_runtime_provenance(&self) -> ChatRuntimeProvenance {
        self.provenance.clone()
    }
}
