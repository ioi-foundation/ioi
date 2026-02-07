// Path: crates/api/src/vm/inference/mod.rs

use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use std::path::Path;
use tokio::sync::mpsc::Sender;

pub mod driver;
pub mod http_adapter;
pub mod mock;

pub use driver::{AcceleratorType, DeviceCapabilities, HardwareDriver, ModelHandle};
pub use http_adapter::HttpInferenceRuntime;

/// A runtime capable of executing deterministic AI inference.
#[async_trait]
pub trait InferenceRuntime: Send + Sync {
    /// Executes a model against an input context with specific generation options.
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError>;

    /// Executes inference, optionally streaming partial tokens to the provided channel.
    /// The default implementation delegates to `execute_inference` and ignores the channel.
    async fn execute_inference_streaming(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        _token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        self.execute_inference(model_hash, input_context, options).await
    }

    /// Generates a vector embedding for a given text input.
    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        // Default implementation returns an empty vector or error if not supported.
        Err(VmError::HostError(
            "Embedding not supported by this runtime".into(),
        ))
    }

    /// Pre-loads a model into memory/VRAM to reduce latency for subsequent calls.
    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError>;

    /// Offloads a model from memory.
    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError>;
}

// --- NEW: Safety Traits Moved from Validator to resolve circular dependency ---

/// Represents the output of a safety check by the local BitNet engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyVerdict {
    /// The content is safe to proceed.
    Safe,
    /// The content violates safety guidelines (e.g., jailbreak attempt, malicious intent).
    Unsafe(String),
    /// The content contains PII that must be scrubbed.
    ContainsPII,
}

/// Abstract interface for the local CPU-based inference engine (BitNet b1.58).
/// This engine is optimized for low-latency classification and scrubbing.
#[async_trait]
pub trait LocalSafetyModel: Send + Sync {
    /// Classifies the intent of a prompt or action payload.
    async fn classify_intent(&self, input: &str) -> anyhow::Result<SafetyVerdict>;

    /// Identifies spans of text that contain PII or secrets.
    /// Returns a list of (start_index, end_index, category).
    async fn detect_pii(&self, input: &str) -> anyhow::Result<Vec<(usize, usize, String)>>;
}

// [NEW] Strategy Pattern for Provider Logic (Internal to `api` crate but used in `http_adapter`)
// We define it here or in a separate file, but it's part of the `vm` module's internal structure.
// Since `http_adapter.rs` uses it, we don't necessarily need to export it publicly unless
// we want users to implement their own strategies. For now, keep it internal to `vm`.

// Note: The trait `ProviderStrategy` is defined inside `http_adapter.rs` to keep it private/internal.
// If we wanted it public, we would export it here.