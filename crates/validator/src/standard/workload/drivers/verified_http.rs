// Path: crates/validator/src/standard/workload/drivers/verified_http.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::control::guardian_control_client::GuardianControlClient;
use ioi_ipc::control::SecureEgressRequest;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use tonic::transport::Channel;

/// A runtime driver that routes inference requests through the Guardian's secure egress.
///
/// This implementation fulfills the "Bring Your Own Key" (BYO-Key) model where the
/// Workload container never sees the raw API credentials. Instead, it delegates
/// the network call to the Guardian, which injects the key and returns a signed
/// attestation of the traffic.
pub struct VerifiedHttpRuntime {
    /// gRPC client to the local Guardian container.
    guardian_client: GuardianControlClient<Channel>,
    /// The provider identifier (e.g., "openai", "anthropic").
    provider: String,
    /// The reference ID of the API key stored in the Guardian (e.g., "openai_primary").
    key_ref: String,
    /// The model name (e.g., "gpt-4").
    model_name: String,
}

impl VerifiedHttpRuntime {
    /// Creates a new `VerifiedHttpRuntime`.
    ///
    /// # Arguments
    ///
    /// * `channel` - The secure gRPC channel to the Guardian.
    /// * `provider` - The name of the AI provider (e.g. "openai").
    /// * `key_ref` - The reference ID of the API key stored in the Guardian's secure store.
    /// * `model_name` - The specific model to request (e.g. "gpt-4-turbo").
    pub fn new(channel: Channel, provider: String, key_ref: String, model_name: String) -> Self {
        Self {
            guardian_client: GuardianControlClient::new(channel),
            provider,
            key_ref,
            model_name,
        }
    }

    fn get_provider_domain(&self) -> String {
        match self.provider.as_str() {
            "openai" => "api.openai.com".to_string(),
            "anthropic" => "api.anthropic.com".to_string(),
            _ => "unknown".to_string(),
        }
    }

    fn get_provider_path(&self) -> String {
        match self.provider.as_str() {
            "openai" => "/v1/chat/completions".to_string(),
            "anthropic" => "/v1/messages".to_string(),
            _ => "/".to_string(),
        }
    }

    fn build_openai_body(
        &self,
        input: &[u8],
        options: &InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt_str = String::from_utf8(input.to_vec())
            .map_err(|e| VmError::InvalidBytecode(format!("Input context must be UTF-8: {}", e)))?;

        // Basic mapping for OpenAI Chat Completion API
        let body = json!({
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt_str}],
            "temperature": options.temperature,
        });

        serde_json::to_vec(&body).map_err(|e| VmError::HostError(e.to_string()))
    }

    fn build_anthropic_body(
        &self,
        input: &[u8],
        options: &InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt_str = String::from_utf8(input.to_vec())
            .map_err(|e| VmError::InvalidBytecode(format!("Input context must be UTF-8: {}", e)))?;

        // Basic mapping for Anthropic Messages API
        let body = json!({
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt_str}],
            "max_tokens": 1024,
            "temperature": options.temperature,
        });

        serde_json::to_vec(&body).map_err(|e| VmError::HostError(e.to_string()))
    }

    fn parse_provider_response(&self, data: &[u8]) -> Result<Vec<u8>, VmError> {
        let json: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| VmError::HostError(format!("Failed to parse response JSON: {}", e)))?;

        match self.provider.as_str() {
            "openai" => {
                let content = json["choices"][0]["message"]["content"].as_str();

                if let Some(c) = content {
                    Ok(c.as_bytes().to_vec())
                } else {
                    // [FIX] Log the full error response from OpenAI for debugging
                    let error_msg = format!("OpenAI response missing content. Payload: {}", json);
                    log::error!("{}", error_msg);
                    Err(VmError::HostError(error_msg))
                }
            }
            "anthropic" => {
                let content = json["content"][0]["text"].as_str().ok_or_else(|| {
                    VmError::HostError("Anthropic response missing content".into())
                })?;
                Ok(content.as_bytes().to_vec())
            }
            _ => Err(VmError::HostError(
                "Unknown provider response format".into(),
            )),
        }
    }
}

#[async_trait]
impl InferenceRuntime for VerifiedHttpRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // 1. Transform input to Provider-Specific JSON (Stateless)
        let request_body = match self.provider.as_str() {
            "openai" => self.build_openai_body(input_context, &options)?,
            "anthropic" => self.build_anthropic_body(input_context, &options)?,
            _ => return Err(VmError::Initialization("Unknown provider".into())),
        };

        // 2. Delegate to Guardian via IPC Secure Egress
        let mut client = self.guardian_client.clone();

        // [FIX] Initialize new field json_patch_path
        let req = SecureEgressRequest {
            domain: self.get_provider_domain(),
            path: self.get_provider_path(),
            method: "POST".into(),
            body: request_body,
            secret_id: self.key_ref.clone(),
            json_patch_path: String::new(),
        };

        let resp = client
            .secure_egress(req)
            .await
            .map_err(|e| VmError::HostError(format!("Guardian Egress Failed: {}", e)))?;

        // 3. Unpack Response
        let inner = resp.into_inner();
        let data = inner.body;

        // 4. Parse and return text
        self.parse_provider_response(&data)
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        // Stateless HTTP runtime, no local loading needed
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}
