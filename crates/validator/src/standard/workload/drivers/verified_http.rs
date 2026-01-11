// Path: crates/validator/src/standard/workload/drivers/verified_http.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::{InferenceRuntime, InferenceOptions};
use ioi_ipc::control::guardian_control_client::GuardianControlClient; 
use ioi_ipc::control::SecureEgressRequest;
use ioi_types::error::VmError;
use std::path::Path;
use tonic::transport::Channel;
use serde_json::json;

/// A runtime driver that routes inference requests through the Guardian's secure egress.
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
    pub fn new(
        channel: Channel,
        provider: String,
        key_ref: String,
        model_name: String,
    ) -> Self {
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
            // Add other providers here
            _ => "unknown".to_string(),
        }
    }

    fn get_provider_path(&self) -> String {
        match self.provider.as_str() {
            "openai" => "/v1/chat/completions".to_string(),
            "anthropic" => "/v1/messages".to_string(),
             // Add other providers here
            _ => "/".to_string(),
        }
    }

    fn build_openai_body(&self, input: &[u8], options: &InferenceOptions) -> Result<Vec<u8>, VmError> {
        let prompt_str = String::from_utf8(input.to_vec())
            .map_err(|e| VmError::InvalidBytecode(format!("Input context must be UTF-8: {}", e)))?;
        
        // Basic mapping for MVP
        let body = json!({
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt_str}],
            "temperature": options.temperature,
            // "tools": ... (map tools if present)
        });
        
        Ok(serde_json::to_vec(&body).map_err(|e| VmError::HostError(e.to_string()))?)
    }

    fn build_anthropic_body(&self, input: &[u8], options: &InferenceOptions) -> Result<Vec<u8>, VmError> {
        let prompt_str = String::from_utf8(input.to_vec())
             .map_err(|e| VmError::InvalidBytecode(format!("Input context must be UTF-8: {}", e)))?;

        let body = json!({
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt_str}],
            "max_tokens": 1024, 
            "temperature": options.temperature,
        });

        Ok(serde_json::to_vec(&body).map_err(|e| VmError::HostError(e.to_string()))?)
    }

    fn parse_provider_response(&self, data: &[u8]) -> Result<Vec<u8>, VmError> {
        let json: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| VmError::HostError(format!("Failed to parse response JSON: {}", e)))?;

        match self.provider.as_str() {
            "openai" => {
                let content = json["choices"][0]["message"]["content"]
                    .as_str()
                    .ok_or_else(|| VmError::HostError("OpenAI response missing content".into()))?;
                Ok(content.as_bytes().to_vec())
            },
             "anthropic" => {
                let content = json["content"][0]["text"]
                    .as_str()
                    .ok_or_else(|| VmError::HostError("Anthropic response missing content".into()))?;
                Ok(content.as_bytes().to_vec())
             },
            _ => Err(VmError::HostError("Unknown provider response format".into())),
        }
    }
}

#[async_trait]
impl InferenceRuntime for VerifiedHttpRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32], 
        input_context: &[u8], 
        options: InferenceOptions
    ) -> Result<Vec<u8>, VmError> {
        
        // 1. Transform input to Provider-Specific JSON (Stateless)
        // The driver formats the body but does NOT add headers/keys.
        let request_body = match self.provider.as_str() {
            "openai" => self.build_openai_body(input_context, &options)?,
            "anthropic" => self.build_anthropic_body(input_context, &options)?,
            _ => return Err(VmError::Config("Unknown provider".into())),
        };

        // 2. Delegate to Guardian via IPC
        // The Workload sends the body and the ID of the key to use.
        // NOTE: self.guardian_client is a Clone of the client, so mutability is handled by the underlying channel.
        let mut client = self.guardian_client.clone();
        
        let req = SecureEgressRequest {
            domain: self.get_provider_domain(),
            path: self.get_provider_path(),
            method: "POST".into(),
            body: request_body,
            secret_id: self.key_ref.clone(), 
        };

        let resp = client.secure_egress(req).await
            .map_err(|e| VmError::HostError(format!("Guardian Egress Failed: {}", e)))?;

        // 3. Unpack Response & Proof
        let inner = resp.into_inner();
        let data = inner.body;
        // In a full implementation, we would verify the guardian_signature here if the Workload distrusts the channel.
        
        // 4. Parse and return text
        self.parse_provider_response(&data)
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        // Stateless HTTP runtime, no loading needed
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}