// Path: crates/validator/src/standard/workload/drivers/verified_http.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::control::guardian_control_client::GuardianControlClient;
use ioi_ipc::control::SecureEgressRequest;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::EgressReceipt;
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::Mutex;
use tonic::transport::Channel;

use crate::common::guardian::{
    compute_secure_egress_request_hash, compute_secure_egress_transcript_root,
};

const DEFAULT_RECEIPT_REPLAY_CACHE_SIZE: usize = 1024;

#[derive(Debug)]
struct ReceiptReplayGuard {
    capacity: usize,
    state: Mutex<(HashSet<[u8; 32]>, VecDeque<[u8; 32]>)>,
}

impl ReceiptReplayGuard {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new((HashSet::new(), VecDeque::new())),
        }
    }

    fn observe(&self, replay_id: [u8; 32]) -> Result<(), VmError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| VmError::HostError("receipt replay guard lock poisoned".into()))?;
        if state.0.contains(&replay_id) {
            return Err(VmError::HostError(
                "Guardian receipt replay detected".into(),
            ));
        }
        state.0.insert(replay_id);
        state.1.push_back(replay_id);
        if state.1.len() > self.capacity {
            if let Some(evicted) = state.1.pop_front() {
                state.0.remove(&evicted);
            }
        }
        Ok(())
    }
}

fn receipt_replay_id(receipt: &EgressReceipt) -> Result<[u8; 32], VmError> {
    let receipt_bytes = codec::to_bytes_canonical(receipt)
        .map_err(|e| VmError::HostError(format!("Failed to encode guardian receipt: {e}")))?;
    ioi_crypto::algorithms::hash::sha256(&receipt_bytes)
        .map_err(|e| VmError::HostError(format!("Failed to hash guardian receipt: {e}")))
}

fn validate_guardian_receipt(
    method: &str,
    target_domain: &str,
    path: &str,
    request_body: &[u8],
    response_body: &[u8],
    receipt: &EgressReceipt,
    replay_guard: &ReceiptReplayGuard,
) -> Result<(), VmError> {
    let expected_response_hash = ioi_crypto::algorithms::hash::sha256(response_body)
        .map_err(|e| VmError::HostError(format!("Failed to hash guardian response: {e}")))?;
    if receipt.response_hash != expected_response_hash {
        return Err(VmError::HostError(
            "Guardian receipt response hash mismatch".into(),
        ));
    }

    let expected_server_name = target_domain.split(':').next().unwrap_or(target_domain);
    if receipt.server_name != expected_server_name {
        return Err(VmError::HostError(
            "Guardian receipt server name mismatch".into(),
        ));
    }

    let expected_request_hash =
        compute_secure_egress_request_hash(method, target_domain, path, request_body)
            .map_err(|e| VmError::HostError(format!("Failed to hash guardian request: {e}")))?;
    if receipt.request_hash != expected_request_hash {
        return Err(VmError::HostError(
            "Guardian receipt request hash mismatch".into(),
        ));
    }

    if receipt.peer_certificate_chain_hash == [0u8; 32]
        || receipt.peer_leaf_certificate_hash == [0u8; 32]
        || receipt.handshake_transcript_hash == [0u8; 32]
        || receipt.transcript_version != 1
    {
        return Err(VmError::HostError(
            "Guardian receipt is missing TLS transcript evidence".into(),
        ));
    }

    let expected_transcript_root = compute_secure_egress_transcript_root(
        receipt.request_hash,
        receipt.handshake_transcript_hash,
        receipt.request_transcript_hash,
        receipt.response_transcript_hash,
        receipt.peer_certificate_chain_hash,
        receipt.response_hash,
    )
    .map_err(|e| VmError::HostError(format!("Failed to hash TLS transcript root: {e}")))?;
    if receipt.transcript_root != expected_transcript_root {
        return Err(VmError::HostError(
            "Guardian receipt transcript root mismatch".into(),
        ));
    }

    replay_guard.observe(receipt_replay_id(receipt)?)?;
    Ok(())
}

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
    /// Replay guard for guardian receipt envelopes.
    receipt_replay_guard: ReceiptReplayGuard,
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
            receipt_replay_guard: ReceiptReplayGuard::new(DEFAULT_RECEIPT_REPLAY_CACHE_SIZE),
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
            body: request_body.clone(),
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
        let receipt: EgressReceipt = codec::from_bytes_canonical(&inner.receipt)
            .map_err(|e| VmError::HostError(format!("Invalid guardian receipt: {}", e)))?;
        validate_guardian_receipt(
            "POST",
            &self.get_provider_domain(),
            &self.get_provider_path(),
            &request_body,
            &data,
            &receipt,
            &self.receipt_replay_guard,
        )?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> EgressReceipt {
        let request_hash = [1u8; 32];
        let handshake = [2u8; 32];
        let request_tx = [3u8; 32];
        let response_tx = [4u8; 32];
        let chain_hash = [5u8; 32];
        let response_hash = [6u8; 32];
        EgressReceipt {
            request_hash,
            server_name: "localhost".into(),
            transcript_version: 1,
            transcript_root: compute_secure_egress_transcript_root(
                request_hash,
                handshake,
                request_tx,
                response_tx,
                chain_hash,
                response_hash,
            )
            .unwrap(),
            handshake_transcript_hash: handshake,
            request_transcript_hash: request_tx,
            response_transcript_hash: response_tx,
            peer_certificate_chain_hash: chain_hash,
            peer_leaf_certificate_hash: [7u8; 32],
            response_hash,
            policy_hash: [8u8; 32],
            guardian_certificate: None,
            log_checkpoint: None,
        }
    }

    #[test]
    fn guardian_receipt_rejects_transcript_mismatch() {
        let guard = ReceiptReplayGuard::new(8);
        let mut receipt = sample_receipt();
        let request_body = b"{}".to_vec();
        let response_body = b"ok".to_vec();
        receipt.request_hash = compute_secure_egress_request_hash(
            "POST",
            "localhost",
            "/v1/chat/completions",
            &request_body,
        )
        .unwrap();
        receipt.response_hash = ioi_crypto::algorithms::hash::sha256(&response_body).unwrap();
        receipt.transcript_root = compute_secure_egress_transcript_root(
            receipt.request_hash,
            receipt.handshake_transcript_hash,
            receipt.request_transcript_hash,
            receipt.response_transcript_hash,
            receipt.peer_certificate_chain_hash,
            receipt.response_hash,
        )
        .unwrap();
        receipt.transcript_root[0] ^= 0x11;
        let err = validate_guardian_receipt(
            "POST",
            "localhost",
            "/v1/chat/completions",
            &request_body,
            &response_body,
            &receipt,
            &guard,
        )
        .unwrap_err();
        assert!(err.to_string().contains("transcript root mismatch"));
    }

    #[test]
    fn guardian_receipt_rejects_replay() {
        let guard = ReceiptReplayGuard::new(8);
        let mut receipt = sample_receipt();
        let request_body = b"{}".to_vec();
        let response_body = b"ok".to_vec();
        receipt.request_hash = compute_secure_egress_request_hash(
            "POST",
            "localhost",
            "/v1/chat/completions",
            &request_body,
        )
        .unwrap();
        receipt.response_hash = ioi_crypto::algorithms::hash::sha256(&response_body).unwrap();
        receipt.transcript_root = compute_secure_egress_transcript_root(
            receipt.request_hash,
            receipt.handshake_transcript_hash,
            receipt.request_transcript_hash,
            receipt.response_transcript_hash,
            receipt.peer_certificate_chain_hash,
            receipt.response_hash,
        )
        .unwrap();

        validate_guardian_receipt(
            "POST",
            "localhost",
            "/v1/chat/completions",
            &request_body,
            &response_body,
            &receipt,
            &guard,
        )
        .unwrap();
        let err = validate_guardian_receipt(
            "POST",
            "localhost",
            "/v1/chat/completions",
            &request_body,
            &response_body,
            &receipt,
            &guard,
        )
        .unwrap_err();
        assert!(err.to_string().contains("replay"));
    }
}
