// Path: crates/validator/src/standard/workload/drivers/verified_http.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::control::guardian_control_client::GuardianControlClient;
use ioi_ipc::control::SecureEgressRequest;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    canonical_collapse_hash_for_sealed_effect, sealed_finality_proof_observer_binding,
    verify_seal_object, EgressReceipt, FinalityTier,
};
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

fn encode_finality_tier(tier: FinalityTier) -> u32 {
    match tier {
        FinalityTier::BaseFinal => 0,
        FinalityTier::SealedFinal => 1,
    }
}

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
    expected_finality_tier: FinalityTier,
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

    if receipt.finality_tier != expected_finality_tier {
        return Err(VmError::HostError(
            "Guardian receipt finality tier mismatch".into(),
        ));
    }
    if matches!(expected_finality_tier, FinalityTier::SealedFinal) {
        let Some(seal_object) = receipt.seal_object.as_ref() else {
            return Err(VmError::HostError(
                "Guardian receipt is missing a proof-carrying seal object".into(),
            ));
        };
        let Some(sealed_finality_proof) = receipt.sealed_finality_proof.as_ref() else {
            return Err(VmError::HostError(
                "Guardian receipt is missing a sealed finality proof".into(),
            ));
        };
        let Some(canonical_collapse_object) = receipt.canonical_collapse_object.as_ref() else {
            return Err(VmError::HostError(
                "Guardian receipt is missing a canonical collapse object".into(),
            ));
        };
        verify_seal_object(seal_object)
            .map_err(|e| VmError::HostError(format!("Guardian seal object is invalid: {e}")))?;
        if seal_object.intent.request_hash != receipt.request_hash {
            return Err(VmError::HostError(
                "Guardian seal object request hash mismatch".into(),
            ));
        }
        if seal_object.intent.target != target_domain
            || seal_object.intent.action != method
            || seal_object.intent.path != path
        {
            return Err(VmError::HostError(
                "Guardian seal object target/action/path mismatch".into(),
            ));
        }
        if seal_object.intent.policy_hash != receipt.policy_hash {
            return Err(VmError::HostError(
                "Guardian seal object policy hash mismatch".into(),
            ));
        }
        let observer_binding = sealed_finality_proof_observer_binding(sealed_finality_proof)
            .map_err(|e| {
                VmError::HostError(format!(
                    "Guardian sealed finality proof observer binding is invalid: {e}"
                ))
            })?;
        if seal_object.epoch != sealed_finality_proof.epoch
            || seal_object.intent.guardian_manifest_hash
                != sealed_finality_proof.guardian_manifest_hash
            || seal_object.intent.guardian_decision_hash
                != sealed_finality_proof.guardian_decision_hash
            || seal_object.public_inputs.guardian_counter != sealed_finality_proof.guardian_counter
            || seal_object.public_inputs.guardian_trace_hash
                != sealed_finality_proof.guardian_trace_hash
            || seal_object.public_inputs.guardian_measurement_root
                != sealed_finality_proof.guardian_measurement_root
            || seal_object.public_inputs.observer_transcripts_root
                != observer_binding.transcripts_root
            || seal_object.public_inputs.observer_challenges_root
                != observer_binding.challenges_root
            || seal_object.public_inputs.observer_resolution_hash
                != observer_binding.resolution_hash
        {
            return Err(VmError::HostError(
                "Guardian seal object does not match the sealed finality proof".into(),
            ));
        }
        let expected_collapse_hash = canonical_collapse_hash_for_sealed_effect(
            canonical_collapse_object,
            sealed_finality_proof,
        )
        .map_err(|e| {
            VmError::HostError(format!(
                "Guardian canonical collapse object is invalid: {e}"
            ))
        })?;
        if seal_object.public_inputs.canonical_collapse_hash != expected_collapse_hash {
            return Err(VmError::HostError(
                "Guardian seal object does not match the canonical collapse object".into(),
            ));
        }
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
        let required_finality_tier = options.required_finality_tier;
        let sealed_finality_proof = options
            .sealed_finality_proof
            .as_ref()
            .map(codec::to_bytes_canonical)
            .transpose()
            .map_err(|e| {
                VmError::HostError(format!("Failed to encode sealed finality proof: {e}"))
            })?
            .unwrap_or_default();
        let canonical_collapse_object = options
            .canonical_collapse_object
            .as_ref()
            .map(codec::to_bytes_canonical)
            .transpose()
            .map_err(|e| {
                VmError::HostError(format!("Failed to encode canonical collapse object: {e}"))
            })?
            .unwrap_or_default();
        if matches!(required_finality_tier, FinalityTier::SealedFinal)
            && (sealed_finality_proof.is_empty() || canonical_collapse_object.is_empty())
        {
            return Err(VmError::HostError(
                "SealedFinal egress requires both a sealed finality proof and canonical collapse object".into(),
            ));
        }

        let req = SecureEgressRequest {
            domain: self.get_provider_domain(),
            path: self.get_provider_path(),
            method: "POST".into(),
            body: request_body.clone(),
            secret_id: self.key_ref.clone(),
            json_patch_path: String::new(),
            required_finality_tier: encode_finality_tier(required_finality_tier),
            sealed_finality_proof,
            seal_object: Vec::new(),
            canonical_collapse_object,
        };

        let resp = client
            .secure_egress(req)
            .await
            .map_err(|e| VmError::HostError(format!("Guardian Egress Failed: {}", e)))?;

        // 3. Unpack Response
        let inner = resp.into_inner();
        if inner.finality_tier != encode_finality_tier(required_finality_tier) {
            return Err(VmError::HostError(
                "Guardian returned an unexpected finality tier".into(),
            ));
        }
        let data = inner.body;
        let receipt: EgressReceipt = codec::from_bytes_canonical(&inner.receipt)
            .map_err(|e| VmError::HostError(format!("Invalid guardian receipt: {}", e)))?;
        validate_guardian_receipt(
            "POST",
            &self.get_provider_domain(),
            &self.get_provider_path(),
            &request_body,
            &data,
            required_finality_tier,
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
#[path = "verified_http/tests.rs"]
mod tests;
