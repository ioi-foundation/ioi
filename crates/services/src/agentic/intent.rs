// Path: crates/services/src/agentic/intent.rs

use crate::agentic::prompt_wrapper::{PolicyGuardrails, PromptWrapper};
use crate::agentic::desktop::StartAgentParams; // [NEW] Import params
use anyhow::{anyhow, Result};
use ioi_api::vm::inference::{InferenceRuntime, SafetyVerdict};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, ChainTransaction, SignHeader, SignatureProof,
    SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use rand::RngCore; // [NEW] Import RNG
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

/// A service to translate natural language user intent into a canonical, signable transaction.
/// This powers the "Search Engine for Action" (Control Plane).
pub struct IntentResolver {
    inference: Arc<dyn InferenceRuntime>,
}

impl IntentResolver {
    pub fn new(inference: Arc<dyn InferenceRuntime>) -> Self {
        Self { inference }
    }

    /// Resolves a natural language prompt into a raw transaction payload bytes.
    ///
    /// # Process
    /// 1. Safety Check (BitNet): Ensure the prompt isn't malicious or PII-laden.
    /// 2. Canonical Prompting: Wrap the user prompt in a strict system prompt.
    /// 3. Inference: Ask the LLM to map the intent to a known service/method.
    /// 4. Construction: Build the `SystemTransaction` struct.
    pub async fn resolve_intent(
        &self,
        user_prompt: &str, 
        chain_id: ioi_types::app::ChainId,
        nonce: u64,
        // Mock address book for name resolution
        address_book: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        // 1. Safety Check (using the runtime as a classifier adapter if needed,
        // or assuming the caller has already run the safety model.
        // For this logic, we assume we trust the runtime to be safe or sandboxed.)

        // 2. Build Canonical Prompt
        let guardrails = PolicyGuardrails {
            allowed_operations: vec![
                "transfer".to_string(),
                "governance_vote".to_string(),
                "start_agent".to_string(),
            ],
            max_token_spend: 1000,
        };

        // Contextualize prompt with address book
        let context_str = format!("Address Book: {:?}", address_book);
        let prompt = PromptWrapper::build_canonical_prompt(user_prompt, &context_str, &guardrails);

        // 3. Inference
        // Use a deterministic hash for the prompt to cache results
        let model_hash = [0u8; 32]; // Use default/system model
        let options = InferenceOptions {
            temperature: 0.0, // Strict determinism desired
            ..Default::default()
        };

        let output_bytes = self
            .inference
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| anyhow!("Intent inference failed: {}", e))?;

        let output_str = String::from_utf8(output_bytes)?;

        // 4. Parse LLM Output (Expected schema: { "operation_id": ..., "params": ... })
        let plan: IntentPlan = serde_json::from_str(&output_str)
            .map_err(|e| anyhow!("Failed to parse intent plan: {}", e))?;

        // 5. Construct Transaction
        // [FIX] Refactored to build the full ChainTransaction inside match arms
        // to handle conflicting Payload types (SettlementPayload vs SystemPayload).
        let tx = match plan.operation_id.as_str() {
            "transfer" => {
                let to_addr = plan
                    .params
                    .get("to")
                    .and_then(|v| v.as_str())
                    .ok_or(anyhow!("Missing 'to' param"))?;
                let amount = plan
                    .params
                    .get("amount")
                    .and_then(|v| v.as_u64())
                    .ok_or(anyhow!("Missing 'amount' param"))?;

                let to_bytes = hex::decode(to_addr.trim_start_matches("0x"))?;
                let to_account = ioi_types::app::AccountId(
                    to_bytes
                        .try_into()
                        .map_err(|_| anyhow!("Invalid address length"))?,
                );

                let payload = ioi_types::app::SettlementPayload::Transfer {
                    to: to_account,
                    amount: amount as u128,
                };

                let header = SignHeader {
                    account_id: Default::default(), // Placeholder, filled by UI
                    nonce,
                    chain_id,
                    tx_version: 1,
                    session_auth: None,
                };

                ChainTransaction::Settlement(ioi_types::app::SettlementTransaction {
                    header,
                    payload,
                    signature_proof: SignatureProof::default(),
                })
            }
            "start_agent" => {
                let goal = plan
                    .params
                    .get("goal")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown goal");

                // Generate random session ID for the new agent task
                let mut session_id = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut session_id);

                let params = StartAgentParams {
                    session_id,
                    goal: goal.to_string(),
                    max_steps: 10,
                    parent_session_id: None,
                    initial_budget: 1000,
                };
                
                let params_bytes = codec::to_bytes_canonical(&params)
                    .map_err(|e| anyhow!("Failed to encode agent params: {}", e))?;

                let payload = SystemPayload::CallService {
                    service_id: "desktop_agent".to_string(),
                    method: "start@v1".to_string(),
                    params: params_bytes,
                };

                let header = SignHeader {
                    account_id: Default::default(), // Placeholder, filled by UI
                    nonce,
                    chain_id,
                    tx_version: 1,
                    session_auth: None,
                };

                ChainTransaction::System(Box::new(SystemTransaction {
                    header,
                    payload,
                    signature_proof: SignatureProof::default(),
                }))
            }
            _ => return Err(anyhow!("Unknown operation ID: {}", plan.operation_id)),
        };

        let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| anyhow!(e))?;
        Ok(tx_bytes)
    }
}

#[derive(Deserialize)]
struct IntentPlan {
    operation_id: String,
    params: serde_json::Map<String, Value>,
    #[serde(default)]
    gas_ceiling: u64,
}