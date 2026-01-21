// Path: crates/services/src/agentic/intent.rs

use crate::agentic::prompt_wrapper::{PolicyGuardrails, PromptWrapper};
use crate::agentic::desktop::StartAgentParams;
use anyhow::{anyhow, Result};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    ChainTransaction, SignHeader, SignatureProof,
    SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

/// A service to translate natural language user intent into a canonical, signable transaction.
pub struct IntentResolver {
    inference: Arc<dyn InferenceRuntime>,
}

impl IntentResolver {
    pub fn new(inference: Arc<dyn InferenceRuntime>) -> Self {
        Self { inference }
    }

    /// Robustly extracts the first JSON object from a string, ignoring surrounding text.
    /// Handles nested braces and string escaping.
    fn extract_json(raw: &str) -> Option<String> {
        let start = raw.find('{')?;
        let mut brace_count = 0;
        let mut in_string = false;
        let mut escape = false;
        let mut end = None;

        // Iterate characters starting from the first '{'
        for (i, c) in raw[start..].char_indices() {
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_string = !in_string;
                continue;
            }
            if !in_string {
                if c == '{' {
                    brace_count += 1;
                } else if c == '}' {
                    brace_count -= 1;
                    if brace_count == 0 {
                        end = Some(start + i + 1);
                        break;
                    }
                }
            }
        }

        end.map(|e| raw[start..e].to_string())
    }

    pub async fn resolve_intent(
        &self,
        user_prompt: &str, 
        chain_id: ioi_types::app::ChainId,
        nonce: u64,
        address_book: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        let guardrails = PolicyGuardrails {
            allowed_operations: vec![
                "transfer".to_string(),
                "governance_vote".to_string(),
                "start_agent".to_string(),
            ],
            max_token_spend: 1000,
        };

        let context_str = format!("Address Book: {:?}", address_book);
        let prompt = PromptWrapper::build_canonical_prompt(user_prompt, &context_str, &guardrails);

        let model_hash = [0u8; 32]; 
        let options = InferenceOptions {
            temperature: 0.0,
            ..Default::default()
        };

        let output_bytes = self
            .inference
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| anyhow!("Intent inference failed: {}", e))?;

        let output_str = String::from_utf8(output_bytes)?;
        
        // [FIX] Robust extraction
        let json_str = Self::extract_json(&output_str).ok_or_else(|| {
            log::error!("IntentResolver: No JSON object found in output: '{}'", output_str);
            anyhow!("LLM did not return a valid JSON object")
        })?;

        // 4. Parse LLM Output
        let plan: IntentPlan = serde_json::from_str(&json_str)
            .map_err(|e| {
                log::error!(
                    "IntentResolver: JSON parse failed.\nRaw: {}\nExtracted: {}\nError: {}", 
                    output_str, json_str, e
                );
                anyhow!("Failed to parse intent plan: {}", e)
            })?;

        // 5. Construct Transaction
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

                let to_bytes = hex::decode(to_addr.trim_start_matches("0x"))
                    .map_err(|_| anyhow!("Invalid hex address"))?;
                    
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
                    account_id: Default::default(), 
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

                let mut session_id = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut session_id);

                let params = StartAgentParams {
                    session_id,
                    goal: goal.to_string(),
                    max_steps: 10,
                    parent_session_id: None,
                    initial_budget: 10_000_000, 
                };
                
                let params_bytes = codec::to_bytes_canonical(&params)
                    .map_err(|e| anyhow!("Failed to encode agent params: {}", e))?;

                let payload = SystemPayload::CallService {
                    service_id: "desktop_agent".to_string(),
                    method: "start@v1".to_string(),
                    params: params_bytes,
                };

                let header = SignHeader {
                    account_id: Default::default(),
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

#[derive(Deserialize, Debug)]
struct IntentPlan {
    // [FIX] Aliases for common LLM hallucinations
    #[serde(alias = "operationId", alias = "action", alias = "function")]
    operation_id: String,
    
    #[serde(default)]
    params: serde_json::Map<String, Value>,
    
    #[serde(default, alias = "gasCeiling", alias = "gas_limit")]
    gas_ceiling: u64,
}