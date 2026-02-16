// Path: crates/services/src/agentic/intent.rs

use crate::agentic::desktop::{AgentMode, StartAgentParams};
use crate::agentic::prompt_wrapper::PolicyGuardrails; // [FIX] Removed PromptWrapper
use anyhow::{anyhow, Result};
use hex;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    ChainTransaction, SignHeader, SignatureProof, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc; // [FIX] Required for decoding session ID

fn decode_session_id_hex_compat(session_id_hex: &str) -> Option<[u8; 32]> {
    let normalized = session_id_hex
        .trim()
        .trim_start_matches("0x")
        .replace('-', "");
    let bytes = hex::decode(normalized).ok()?;
    let mut session_id = [0u8; 32];
    match bytes.len() {
        32 => {
            session_id.copy_from_slice(&bytes);
            Some(session_id)
        }
        16 => {
            session_id[..16].copy_from_slice(&bytes);
            Some(session_id)
        }
        _ => None,
    }
}

fn parse_prefixed_agent_start(user_prompt: &str) -> Option<([u8; 32], AgentMode, String)> {
    let mut remaining = user_prompt.trim_start();
    let mut mode = AgentMode::Agent;
    let mut session_id: Option<[u8; 32]> = None;

    loop {
        if let Some(rest) = remaining.strip_prefix("MODE:CHAT") {
            mode = AgentMode::Chat;
            remaining = rest.trim_start();
            continue;
        }
        if let Some(rest) = remaining.strip_prefix("MODE:AGENT") {
            mode = AgentMode::Agent;
            remaining = rest.trim_start();
            continue;
        }
        if let Some(rest) = remaining.strip_prefix("SESSION:") {
            let token_end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            let token = &rest[..token_end];
            let parsed = decode_session_id_hex_compat(token)?;
            session_id = Some(parsed);
            remaining = rest[token_end..].trim_start();
            continue;
        }
        break;
    }

    let sid = session_id?;
    Some((sid, mode, remaining.to_string()))
}

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
        if let Some((session_id, mode, goal)) = parse_prefixed_agent_start(user_prompt) {
            let params = StartAgentParams {
                session_id,
                goal,
                max_steps: 10,
                parent_session_id: None,
                initial_budget: 10_000_000,
                mode,
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

            let tx = ChainTransaction::System(Box::new(SystemTransaction {
                header,
                payload,
                signature_proof: SignatureProof::default(),
            }));
            let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| anyhow!(e))?;
            return Ok(tx_bytes);
        }

        let guardrails = PolicyGuardrails {
            allowed_operations: vec![
                "transfer".to_string(),
                "governance_vote".to_string(),
                "start_agent".to_string(),
            ],
            max_token_spend: 1000,
        };

        let context_str = format!("Address Book: {:?}", address_book);

        // [MODIFIED] Update prompt to handle explicit "Chat Mode" prefix and schema examples
        // Also added instruction for Session ID extraction from prompt if present (e.g., re-launching context)
        let header = format!(
            "You are a secure blockchain intent resolver. Your job is to map natural language to a transaction JSON.\n\
            Allowed Operations: {:?}\n\
            Chain Context: {}\n\n\
            Schemas:\n\
            - Transfer: {{ \"operation_id\": \"transfer\", \"params\": {{ \"to\": \"0x...\", \"amount\": 100 }} }}\n\
            - Agent: {{ \"operation_id\": \"start_agent\", \"params\": {{ \"goal\": \"...\", \"mode\": \"Agent\" }} }}\n\
            - Chat: {{ \"operation_id\": \"start_agent\", \"params\": {{ \"goal\": \"...\", \"mode\": \"Chat\" }} }}\n\
            - Governance: {{ \"operation_id\": \"governance_vote\", \"params\": {{ \"proposal_id\": 1, \"vote\": \"yes\" }} }}",
            guardrails.allowed_operations, context_str
        );

        let body = format!("User Input: \"{}\"", user_prompt);

        let footer = "OUTPUT RULES:\n\
            1. Return ONLY the JSON object.\n\
            2. Do NOT use Markdown formatting (no ```json ... ```).\n\
            3. The root object MUST have an 'operation_id' field.\n\
            4. If input starts with 'MODE:CHAT', set params.mode='Chat'. Default mode is 'Agent'.\n\
            5. If input contains 'SESSION:<hex_id>', extract it into params.session_id_hex.\n\
            6. 'gas_ceiling' is optional.";

        let prompt = format!("{}\n\n{}\n\n{}", header, body, footer);

        let model_hash = [0u8; 32];
        let options = InferenceOptions {
            temperature: 0.0,
            json_mode: true, // [FIX] Enforce JSON mode for reliable intent parsing
            ..Default::default()
        };

        let output_bytes = self
            .inference
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| anyhow!("Intent inference failed: {}", e))?;

        let output_str = String::from_utf8(output_bytes)?;

        // Robust extraction
        let json_str = Self::extract_json(&output_str).ok_or_else(|| {
            log::error!(
                "IntentResolver: No JSON object found in output: '{}'",
                output_str
            );
            anyhow!("LLM did not return a valid JSON object")
        })?;

        // 4. Parse LLM Output
        let plan: IntentPlan = serde_json::from_str(&json_str).map_err(|e| {
            log::error!(
                "IntentResolver: JSON parse failed.\nRaw: {}\nExtracted: {}\nError: {}",
                output_str,
                json_str,
                e
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

                // [NEW] Parse mode from LLM output
                let mode = match plan.params.get("mode").and_then(|v| v.as_str()) {
                    Some("Chat") => AgentMode::Chat,
                    _ => AgentMode::Agent,
                };

                // [NEW] Check for explicit session ID in params (e.g. resumption context)
                let mut session_id = [0u8; 32];
                if let Some(sid_hex) = plan.params.get("session_id_hex").and_then(|v| v.as_str()) {
                    if let Some(parsed) = decode_session_id_hex_compat(sid_hex) {
                        session_id = parsed;
                    } else {
                        rand::thread_rng().fill_bytes(&mut session_id);
                    }
                } else {
                    rand::thread_rng().fill_bytes(&mut session_id);
                }

                let params = StartAgentParams {
                    session_id,
                    goal: goal.to_string(),
                    max_steps: 10,
                    parent_session_id: None,
                    initial_budget: 10_000_000,
                    mode,
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
    // Aliases for common LLM hallucinations
    #[serde(alias = "operationId", alias = "action", alias = "function")]
    operation_id: String,

    #[serde(default)]
    params: serde_json::Map<String, Value>,

    #[serde(default, alias = "gasCeiling", alias = "gas_limit")]
    gas_ceiling: u64,
}

#[cfg(test)]
mod tests {
    use super::{decode_session_id_hex_compat, parse_prefixed_agent_start};
    use crate::agentic::desktop::AgentMode;

    #[test]
    fn session_id_32_bytes_is_preserved() {
        let input = "ab".repeat(32);
        let parsed = decode_session_id_hex_compat(&input).expect("must decode");
        assert_eq!(hex::encode(parsed), input);
    }

    #[test]
    fn session_id_16_bytes_is_zero_extended() {
        let input = "cd".repeat(16);
        let parsed = decode_session_id_hex_compat(&input).expect("must decode");
        assert_eq!(hex::encode(&parsed[..16]), input);
        assert_eq!(parsed[16..], [0u8; 16]);
    }

    #[test]
    fn invalid_session_id_returns_none() {
        assert!(decode_session_id_hex_compat("xyz").is_none());
        assert!(decode_session_id_hex_compat(&"aa".repeat(15)).is_none());
    }

    #[test]
    fn prefixed_agent_start_preserves_multiline_goal() {
        let sid = "ab".repeat(32);
        let prompt = format!(
            "SESSION:{} I'm testing privacy pruning.\nPlease summarize this note:\nLine 2 with key=value",
            sid
        );
        let (session_id, mode, goal) =
            parse_prefixed_agent_start(&prompt).expect("must parse prefixed prompt");
        assert_eq!(hex::encode(session_id), sid);
        assert_eq!(mode, AgentMode::Agent);
        assert_eq!(
            goal,
            "I'm testing privacy pruning.\nPlease summarize this note:\nLine 2 with key=value"
        );
    }

    #[test]
    fn prefixed_agent_start_supports_chat_mode_prefix() {
        let sid = "cd".repeat(32);
        let prompt = format!("MODE:CHAT SESSION:{} draft reply", sid);
        let (session_id, mode, goal) =
            parse_prefixed_agent_start(&prompt).expect("must parse prefixed prompt");
        assert_eq!(hex::encode(session_id), sid);
        assert_eq!(mode, AgentMode::Chat);
        assert_eq!(goal, "draft reply");
    }

    #[test]
    fn prefixed_agent_start_requires_session_prefix() {
        assert!(parse_prefixed_agent_start("hello world").is_none());
    }
}
