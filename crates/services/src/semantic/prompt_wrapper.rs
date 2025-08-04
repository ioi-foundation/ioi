// crates/services/src/semantic/prompt_wrapper.rs
use depin_sdk_api::services::{BlockchainService, ServiceType};

// A placeholder for on-chain policy definitions.
pub struct PolicyGuardrails {
    pub allowed_operations: Vec<String>,
    pub max_token_spend: u64,
}

pub struct PromptWrapper;

impl BlockchainService for PromptWrapper {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("PromptWrapper".to_string())
    }
}

impl PromptWrapper {
    /// Constructs the canonical prompt sent to all inference committee members.
    /// This ensures every node starts with the exact same input.
    pub fn build_canonical_prompt(
        user_intent: &str,
        chain_state_context: &str, // e.g., current block height, timestamp
        guardrails: &PolicyGuardrails,
    ) -> String {
        // 1. Header: Injects system role and security constraints.
        let header = format!(
            "You are a secure blockchain translation agent. Your role is to interpret user intent into a specific JSON format. \
            You must strictly adhere to the following guardrails: only use operations from the list {:?}. \
            The maximum token spend is {}. Current chain context: {}.",
            guardrails.allowed_operations, guardrails.max_token_spend, chain_state_context
        );

        // 2. Body: Safely wraps the user's raw input.
        let body = format!("<user_intent>{}</user_intent>", user_intent);

        // 3. Footer: Appends the rigid JSON schema for the output.
        let footer =
            "Your entire output must be a single, minified JSON object matching this exact schema: \
            {\"operation_id\": \"string\", \"params\": {\"to\": \"address\", \"amount\": number}, \"gas_ceiling\": number}. \
            Do not include any other text, explanations, or formatting.";

        let prompt = format!("{}\n{}\n{}", header, body, footer);
        log::info!("PromptWrapper created canonical prompt");
        prompt
    }
}
