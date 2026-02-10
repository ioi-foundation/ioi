// Path: crates/services/src/agentic/prompt_wrapper.rs
use ioi_api::impl_service_base;

pub struct PolicyGuardrails {
    pub allowed_operations: Vec<String>,
    pub max_token_spend: u64,
}

pub struct PromptWrapper;

impl_service_base!(PromptWrapper, "prompt_wrapper");

impl PromptWrapper {
    pub fn build_canonical_prompt(
        user_intent: &str,
        chain_state_context: &str,
        guardrails: &PolicyGuardrails,
    ) -> String {
        // [FIX] Improved Prompt Engineering to ensure correct schema compliance
        let header = format!(
            "You are a secure blockchain intent resolver. Your job is to map natural language to a transaction JSON.\n\
            Allowed Operations: {:?}\n\
            Chain Context: {}\n\n\
            Schemas:\n\
            - Transfer: {{ \"operation_id\": \"transfer\", \"params\": {{ \"to\": \"0x...\", \"amount\": 100 }} }}\n\
            - Start Agent: {{ \"operation_id\": \"start_agent\", \"params\": {{ \"goal\": \"...\" }} }}\n\
            - Governance: {{ \"operation_id\": \"governance_vote\", \"params\": {{ \"proposal_id\": 1, \"vote\": \"yes\" }} }}",
            guardrails.allowed_operations, chain_state_context
        );

        let body = format!("User Input: \"{}\"", user_intent);

        let footer = "OUTPUT RULES:\n\
            1. Return ONLY the JSON object.\n\
            2. Do NOT use Markdown formatting (no ```json ... ```).\n\
            3. The root object MUST have an 'operation_id' field.\n\
            4. 'gas_ceiling' is optional.";

        let prompt = format!("{}\n\n{}\n\n{}", header, body, footer);
        log::info!("PromptWrapper created canonical prompt");
        prompt
    }
}
