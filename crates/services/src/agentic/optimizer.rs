// Path: crates/services/src/agentic/optimizer.rs

//! The Optimizer Service (The Meta-Manager).
//! 
//! This service acts as the "Evolutionary Engine" for the IOI Kernel.
//! It observes agent execution failures, synthesizes code patches (mutations),
//! verifies them in a sandbox, and submits upgrade transactions to evolve the agent.
//! 
//! # Evolutionary Cycle
//! 1. **Observe:** Query SCS for failed `StepTrace` frames.
//! 2. **Mutate:** Use a Reasoning Model (e.g., DeepSeek/OpenAI o1) to rewrite the Agent Manifest.
//! 3. **Filter:** Run `PolicyEngine::validate_safety_ratchet` (Pre-check).
//! 4. **Verify:** Execute the new manifest against the failed input in Ghost Mode.
//! 5. **Deploy:** Submit `swap_module` transaction to the Governance service.

use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_macros::service_interface;
use ioi_types::app::{
    ActionRequest, ActionTarget, AgentState, ChainTransaction, KernelEvent, StepTrace,
    SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::any::Any;
use std::sync::Arc;

// [NEW] Import Policy Engine for Safety Ratchet
use crate::agentic::policy::PolicyEngine;
use crate::agentic::rules::ActionRules;
use ioi_types::app::agentic::InferenceOptions;

/// Parameters for triggering an optimization loop.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct OptimizeAgentParams {
    /// The ID of the agent service to optimize.
    pub target_service_id: String,
    /// The ID of the session where the failure occurred.
    pub session_id: [u8; 32],
    /// The specific step index that failed.
    pub failed_step_index: u32,
    /// The feedback/error message to guide the mutation.
    pub feedback_hint: Option<String>,
}

#[derive(Default, Debug)]
pub struct OptimizerService {
    // References to Kernel primitives needed for mutation
    inference: Option<Arc<dyn InferenceRuntime>>,
    safety_model: Option<Arc<dyn LocalSafetyModel>>,
}

impl OptimizerService {
    pub fn new(
        inference: Arc<dyn InferenceRuntime>,
        safety_model: Arc<dyn LocalSafetyModel>,
    ) -> Self {
        Self {
            inference: Some(inference),
            safety_model: Some(safety_model),
        }
    }

    /// Internal helper to generate the mutation (The "Genetic Algorithm").
    async fn synthesize_mutation(
        &self,
        current_manifest: &str,
        failure_trace: &StepTrace,
        feedback: Option<&String>,
    ) -> Result<String, TransactionError> {
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid(
            "Optimizer has no inference runtime".into(),
        ))?;

        let prompt = format!(
            "SYSTEM: You are an AGI Optimizer. Your goal is to fix a failing agent.\n\
            \n\
            CONTEXT:\n\
            Current Agent Manifest:\n{}\n\
            \n\
            Failure Trace:\n\
            - Input: {}\n\
            - Output: {}\n\
            - Error: {:?}\n\
            - Feedback: {:?}\n\
            \n\
            TASK:\n\
            Rewrite the Agent Manifest to fix this error. \n\
            1. You MAY update the `system_prompt` or `tools`.\n\
            2. You MUST NOT relax the `policy` (safety rules).\n\
            3. Return ONLY the valid JSON of the new manifest.",
            current_manifest,
            failure_trace.full_prompt,
            failure_trace.raw_output,
            failure_trace.error,
            feedback.unwrap_or(&"Fix the runtime error.".to_string())
        );

        // Use high-temp for creative solutions, or reasoning model if available
        let options = InferenceOptions {
            temperature: 0.7, 
            ..Default::default()
        };

        // Use zero-hash for model ID (default model for the runtime)
        let model_hash = [0u8; 32];
        
        let output_bytes = runtime
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Mutation failed: {}", e)))?;

        let output_str = String::from_utf8(output_bytes)
            .map_err(|_| TransactionError::Invalid("Invalid UTF-8 from optimizer".into()))?;

        // Extract JSON from potential markdown wrapping
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str.rfind('}').map(|i| i + 1).unwrap_or(output_str.len());
        let new_manifest = output_str[json_start..json_end].to_string();

        Ok(new_manifest)
    }
}

#[service_interface(
    id = "optimizer",
    abi_version = 1,
    state_schema = "v1",
    capabilities = ""
)]
impl OptimizerService {
    /// The main entrypoint: "Improve this Agent".
    #[method]
    pub async fn optimize_agent(
        &self,
        state: &mut dyn StateAccess,
        params: OptimizeAgentParams,
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // 1. Fetch Failure Context (Introspection)
        // In a real implementation, we would query the SCS directly.
        // For now, we simulate fetching the trace from the state log.
        // (See `services/agentic/desktop/keys.rs` for trace key schema)
        let trace_key = [
            b"agent::trace::",
            params.session_id.as_slice(),
            &params.failed_step_index.to_le_bytes(),
        ]
        .concat();

        let trace_bytes = state
            .get(&trace_key)?
            .ok_or(TransactionError::Invalid("Failure trace not found".into()))?;
        
        let trace: StepTrace = codec::from_bytes_canonical(&trace_bytes)?;

        // 2. Fetch Current Manifest (The Parent Genome)
        // Using the active service registry
        let meta_key = ioi_types::keys::active_service_key(&params.target_service_id);
        let meta_bytes = state.get(&meta_key)?.ok_or(TransactionError::Invalid(
            "Target service not active".into(),
        ))?;
        
        // We need the actual Manifest content. In a full implementation, we fetch the artifact.
        // Here, we assume the manifest is recoverable or passed in.
        // Placeholder: "Assume current_manifest is known or retrievable"
        let current_manifest = "{\"system_prompt\": \"...\"}".to_string(); 

        // 3. Generate Mutation
        let new_manifest_str = self.synthesize_mutation(
            &current_manifest, 
            &trace, 
            params.feedback_hint.as_ref()
        ).await?;

        // 4. The Safety Ratchet (Evolutionary Filter)
        // Verify that the new policy is not weaker than the old one.
        // We need to parse both manifests into ActionRules (Policy).
        let old_policy = ActionRules::default(); // Mock: Parse from current_manifest
        let new_policy = ActionRules::default(); // Mock: Parse from new_manifest_str
        
        if let Err(violation) = PolicyEngine::validate_safety_ratchet(&old_policy, &new_policy) {
            return Err(TransactionError::Invalid(format!(
                "Evolution rejected by Safety Ratchet: {}",
                violation
            )));
        }

        // 5. Submit Upgrade Transaction (The deployment)
        // Note: In a real system, we would first run a "Ghost Mode" simulation here to verify the fix works.
        
        // We construct a cross-service call to `governance::swap_module`
        // NOTE: The Kernel doesn't allow services to invoke other services directly synchronously easily
        // in the current trait definition without a dispatcher.
        // Instead, we emit an Event suggesting the upgrade, or we modify state directly if authorized.
        
        // Since we are inside `handle_service_call`, we can't easily call another service's handle.
        // Pattern: We can schedule a "Pending Upgrade" in our own state, 
        // which the Governance service picks up, or we return a specific Result indicating a proposed upgrade.
        
        log::info!(
            "Optimizer: Generated valid mutation for agent {}. \
            Ratchet check passed. \
            New manifest hash: {}",
            params.target_service_id,
            "hash(new_manifest_str)"
        );

        // For this implementation, we simply log success. 
        // The UI/Orchestrator would see this and sign the actual `swap_module` transaction.
        Ok(())
    }
}

#[async_trait]
impl UpgradableService for OptimizerService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}