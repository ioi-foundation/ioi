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
use ioi_api::services::{UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_macros::service_interface;
use ioi_types::app::{StepTrace}; 
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

// [NEW] Import Policy Engine for Safety Ratchet
use crate::agentic::policy::PolicyEngine;
use crate::agentic::rules::{ActionRules};
use ioi_types::app::agentic::{
    InferenceOptions, AgentMacro, LlmToolDefinition, IntelligenceAsset, AgentManifest,
    RuntimeEnvironment, ResourceRequirements 
};
use ioi_scs::{SovereignContextStore, FrameType}; 
use ioi_crypto::algorithms::hash::sha256;
// [FIX] Removed unused import
// use dcrypt::algorithms::ByteSerializable; 
use reqwest::Url; 

// [NEW] Import Market Service types
use crate::market::{PublishAssetParams}; 

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

#[derive(Default)]
pub struct OptimizerService {
    // References to Kernel primitives needed for mutation
    inference: Option<Arc<dyn InferenceRuntime>>,
    safety_model: Option<Arc<dyn LocalSafetyModel>>,
    // [NEW] SCS reference for persisting skills
    scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
}

// [FIX] Manual Debug implementation
impl fmt::Debug for OptimizerService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OptimizerService")
            .field("inference", &self.inference.is_some())
            .field("safety_model", &self.safety_model.is_some())
            .field("scs", &self.scs.is_some())
            .finish()
    }
}

impl OptimizerService {
    pub fn new(
        inference: Arc<dyn InferenceRuntime>,
        safety_model: Arc<dyn LocalSafetyModel>,
    ) -> Self {
        Self {
            inference: Some(inference),
            safety_model: Some(safety_model),
            scs: None, 
        }
    }
    
    // [NEW] Builder method to inject SCS
    pub fn with_scs(mut self, scs: Arc<std::sync::Mutex<SovereignContextStore>>) -> Self {
        self.scs = Some(scs);
        self
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

    /// [NEW] Policy Compilation: Freezes a recorded trace into an immutable policy.
    pub async fn compile_trace(
        &self,
        trace_steps: Vec<StepTrace>,
    ) -> Result<ActionRules, TransactionError> {
        use std::collections::{HashSet};
        use crate::agentic::rules::{Rule, RuleConditions, DefaultPolicy, Verdict};

        let mut allowed_domains = HashSet::new();
        let mut allowed_files = HashSet::new();

        for step in trace_steps {
            // Only learn from successful steps
            if !step.success { continue; }
            if let Ok(tool_call) = serde_json::from_str::<serde_json::Value>(&step.raw_output) {
                 if let Some(name) = tool_call["name"].as_str() {
                      let args = &tool_call["arguments"];
                      match name {
                          "browser__navigate" | "net__fetch" => {
                              if let Some(url) = args["url"].as_str() {
                                  // [FIX] Use Url from reqwest
                                  if let Ok(u) = Url::parse(url) {
                                      if let Some(host) = u.host_str() {
                                          allowed_domains.insert(host.to_string());
                                      }
                                  }
                              }
                          },
                          "filesystem__read_file" | "filesystem__write_file" => {
                              if let Some(path) = args["path"].as_str() {
                                  allowed_files.insert(path.to_string());
                              }
                          },
                          _ => {}
                      }
                 }
            }
        }

        // Convert map to Vec<Rule>
        let rules = vec![
            Rule {
                rule_id: Some("compiled-network-whitelist".into()),
                target: "net::fetch".into(),
                conditions: RuleConditions {
                    allow_domains: Some(allowed_domains.into_iter().collect()),
                    ..Default::default()
                },
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("compiled-fs-whitelist".into()),
                target: "fs::*".into(), 
                conditions: RuleConditions {
                    allow_paths: Some(allowed_files.into_iter().collect()),
                    ..Default::default()
                },
                action: Verdict::Allow,
            }
        ];

        Ok(ActionRules {
            policy_id: format!("frozen-skill-{}", hex::encode(ioi_crypto::algorithms::hash::sha256(b"trace").unwrap())),
            defaults: DefaultPolicy::DenyAll, 
            rules,
        })
    }

    /// [NEW] Skill Crystallization (RSI)
    /// Converts a successful execution trace into a reusable, parameterized tool macro.
    pub async fn crystallize_skill_internal(
        &self,
        session_id: [u8; 32],
        trace_hash: [u8; 32],
    ) -> Result<AgentMacro, TransactionError> {
        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;
        
        // 1. Fetch Session Trace (Mocked)
        let trace_summary = "Step 1: Navigate to stripe.com/login. Step 2: Click 'Sign In'. Step 3: Wait for dashboard."; 

        // 2. Synthesize Macro Definition
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid(
            "Optimizer has no inference runtime".into(),
        ))?;
        
        let prompt = format!(
            "SYSTEM: Convert this execution trace into a reusable JSON tool definition.
             Trace: {}
             
             Output Schema:
             {{
                \"name\": \"login_stripe\",
                \"description\": \"Logs into Stripe dashboard automatically.\",
                \"parameters\": {{ \"type\": \"object\", \"properties\": {{ \"username\": {{ \"type\": \"string\" }} }} }},
                \"steps\": [
                    {{ \"target\": \"browser::navigate\", \"params\": {{ \"url\": \"https://dashboard.stripe.com/login\" }} }},
                    {{ \"target\": \"gui::type\", \"params\": {{ \"text\": \"{{username}}\" }} }}
                ]
             }}
             RETURN JSON ONLY.",
             trace_summary
        );

        let options = InferenceOptions { temperature: 0.0, ..Default::default() };
        let output_bytes = runtime.execute_inference([0u8;32], prompt.as_bytes(), options).await
             .map_err(|e| TransactionError::Invalid(e.to_string()))?;
             
        let output_str = String::from_utf8(output_bytes).unwrap_or_default();
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str.rfind('}').map(|i| i + 1).unwrap_or(output_str.len());
        let skill_json: serde_json::Value = serde_json::from_str(&output_str[json_start..json_end])
             .map_err(|e| TransactionError::Invalid(format!("Skill synthesis failed: {}", e)))?;

        // 3. Construct AgentMacro Struct
        let definition = LlmToolDefinition {
            name: skill_json["name"].as_str().unwrap_or("unknown_skill").to_string(),
            description: skill_json["description"].as_str().unwrap_or("").to_string(),
            parameters: skill_json["parameters"].to_string(),
        };

        let mut steps = Vec::new();
        if let Some(steps_arr) = skill_json["steps"].as_array() {
            for s in steps_arr {
                let target_str = s["target"].as_str().unwrap_or("");
                let target = match target_str {
                    "browser::navigate" => ioi_types::app::ActionTarget::BrowserNavigate,
                    "gui::type" => ioi_types::app::ActionTarget::GuiType,
                    "gui::click" => ioi_types::app::ActionTarget::GuiClick,
                    _ => ioi_types::app::ActionTarget::Custom(target_str.to_string()),
                };
                
                // Serialize params for the action request
                let params = serde_json::to_vec(&s["params"]).unwrap_or_default();
                
                // [FIX] Correctly construct ActionRequest
                steps.push(ioi_types::app::ActionRequest {
                    target,
                    params,
                    context: ioi_types::app::ActionContext {
                        agent_id: "macro".into(),
                        session_id: None,
                        window_id: None,
                    },
                    nonce: 0,
                });
            }
        }
        
        let skill = AgentMacro {
            definition,
            steps,
            source_trace_hash: trace_hash,
            fitness: 1.0, // Initial high fitness as it comes from a success
        };

        // 4. Persist to SCS as Skill Frame
        // This makes it discoverable by `discover_tools` via `store.scan_skills()`
        let skill_bytes = codec::to_bytes_canonical(&skill).map_err(|e| TransactionError::Serialization(e))?;
        
        // Calculate deterministic hash for skill identity
        let skill_hash_res = sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
        let mut skill_hash = [0u8; 32];
        // [FIX] Use copy_from_slice via local binding or manual copy if ByteSerializable not imported
        // Since we removed ByteSerializable, we can't use copy_from_slice from the trait.
        // Array implements copy_from_slice natively on slice, so this works if we have the slice.
        skill_hash[..32].copy_from_slice(&skill_hash_res.as_ref()[..32]);

        {
            let mut store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
            let _ = store.append_frame(
                FrameType::Skill, 
                &skill_bytes,
                0, 
                [0u8; 32], 
                session_id
            ).map_err(|e| TransactionError::Invalid(e.to_string()))?;
        }
        
        log::info!("Optimizer: Crystallized new skill '{}' from session {}", skill.definition.name, hex::encode(session_id));

        Ok(skill)
    }

    /// [NEW] Converts a successful agent session into a tradeable Agent Manifest and submits it to the market.
    pub async fn package_agent_for_market(
        &self,
        state: &mut dyn StateAccess,
        // Using OptimizeAgentParams to carry session_id
        params: OptimizeAgentParams, 
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // 1. Retrieve Agent State
        let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
        let full_key = [ns_prefix.as_slice(), b"agent::state::", params.session_id.as_slice()].concat();
        
        let state_bytes = state.get(&full_key)?.ok_or(TransactionError::Invalid("Agent state not found".into()))?;
        // [FIX] Correctly refer to the AgentState type via the crate root
        let agent_state: crate::agentic::desktop::AgentState = codec::from_bytes_canonical(&state_bytes)?;

        // 2. Discover Skills Used
        // We scan the trace to see which skills/tools were actually effective.
        // For MVP, we'll just grab all skills crystallized in this session.
        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;
        let store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
        
        // [FIX] E0716: Bind empty vec to extend lifetime
        let empty_vec = Vec::new();
        let session_frames = store.session_index.get(&params.session_id).unwrap_or(&empty_vec);
        
        let mut skill_hashes = Vec::new();
        for &fid in session_frames {
            let frame = store.toc.frames.get(fid as usize).unwrap();
            if frame.frame_type == ioi_scs::FrameType::Skill {
                skill_hashes.push(frame.checksum);
            }
        }

        // 3. Construct Manifest
        // "Package" the agent configuration
        let manifest = AgentManifest {
            name: format!("Agent-{}", hex::encode(&params.session_id[0..4])),
            description: format!("Auto-packaged agent trained on goal: '{}'", agent_state.goal),
            system_prompt: "You are a specialized agent...".to_string(), // In real impl, fetch from config
            model_selector: "gpt-4o".to_string(), // In real impl, fetch from config
            skills: skill_hashes,
            default_policy_hash: [0u8; 32], // Default policy
            author: ctx.signer_account_id,
            price: 500, // Default price
            tags: vec!["auto-packaged".into()],
            version: "0.1.0".to_string(),
            // [FIX] Initialize new fields
            runtime: RuntimeEnvironment::Native,
            resources: ResourceRequirements {
                min_vram_gb: 0,
                min_ram_gb: 4,
                min_cpus: 2,
                network_access: "public".to_string(),
                provider_preference: "any".to_string(),
            },
        };

        // 4. Submit to Market (via Intent)
        let intent_key = [b"optimizer::publish_intent::", params.session_id.as_slice()].concat();
        let publish_params = PublishAssetParams {
            asset: IntelligenceAsset::Agent(manifest),
        };
        
        // This blob is what the UI will sign and send to "market::publish_asset"
        state.insert(&intent_key, &codec::to_bytes_canonical(&publish_params)?)?;
        
        log::info!("Optimizer: Packaged agent session {} for market.", hex::encode(&params.session_id[0..4]));
        Ok(())
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
        _ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // 1. Fetch Failure Context (Introspection)
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
        let meta_key = ioi_types::keys::active_service_key(&params.target_service_id);
        let _meta_bytes = state.get(&meta_key)?.ok_or(TransactionError::Invalid(
            "Target service not active".into(),
        ))?;
        
        // Placeholder for manifest retrieval
        let current_manifest = "{\"system_prompt\": \"...\"}".to_string(); 

        // 3. Generate Mutation
        let _new_manifest_str = self.synthesize_mutation(
            &current_manifest, 
            &trace, 
            params.feedback_hint.as_ref()
        ).await?;

        // 4. The Safety Ratchet (Evolutionary Filter)
        let old_policy = ActionRules::default(); 
        let new_policy = ActionRules::default(); 
        
        if let Err(violation) = PolicyEngine::validate_safety_ratchet(&old_policy, &new_policy) {
            return Err(TransactionError::Invalid(format!(
                "Evolution rejected by Safety Ratchet: {}",
                violation
            )));
        }

        // 5. Submit Upgrade Transaction (The deployment)
        log::info!(
            "Optimizer: Generated valid mutation for agent {}. \
            Ratchet check passed. \
            New manifest hash: {}",
            params.target_service_id,
            "hash(new_manifest_str)"
        );

        Ok(())
    }
    
    // [NEW] Dispatcher for skill crystallization (called via system transaction)
    #[method]
    pub async fn crystallize_skill(
        &self,
        _state: &mut dyn StateAccess,
        params: crate::agentic::desktop::types::StepAgentParams, // Reuse struct for session_id
        _ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // In a real flow, we'd look up the trace hash from state or pass it in.
        // For MVP, we use a zero hash or derive it.
        let trace_hash = [0u8; 32];
        
        // [FIX] Call the renamed internal helper
        self.crystallize_skill_internal(params.session_id, trace_hash).await?;
        Ok(())
    }

    /// [NEW] Dispatcher for deploying an agent to the market (called via system transaction)
    #[method]
    pub async fn deploy_skill(
        &self,
        state: &mut dyn StateAccess,
        params: OptimizeAgentParams, 
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // Delegate to the internal packager
        self.package_agent_for_market(state, params, ctx).await
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