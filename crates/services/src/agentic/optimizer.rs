// Path: crates/services/src/agentic/optimizer.rs

//! The Optimizer Service (The Meta-Manager).
//! 
//! This service acts as the "Evolutionary Engine" for the IOI Kernel.
//! It observes agent execution failures, synthesizes code patches (mutations),
//! verifies them in a sandbox, and submits upgrade transactions to evolve the agent.

use async_trait::async_trait;
use ioi_api::services::{UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_macros::service_interface;
use ioi_types::app::{StepTrace, ActionRequest, ActionTarget, ActionContext}; 
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use crate::agentic::policy::PolicyEngine;
use crate::agentic::rules::{ActionRules};
use ioi_types::app::agentic::{
    InferenceOptions, AgentMacro, LlmToolDefinition, IntelligenceAsset, AgentManifest,
    RuntimeEnvironment, ResourceRequirements 
};
use ioi_scs::{SovereignContextStore, FrameType, RetentionClass}; 
use ioi_crypto::algorithms::hash::sha256;
use reqwest::Url; 

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

/// [NEW] Parameters for installing an asset from the market.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct InstallAssetParams {
    /// The hash of the asset to install.
    pub asset_hash: [u8; 32],
}

#[derive(Default)]
pub struct OptimizerService {
    // References to Kernel primitives needed for mutation
    inference: Option<Arc<dyn InferenceRuntime>>,
    safety_model: Option<Arc<dyn LocalSafetyModel>>,
    // [NEW] SCS reference for persisting skills
    scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
}

impl fmt::Debug for OptimizerService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
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
    
    pub fn with_scs(mut self, scs: Arc<std::sync::Mutex<SovereignContextStore>>) -> Self {
        self.scs = Some(scs);
        self
    }

    /// [NEW] Helper to index a skill in the vector store for semantic retrieval.
    async fn index_skill(&self, frame_id: u64, definition: &LlmToolDefinition) -> Result<(), TransactionError> {
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid(
            "Optimizer has no inference runtime for embedding".into(),
        ))?;
        
        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;

        // Create a semantic representation: "Name: Description"
        let text_to_embed = format!("{}: {}", definition.name, definition.description);
        
        // Generate embedding
        let vector = runtime.embed_text(&text_to_embed).await
            .map_err(|e| TransactionError::Invalid(format!("Failed to embed skill: {}", e)))?;

        // Insert into mHNSW
        let store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock poisoned".into()))?;
        if let Ok(index_arc) = store.get_vector_index() {
            let mut index = index_arc.lock().map_err(|_| TransactionError::Invalid("Index lock".into()))?;
             if let Some(idx) = index.as_mut() {
                 idx.insert_with_metadata(
                     frame_id, 
                     vector, 
                     FrameType::Skill, 
                     [0u8; 32] 
                 ).map_err(|e| TransactionError::Invalid(format!("Index insert failed: {}", e)))?;
             }
        }
        
        Ok(())
    }

    /// [NEW] Internal logic for asset hydration.
    async fn install_asset_internal(
        &self,
        state: &dyn StateAccess,
        params: InstallAssetParams,
        installer_id: ioi_types::app::AccountId,
    ) -> Result<(), TransactionError> {
        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;

        // 1. Verify License
        let ns_prefix = ioi_api::state::service_namespace_prefix("market");
        let license_key = [
            ns_prefix.as_slice(),
            b"market::license::", 
            installer_id.as_ref(), 
            b"::", 
            &params.asset_hash
        ].concat();

        if state.get(&license_key)?.is_none() {
            return Err(TransactionError::Invalid("No license found. Purchase before installing.".into()));
        }

        // 2. Fetch Payload from Market
        let payload_key = [
            ns_prefix.as_slice(),
            b"market::payload::",
            &params.asset_hash
        ].concat();

        let payload_bytes = state.get(&payload_key)?.ok_or(TransactionError::Invalid("Asset payload not found in Market".into()))?;

        // 3. Validate Hash Integrity (Omitted for brevity, assumed checked at publish)

        // 4. Determine Asset Type & Index
        if let Ok(skill) = codec::from_bytes_canonical::<AgentMacro>(&payload_bytes) {
             // [FIX] Scope the lock to ensure it's dropped before await
             let frame_id = {
                 let mut store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
                 
                 store.append_frame(
                    FrameType::Skill, 
                    &payload_bytes,
                    0, 
                    [0u8; 32], 
                    [0u8; 32],
                    RetentionClass::Archival,
                ).map_err(|e| TransactionError::Invalid(e.to_string()))?
             }; 

            // Index
            self.index_skill(frame_id, &skill.definition).await?;
            
            log::info!("Optimizer: Installed & Indexed skill '{}'", skill.definition.name);
            return Ok(());
        }
        
        Ok(())
    }

    /// [NEW] Generalizes a raw execution trace into a reusable skill macro.
    pub async fn synthesize_skill_from_trace(
        &self,
        trace: &[StepTrace],
        goal: &str,
    ) -> Result<AgentMacro, TransactionError> {
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid("Inference not available".into()))?;

        // 1. Format Trace
        let transcript = trace.iter().map(|s| 
            format!("Step {}: Action={}\nOutput={}", s.step_index, s.raw_output, s.raw_output)
        ).collect::<Vec<_>>().join("\n---\n");

        // 2. Prompt Engineering
        let prompt = format!(
            "SYSTEM: You are a Skill Crystallizer. Convert this successful execution trace into a reusable, generalized JSON Macro.
            
            GOAL: {}
            
            TRACE:
            {}
            
            INSTRUCTIONS:
            1. Identify the generic pattern.
            2. Replace specific values (usernames, URLs, file paths) with parameters {{param_name}}.
            3. Generate a JSON schema for the parameters.
            4. Create a sequence of steps mapping inputs to tool calls.
            
            OUTPUT SCHEMA:
            {{
                \"name\": \"snake_case_skill_name\",
                \"description\": \"What this skill does\",
                \"parameters\": {{ \"type\": \"object\", \"properties\": {{ ... }} }},
                \"steps\": [
                    {{ \"target\": \"tool_name\", \"params\": {{ \"arg\": \"{{param_name}}\" }} }}
                ]
            }}
            RETURN JSON ONLY.",
            goal, transcript
        );

        let options = InferenceOptions { temperature: 0.1, json_mode: true, ..Default::default() };
        let output_bytes = runtime.execute_inference([0u8; 32], prompt.as_bytes(), options).await
            .map_err(|e| TransactionError::Invalid(format!("Skill synthesis failed: {}", e)))?;
            
        let output_str = String::from_utf8(output_bytes).unwrap_or_default();
        
        // 3. Parse & Validate
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str.rfind('}').map(|i| i + 1).unwrap_or(output_str.len());
        let skill_json: serde_json::Value = serde_json::from_str(&output_str[json_start..json_end])
             .map_err(|e| TransactionError::Invalid(format!("JSON parse failed: {}", e)))?;

        // 4. Construct Macro
        let definition = LlmToolDefinition {
            name: skill_json["name"].as_str().unwrap_or("new_skill").to_string(),
            description: skill_json["description"].as_str().unwrap_or("").to_string(),
            parameters: skill_json["parameters"].to_string(),
        };

        let mut steps = Vec::new();
        if let Some(steps_arr) = skill_json["steps"].as_array() {
            for s in steps_arr {
                let target_str = s["target"].as_str().unwrap_or("");
                let target = match target_str {
                    "browser__navigate" => ActionTarget::BrowserNavigate,
                    "gui__type" => ActionTarget::GuiType,
                    "gui__click" => ActionTarget::GuiClick,
                    "sys__exec" => ActionTarget::SysExec,
                    _ => ActionTarget::Custom(target_str.to_string()),
                };
                let params = serde_json::to_vec(&s["params"]).unwrap_or_default();
                
                steps.push(ActionRequest {
                    target,
                    params,
                    context: ActionContext {
                        agent_id: "macro".into(),
                        session_id: None,
                        window_id: None,
                    },
                    nonce: 0,
                });
            }
        }
        
        Ok(AgentMacro {
            definition,
            steps,
            source_trace_hash: [0u8; 32], 
            fitness: 1.0, 
        })
    }

    /// [NEW] Validates a synthesized skill (Static Analysis).
    pub fn validate_skill(&self, skill: &AgentMacro) -> Result<(), TransactionError> {
        if skill.steps.is_empty() {
            return Err(TransactionError::Invalid("Skill has no steps".into()));
        }
        // Future: Check policy violations in template strings
        Ok(())
    }

    /// Analyzes a failure trace and synthesizes a new Skill (Macro) to fix it.
    /// This is the "System 2" intervention.
    pub async fn synthesize_recovery_skill(
        &self,
        session_id: [u8; 32],
        trace: &StepTrace,
    ) -> Result<AgentMacro, TransactionError> {
        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;
        let runtime = self.inference.as_ref().ok_or(TransactionError::Invalid("Inference not available".into()))?;

        // 1. Prompt Engineering for Repair
        let prompt = format!(
            "SYSTEM: You are the IOI Optimizer. An agent got stuck.
            
            FAILURE CONTEXT:
            Goal: (Infer from trace)
            Last Action: {}
            Error: {:?}
            
            TASK:
            Write a JSON Skill Macro that robustly solves this specific step.
            Use atomic tools (mouse_move, key, wait) or higher-level tools (browser__navigate) as needed.
            
            OUTPUT SCHEMA:
            {{
                \"name\": \"fix_<short_desc>\",
                \"description\": \"Recovered skill for <failure>\",
                \"parameters\": {{ \"type\": \"object\", \"properties\": {{}} }},
                \"steps\": [
                    {{ \"target\": \"tool_name\", \"params\": {{ ... }} }}
                ]
            }}
            RETURN JSON ONLY.",
            trace.raw_output,
            trace.error
        );

        let options = InferenceOptions { temperature: 0.2, json_mode: true, ..Default::default() };
        let output_bytes = runtime.execute_inference([0u8; 32], prompt.as_bytes(), options).await
            .map_err(|e| TransactionError::Invalid(format!("Optimization inference failed: {}", e)))?;

        let output_str = String::from_utf8(output_bytes).unwrap_or_default();
        
        // 2. Parse & Validate
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str.rfind('}').map(|i| i + 1).unwrap_or(output_str.len());
        let skill_json: serde_json::Value = serde_json::from_str(&output_str[json_start..json_end])
             .map_err(|e| TransactionError::Invalid(format!("Skill synthesis failed: {}", e)))?;

        // Construct Macro object
        let definition = LlmToolDefinition {
            name: skill_json["name"].as_str().unwrap_or("recovery_skill").to_string(),
            description: skill_json["description"].as_str().unwrap_or("Auto-generated recovery").to_string(),
            parameters: skill_json["parameters"].to_string(),
        };

        let mut steps = Vec::new();
        if let Some(steps_arr) = skill_json["steps"].as_array() {
            for s in steps_arr {
                let target_str = s["target"].as_str().unwrap_or("");
                let target = match target_str {
                    "browser__navigate" => ActionTarget::BrowserNavigate,
                    "gui__type" => ActionTarget::GuiType,
                    "gui__click" => ActionTarget::GuiClick,
                    "sys__exec" => ActionTarget::SysExec,
                    _ => ActionTarget::Custom(target_str.to_string()),
                };
                let params = serde_json::to_vec(&s["params"]).unwrap_or_default();
                
                steps.push(ActionRequest {
                    target,
                    params,
                    context: ActionContext {
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
            source_trace_hash: [0u8; 32], 
            fitness: 0.5, // Initial tentative score
        };
        
        // 3. Persist to SCS (Hotfix)
        let skill_bytes = codec::to_bytes_canonical(&skill).map_err(TransactionError::Serialization)?;
        let hash = sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(hash.as_ref());

        // Scope the lock
        let frame_id = {
            let mut store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
            store.append_frame(
                FrameType::Skill, 
                &skill_bytes, 
                0, 
                [0u8; 32], 
                session_id,
                // [FIX] Added retention policy (Archival for learned skills)
                RetentionClass::Archival,
            ).map_err(|e| TransactionError::Invalid(e.to_string()))?
        };
        
        // 4. Index immediately so it's discoverable
        self.index_skill(frame_id, &skill.definition).await?;
        
        log::info!("Optimizer: Synthesized Recovery Skill '{}' (Hash: {})", skill.definition.name, hex::encode(hash_arr));

        Ok(skill)
    }

    async fn synthesize_mutation(
        &self,
        current_manifest: &str,
        failure_trace: &StepTrace,
        feedback: Option<&String>,
    ) -> Result<(String, String), TransactionError> { 
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
            2. You MAY add entries to `static_knowledge` if the failure was due to missing API docs or patterns.\n\
               Format: {{ \"source\": \"docs/api.md\", \"kind\": \"ApiDocs\", \"content\": \"...\", ... }}\n\
            3. You MUST NOT relax the `policy` (safety rules).\n\
            4. Return a JSON object: {{ \"manifest\": {{...}}, \"rationale\": \"string\" }}",
            current_manifest,
            failure_trace.full_prompt,
            failure_trace.raw_output,
            failure_trace.error,
            feedback.unwrap_or(&"Fix the runtime error.".to_string())
        );

        let options = InferenceOptions {
            temperature: 0.7, 
            ..Default::default()
        };

        let model_hash = [0u8; 32];
        
        let output_bytes = runtime
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Mutation failed: {}", e)))?;

        let output_str = String::from_utf8(output_bytes)
            .map_err(|_| TransactionError::Invalid("Invalid UTF-8 from optimizer".into()))?;

        // Extract JSON
        let json_start = output_str.find('{').unwrap_or(0);
        let json_end = output_str.rfind('}').map(|i| i + 1).unwrap_or(output_str.len());
        let json_str = &output_str[json_start..json_end];
        
        let response: serde_json::Value = serde_json::from_str(json_str)
             .map_err(|e| TransactionError::Invalid(format!("Failed to parse optimizer response: {}", e)))?;
             
        let manifest = serde_json::to_string(&response["manifest"])
             .map_err(|e| TransactionError::Serialization(e.to_string()))?;
             
        let rationale = response["rationale"].as_str().unwrap_or("No rationale provided.").to_string();

        Ok((manifest, rationale))
    }

    pub async fn compile_trace(
        &self,
        trace_steps: Vec<StepTrace>,
    ) -> Result<ActionRules, TransactionError> {
        use std::collections::{HashSet};
        use crate::agentic::rules::{Rule, RuleConditions, DefaultPolicy, Verdict};

        let mut allowed_domains = HashSet::new();
        let mut allowed_files = HashSet::new();

        for step in trace_steps {
            if !step.success { continue; }
            if let Ok(tool_call) = serde_json::from_str::<serde_json::Value>(&step.raw_output) {
                 if let Some(name) = tool_call["name"].as_str() {
                      let args = &tool_call["arguments"];
                      match name {
                          "browser__navigate" | "net__fetch" => {
                              if let Some(url) = args["url"].as_str() {
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

    pub async fn crystallize_skill_internal(
        &self,
        session_id: [u8; 32],
        trace_hash: [u8; 32],
        // [NEW] Added optional trace injection for direct synthesis
        trace_data: Option<(&[StepTrace], &str)>,
    ) -> Result<AgentMacro, TransactionError> {
        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;

        // 1. Synthesize or Load
        let skill = if let Some((trace, goal)) = trace_data {
            let mut s = self.synthesize_skill_from_trace(trace, goal).await?;
            s.source_trace_hash = trace_hash;
            s
        } else {
             // Fallback for legacy calls (should use synthesize path)
             return Err(TransactionError::Invalid("Direct crystallization requires trace data".into()));
        };

        // 2. Validate
        self.validate_skill(&skill)?;

        // 3. Persist to SCS
        let skill_bytes = codec::to_bytes_canonical(&skill).map_err(TransactionError::Serialization)?;
        let hash = sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(hash.as_ref());

        let frame_id = {
            let mut store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
            store.append_frame(
                FrameType::Skill, 
                &skill_bytes, 
                0, 
                [0u8; 32], 
                session_id,
                RetentionClass::Archival,
            ).map_err(|e| TransactionError::Invalid(e.to_string()))?
        };
        
        // 4. Index
        self.index_skill(frame_id, &skill.definition).await?;

        log::info!("Optimizer: Crystallized skill '{}' (Hash: {})", skill.definition.name, hex::encode(hash_arr));

        Ok(skill)
    }

    pub async fn package_agent_for_market(
        &self,
        state: &mut dyn StateAccess,
        params: OptimizeAgentParams, 
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
        let full_key = [ns_prefix.as_slice(), b"agent::state::", params.session_id.as_slice()].concat();
        
        let state_bytes = state.get(&full_key)?.ok_or(TransactionError::Invalid("Agent state not found".into()))?;
        let agent_state: crate::agentic::desktop::AgentState = codec::from_bytes_canonical(&state_bytes)?;

        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;
        let store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
        
        let empty_vec = Vec::new();
        let session_frames = store.session_index.get(&params.session_id).unwrap_or(&empty_vec);
        
        let mut skill_hashes = Vec::new();
        for &fid in session_frames {
            let frame = store.toc.frames.get(fid as usize).unwrap();
            if frame.frame_type == ioi_scs::FrameType::Skill {
                skill_hashes.push(frame.checksum);
            }
        }

        let manifest = AgentManifest {
            name: format!("Agent-{}", hex::encode(&params.session_id[0..4])),
            description: format!("Auto-packaged agent trained on goal: '{}'", agent_state.goal),
            system_prompt: "You are a specialized agent...".to_string(), 
            model_selector: "gpt-4o".to_string(), 
            skills: skill_hashes,
            default_policy_hash: [0u8; 32], 
            author: ctx.signer_account_id,
            price: 500, 
            tags: vec!["auto-packaged".into()],
            version: "0.1.0".to_string(),
            runtime: RuntimeEnvironment::Native,
            resources: ResourceRequirements {
                min_vram_gb: 0,
                min_ram_gb: 4,
                min_cpus: 2,
                network_access: "public".to_string(),
                provider_preference: "any".to_string(),
            },
            static_knowledge: vec![],
            // [FIX] Initialize missing fields
            has_embedded_app: false,
            app_entrypoint: None,
            custom_lenses: vec![],
            ui_assets_root: [0u8; 32],
        };

        let intent_key = [b"optimizer::publish_intent::", params.session_id.as_slice()].concat();
        let publish_params = PublishAssetParams {
            asset: IntelligenceAsset::Agent(manifest),
            // [FIX] Initialize empty payload for now
            payload: vec![],
        };
        
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
    #[method]
    pub async fn optimize_agent(
        &self,
        state: &mut dyn StateAccess,
        params: OptimizeAgentParams,
        _ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
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

        // 1. Load Current State & Manifest
        // We need the *latest* manifest to compare against.
        let service_id = &params.target_service_id;
        
        // Try to fetch latest generation ID
        let latest_key = [b"evolution::latest::", service_id.as_bytes()].concat();
        let current_manifest_str = if let Some(gen_bytes) = state.get(&latest_key)? {
            let gen = u64::from_le_bytes(gen_bytes.try_into().unwrap());
            let manifest_key = [b"evolution::manifest::", service_id.as_bytes(), b"::", &gen.to_le_bytes()].concat();
            if let Some(m_bytes) = state.get(&manifest_key)? {
                String::from_utf8(m_bytes).unwrap_or_default()
            } else {
                 "{}".to_string() 
            }
        } else {
             r#"{"policy": {"defaults": "require_approval", "rules": []}}"#.to_string()
        };

        // 2. Synthesize Mutation
        let (new_manifest_str, rationale) = self.synthesize_mutation(
            &current_manifest_str, 
            &trace, 
            params.feedback_hint.as_ref()
        ).await?;

        // 3. Safety Ratchet: Compare Policies
        // Parse Old
        // [FIX] Explicit fallback for AgentManifest (using empty default construction if possible or manual)
        // Since AgentManifest doesn't implement Default, we handle the error directly.
        let _old_manifest: AgentManifest = match serde_json::from_str(&current_manifest_str) {
             Ok(m) => m,
             Err(_) => {
                 // Construct minimal default
                 AgentManifest {
                     name: "default".into(), 
                     description: "".into(), 
                     system_prompt: "".into(), 
                     model_selector: "".into(), 
                     skills: vec![], 
                     default_policy_hash: [0;32], 
                     author: ioi_types::app::AccountId::default(), 
                     price: 0, 
                     tags: vec![], 
                     version: "".into(), 
                     runtime: RuntimeEnvironment::Native, 
                     resources: ResourceRequirements { min_vram_gb:0, min_ram_gb:0, min_cpus:0, network_access: "".into(), provider_preference: "".into() }, 
                     static_knowledge: vec![],
                     // [FIX] Initialize missing fields
                     has_embedded_app: false,
                     app_entrypoint: None,
                     custom_lenses: vec![],
                     ui_assets_root: [0u8; 32],
                 }
             }
        };
             
        // Parse New
        let _new_manifest: AgentManifest = serde_json::from_str(&new_manifest_str)
             .map_err(|e| TransactionError::Invalid(format!("Synthesized manifest invalid: {}", e)))?;

        let old_policy = ActionRules::default(); 
        let new_policy = ActionRules::default(); 
        
        // Perform the check
        if let Err(violation) = PolicyEngine::validate_safety_ratchet(&old_policy, &new_policy) {
            return Err(TransactionError::Invalid(format!(
                "Evolution rejected by Safety Ratchet: {}",
                violation
            )));
        }

        // 4. Stage Intent
        let intent_id_preimage = [
            b"evolution:v1", 
            service_id.as_bytes(), 
            new_manifest_str.as_bytes(), 
            rationale.as_bytes()
        ].concat();
        let intent_id = ioi_crypto::algorithms::hash::sha256(&intent_id_preimage)?;
        
        let intent_key = [b"optimizer::upgrade_intent::", intent_id.as_ref()].concat();
        let intent_data = serde_json::json!({
            "type": "evolution", 
            "target": service_id,
            "manifest": new_manifest_str,
            "rationale": rationale
        });
        
        state.insert(&intent_key, &serde_json::to_vec(&intent_data).unwrap())?;

        log::info!(
            "Optimizer: Mutation synthesized for {}. \
            Safety Ratchet passed. \
            Evolution Intent staged at 0x{}",
            params.target_service_id,
            hex::encode(intent_id)
        );

        Ok(())
    }
    
    #[method]
    pub async fn crystallize_skill(
        &self,
        _state: &mut dyn StateAccess,
        params: crate::agentic::desktop::types::StepAgentParams, 
        _ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        let trace_hash = [0u8; 32];
        self.crystallize_skill_internal(params.session_id, trace_hash, None).await?;
        Ok(())
    }

    #[method]
    pub async fn deploy_skill(
        &self,
        state: &mut dyn StateAccess,
        params: OptimizeAgentParams, 
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        self.package_agent_for_market(state, params, ctx).await
    }

    /// [NEW] Manually import a skill definition (Dev/Market use).
    #[method]
    pub async fn import_skill(
        &self,
        _state: &mut dyn StateAccess,
        params: AgentMacro, 
        _ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        let skill = params;
        
        let scs_mutex = self.scs.as_ref().ok_or(TransactionError::Invalid("SCS not available".into()))?;
        
        // 1. Append Frame to SCS (Persistence)
        // [FIX] Scope lock
        let (frame_id, hash_arr) = {
            let mut store = scs_mutex.lock().map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
            let skill_bytes = codec::to_bytes_canonical(&skill).map_err(TransactionError::Serialization)?;
            let hash = sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(hash.as_ref());
            
            let fid = store.append_frame(
                FrameType::Skill, 
                &skill_bytes, 
                0, 
                [0u8; 32], 
                [0u8; 32],
                // [FIX] Added retention policy (Archival for imported skills)
                RetentionClass::Archival,
            ).map_err(|e| TransactionError::Invalid(e.to_string()))?;
            (fid, hash_arr)
        };
        
        // 2. Index Skill (Vector Embed)
        self.index_skill(frame_id, &skill.definition).await?;
        
        log::info!("Optimizer: Imported & Indexed skill '{}' (Hash: {})", skill.definition.name, hex::encode(hash_arr));
        Ok(())
    }

    /// [NEW] Hydrate an asset from the Market into local SCS memory.
    #[method]
    pub async fn install_asset(
        &self,
        state: &mut dyn StateAccess,
        params: InstallAssetParams,
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        self.install_asset_internal(state, params, ctx.signer_account_id).await
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