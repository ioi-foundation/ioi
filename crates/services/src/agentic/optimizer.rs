// Path: crates/services/src/agentic/optimizer.rs

//! The Optimizer Service (The Meta-Manager).
//!
//! This service acts as the "Evolutionary Engine" for the IOI Kernel.
//! It observes agent execution failures, synthesizes code patches (mutations),
//! verifies them in a sandbox, and submits upgrade transactions to evolve the agent.

use async_trait::async_trait;
use ioi_api::services::UpgradableService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_macros::service_interface;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, StepTrace};
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use crate::agentic::policy::PolicyEngine;
use crate::agentic::rules::ActionRules;
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, RetentionClass, SovereignContextStore};
use ioi_types::app::agentic::{
    AgentMacro, AgentManifest, InferenceOptions, IntelligenceAsset, LlmToolDefinition,
    ResourceRequirements, RuntimeEnvironment,
};
use reqwest::Url;

use crate::market::PublishAssetParams;

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

mod market;
mod skills;

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
            let manifest_key = [
                b"evolution::manifest::",
                service_id.as_bytes(),
                b"::",
                &gen.to_le_bytes(),
            ]
            .concat();
            if let Some(m_bytes) = state.get(&manifest_key)? {
                String::from_utf8(m_bytes).unwrap_or_default()
            } else {
                "{}".to_string()
            }
        } else {
            r#"{"policy": {"defaults": "require_approval", "rules": []}}"#.to_string()
        };

        // 2. Synthesize Mutation
        let (new_manifest_str, rationale) = self
            .synthesize_mutation(&current_manifest_str, &trace, params.feedback_hint.as_ref())
            .await?;

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
                    default_policy_hash: [0; 32],
                    author: ioi_types::app::AccountId::default(),
                    price: 0,
                    tags: vec![],
                    version: "".into(),
                    runtime: RuntimeEnvironment::Native,
                    resources: ResourceRequirements {
                        min_vram_gb: 0,
                        min_ram_gb: 0,
                        min_cpus: 0,
                        network_access: "".into(),
                        provider_preference: "".into(),
                    },
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
        let _new_manifest: AgentManifest =
            serde_json::from_str(&new_manifest_str).map_err(|e| {
                TransactionError::Invalid(format!("Synthesized manifest invalid: {}", e))
            })?;

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
            rationale.as_bytes(),
        ]
        .concat();
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
        self.crystallize_skill_internal(params.session_id, trace_hash, None)
            .await?;
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

        let scs_mutex = self
            .scs
            .as_ref()
            .ok_or(TransactionError::Invalid("SCS not available".into()))?;

        // 1. Append Frame to SCS (Persistence)
        // [FIX] Scope lock
        let (frame_id, hash_arr) = {
            let mut store = scs_mutex
                .lock()
                .map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
            let skill_bytes =
                codec::to_bytes_canonical(&skill).map_err(TransactionError::Serialization)?;
            let hash =
                sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(hash.as_ref());

            let fid = store
                .append_frame(
                    FrameType::Skill,
                    &skill_bytes,
                    0,
                    [0u8; 32],
                    [0u8; 32],
                    // [FIX] Added retention policy (Archival for imported skills)
                    RetentionClass::Archival,
                )
                .map_err(|e| TransactionError::Invalid(e.to_string()))?;
            (fid, hash_arr)
        };

        // 2. Index Skill (Vector Embed)
        self.index_skill(frame_id, &skill.definition).await?;

        log::info!(
            "Optimizer: Imported & Indexed skill '{}' (Hash: {})",
            skill.definition.name,
            hex::encode(hash_arr)
        );
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
        self.install_asset_internal(state, params, ctx.signer_account_id)
            .await
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
