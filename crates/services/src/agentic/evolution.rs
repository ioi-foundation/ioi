// Path: crates/services/src/agentic/evolution.rs

//! The Evolution Service.
//!
//! Handles "Sovereign Updates" for local agents. Unlike `Governance`, which requires
//! consensus voting for network-wide changes, `Evolution` allows an owner to
//! atomically upgrade their own agents/services without permission from the network.

use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_macros::service_interface;
use ioi_types::app::agentic::AgentManifest;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Parameters to evolve a specific agent.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct EvolveAgentParams {
    /// The ID of the service/agent to upgrade.
    pub target_service_id: String,
    /// The new manifest JSON string.
    pub new_manifest: String,
    /// The rationale/reason for this evolution (audit trail).
    pub rationale: String,
}

#[derive(Default, Debug, Clone)]
pub struct EvolutionService;

#[async_trait]
impl UpgradableService for EvolutionService {
    async fn prepare_upgrade(&self, _new: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snap: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[service_interface(
    id = "evolution",
    abi_version = 1,
    state_schema = "v1",
    capabilities = ""
)]
impl EvolutionService {
    /// Atomically upgrades an agent if the signer is the owner/author.
    #[method]
    pub fn evolve(
        &self,
        state: &mut dyn StateAccess,
        params: EvolveAgentParams,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let service_id = &params.target_service_id;

        // 1. Fetch Current Metadata
        let meta_key = active_service_key(service_id);
        let meta_bytes = state
            .get(&meta_key)?
            .ok_or(TransactionError::Invalid(format!(
                "Target service '{}' not found",
                service_id
            )))?;

        let mut meta: ActiveServiceMeta = codec::from_bytes_canonical(&meta_bytes)?;

        // 2. Authorization Check (Sovereignty)
        // Only the documented author can evolve the agent.
        if let Some(author) = meta.author {
            if author != ctx.signer_account_id {
                return Err(TransactionError::UnauthorizedByCredentials);
            }
        } else {
            // If no author is set (e.g. system service), we default to fail-safe or governance check.
            // For now, strict fail-safe: unowned agents cannot be evolved by users.
            return Err(TransactionError::Invalid("Service has no owner".into()));
        }

        // 3. Verify Manifest Validity & Parse
        // We enforce that the new config parses as a valid AgentManifest.
        let _new_manifest_struct: AgentManifest = serde_json::from_str(&params.new_manifest)
            .map_err(|e| TransactionError::Invalid(format!("Invalid new manifest JSON: {}", e)))?;

        // 4. Update Evolution State (Versioned Storage)
        let new_gen = meta.generation_id + 1;

        // Canonical Key: evolution::manifest::{service_id}::{gen}
        let manifest_key = [
            b"evolution::manifest::",
            service_id.as_bytes(),
            b"::",
            &new_gen.to_le_bytes(),
        ]
        .concat();
        state.insert(&manifest_key, params.new_manifest.as_bytes())?;

        // Pointer Key: evolution::latest::{service_id} -> gen
        let latest_key = [b"evolution::latest::", service_id.as_bytes()].concat();
        state.insert(&latest_key, &new_gen.to_le_bytes())?;

        // Rationale Key: evolution::rationale::{service_id}::{gen}
        let rationale_key = [
            b"evolution::rationale::",
            service_id.as_bytes(),
            b"::",
            &new_gen.to_le_bytes(),
        ]
        .concat();
        state.insert(&rationale_key, params.rationale.as_bytes())?;

        // 5. Update Active Metadata
        meta.generation_id = new_gen;
        // In a real system, we'd hash the manifest. For now, we update the meta record.
        // Ideally, `artifact_hash` should reflect the new logic if code changed, but here we just update manifest.
        state.insert(&meta_key, &codec::to_bytes_canonical(&meta)?)?;

        log::info!(
            "Evolution: Evolved agent '{}' to Gen {}. Owner: 0x{}",
            service_id,
            new_gen,
            hex::encode(ctx.signer_account_id)
        );

        Ok(())
    }
}
