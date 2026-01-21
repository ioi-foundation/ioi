// Path: crates/services/src/compute_market/mod.rs
use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
// [FIX] Removed unused hash import
use ioi_macros::service_interface;
use ioi_types::{
    app::AccountId, // [FIX] Removed ChainTransaction
    codec,
    error::TransactionError,
    // [FIX] Removed unused active_service_key
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

// --- Canonical Data Structures ---

/// The specific requirements for the external compute task.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ComputeSpecs {
    /// The class of provider required (e.g. "bare-metal", "api-gateway").
    pub provider_type: String,
    /// The specific model or capability required (e.g. "gpu-h100", "gpt-4o").
    pub capability_id: String,
    /// Geographic or network region preference.
    pub region: String,
}

/// The immutable, on-chain record of a compute request.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct JobTicket {
    pub request_id: u64,
    pub owner: AccountId,
    pub specs: ComputeSpecs,
    pub max_bid: u64,
    pub expiry_height: u64,
    pub security_tier: u8,
    pub nonce: u64,
}

/// The proof submitted by a Provider (Centralized or Decentralized) to claim payment.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct ProvisioningReceipt {
    pub request_id: u64,
    pub ticket_root: [u8; 32],
    pub provider_id: Vec<u8>,
    pub endpoint_uri: String,
    pub instance_id: String,
    pub provider_signature: Vec<u8>,
}

#[derive(Default, Debug)]
pub struct ComputeMarketService;

#[async_trait]
impl UpgradableService for ComputeMarketService {
    async fn prepare_upgrade(
        &self,
        _new_module_wasm: &[u8],
    ) -> Result<Vec<u8>, ioi_types::error::UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(
        &self,
        _snapshot: &[u8],
    ) -> Result<(), ioi_types::error::UpgradeError> {
        Ok(())
    }
}

#[service_interface(id = "compute_market", abi_version = 1, state_schema = "v1")]
impl ComputeMarketService {
    /// Dispatches a new task request to the market.
    #[method]
    pub fn request_task(
        &self,
        state: &mut dyn StateAccess,
        params: ComputeSpecs,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let id = self.next_id(state)?;
        let ticket = JobTicket {
            request_id: id,
            owner: ctx.signer_account_id,
            specs: params,
            max_bid: 1000,
            expiry_height: ctx.block_height + 600,
            security_tier: 1,
            nonce: 0,
        };
        let key = format!("tickets::{}", id).into_bytes();
        state.insert(&key, &codec::to_bytes_canonical(&ticket)?)?;
        Ok(())
    }

    /// Settles a completed provisioning request.
    #[method]
    pub fn finalize_provisioning(
        &self,
        state: &mut dyn StateAccess,
        params: ProvisioningReceipt,
        _ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let key = format!("tickets::{}", params.request_id).into_bytes();
        // Atomic settlement: ticket is removed when provisioning is finalized.
        state.delete(&key)?;
        Ok(())
    }

    // Internal helper for ID generation
    fn next_id(&self, state: &mut dyn StateAccess) -> Result<u64, TransactionError> {
        let key = b"compute::next_id";
        let id = state
            .get(key)?
            .map(|b| {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&b);
                u64::from_le_bytes(arr)
            })
            .unwrap_or(1);

        state.insert(key, &(id + 1).to_le_bytes())?;
        Ok(id)
    }
}