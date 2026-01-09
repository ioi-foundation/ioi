// Path: crates/services/src/compute_market/mod.rs
use ioi_api::{impl_service_base, services::BlockchainService, state::StateAccess};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::{
    app::{AccountId, ChainTransaction},
    codec,
    error::TransactionError,
    keys::active_service_key,
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
    pub instance_id: String, // Unique execution ID from AWS/Akash
    pub provider_signature: Vec<u8>,
}

pub struct ComputeMarketService;
impl_service_base!(ComputeMarketService, "compute_market");

#[async_trait::async_trait]
impl ioi_api::services::UpgradableService for ComputeMarketService {
    async fn prepare_upgrade(&self, _: &[u8]) -> Result<Vec<u8>, ioi_types::error::UpgradeError> {
        Ok(vec![])
    }
    async fn complete_upgrade(&self, _: &[u8]) -> Result<(), ioi_types::error::UpgradeError> {
        Ok(())
    }
}

impl BlockchainService for ComputeMarketService {
    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut ioi_api::transaction::context::TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "request_task@v1" => {
                let req: ComputeSpecs = codec::from_bytes_canonical(params)?;
                let id = self.next_id(state)?;
                let ticket = JobTicket {
                    request_id: id,
                    owner: ctx.signer_account_id,
                    specs: req,
                    max_bid: 1000,
                    expiry_height: ctx.block_height + 600,
                    security_tier: 1,
                    nonce: 0,
                };
                let key = format!("tickets::{}", id).into_bytes();
                state.insert(&key, &codec::to_bytes_canonical(&ticket)?)?;
                Ok(())
            }
            "finalize_provisioning@v1" => {
                let receipt: ProvisioningReceipt = codec::from_bytes_canonical(params)?;
                let key = format!("tickets::{}", receipt.request_id).into_bytes();
                state.delete(&key)?; // Atomic settlement
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}

impl ComputeMarketService {
    fn next_id(&self, state: &mut dyn StateAccess) -> Result<u64, TransactionError> {
        let key = b"compute::next_id";
        let id = state
            .get(key)?
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(1);
        state.insert(key, &(id + 1).to_le_bytes())?;
        Ok(id)
    }
}
