// Path: crates/services/src/market/mod.rs

use async_trait::async_trait;
use ioi_api::services::UpgradableService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_macros::service_interface;
use ioi_types::{
    // [NEW] Unified Asset Types
    app::agentic::{AssetLicense, AssetType, IntelligenceAsset},
    app::AccountId,
    codec,
    error::TransactionError,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

// [NEW] Export licensing module
pub mod licensing;
pub mod router;

// --- Storage Prefixes ---
// Consolidated namespace for all market activities
const ASSET_REGISTRY_PREFIX: &[u8] = b"market::asset::";
// [NEW] Prefix for storing the actual executable content (Blob)
const ASSET_PAYLOAD_PREFIX: &[u8] = b"market::payload::";
const LICENSE_PREFIX: &[u8] = b"market::license::";
const TICKET_PREFIX: &[u8] = b"market::ticket::";
const BALANCE_PREFIX: &[u8] = b"balance::";

// --- Service Parameters ---

#[derive(Encode, Decode)]
pub struct PublishAssetParams {
    /// The metadata manifest (Pricing, Author, Tags).
    pub asset: IntelligenceAsset,
    /// The raw executable content (e.g. serialized AgentMacro, or WASM bytes).
    /// This is what gets "Installed" by the buyer.
    pub payload: Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct PurchaseLicenseParams {
    pub asset_hash: [u8; 32],
}

/// The specific requirements for a hardware task (Legacy Compute Support).
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ComputeSpecs {
    pub provider_type: String,
    pub capability_id: String,
    pub region: String,
}

/// A Job Ticket is now just a specific type of "Service Request" within the Market.
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

// Re-use ProvisioningReceipt for compute settlement compatibility
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct ProvisioningReceipt {
    pub request_id: u64,
    pub ticket_root: [u8; 32],
    pub provider_id: Vec<u8>,
    pub endpoint_uri: String,
    pub instance_id: String,
    pub provider_signature: Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct DeployAgentParams {
    pub asset_hash: [u8; 32],
    pub provider_override: Option<String>,
}

/// The Universal Market Service.
/// Handles the listing, discovery, and settlement of both Intelligence and Compute.
#[derive(Default, Debug)]
pub struct MarketService;

#[async_trait]
impl UpgradableService for MarketService {
    async fn prepare_upgrade(
        &self,
        _new: &[u8],
    ) -> Result<Vec<u8>, ioi_types::error::UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snap: &[u8]) -> Result<(), ioi_types::error::UpgradeError> {
        Ok(())
    }
}

#[service_interface(id = "market", abi_version = 1, state_schema = "v1")]
impl MarketService {
    // --- INTELLIGENCE ASSETS (Software/Agents) ---

    /// Registers a Skill, Agent, or Swarm in the global marketplace.
    #[method]
    pub fn publish_asset(
        &self,
        state: &mut dyn StateAccess,
        params: PublishAssetParams,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        // 1. Compute Asset Identity from Manifest
        let asset_bytes = codec::to_bytes_canonical(&params.asset)?;
        let asset_hash_res = sha256(&asset_bytes)?;
        let mut asset_hash = [0u8; 32];
        asset_hash.copy_from_slice(asset_hash_res.as_ref());

        // 2. Check Collision
        let registry_key = [ASSET_REGISTRY_PREFIX, &asset_hash].concat();
        if state.get(&registry_key)?.is_some() {
            return Err(TransactionError::Invalid("Asset already registered".into()));
        }

        // 3. Verify Ownership / Metadata
        let (author, _price, asset_type) = match &params.asset {
            IntelligenceAsset::Skill(m) => (m.author, m.price, AssetType::Skill),
            IntelligenceAsset::Agent(m) => (m.author, m.price, AssetType::Agent),
            IntelligenceAsset::Swarm(m) => (m.author, m.price, AssetType::Swarm),
        };

        if author != ctx.signer_account_id {
            return Err(TransactionError::Invalid(
                "Signer must be asset author".into(),
            ));
        }

        // 4. Verify Payload Integrity
        // The manifest must refer to this payload.
        // For Skills: The SkillManifest.skill_hash must match SHA256(payload).
        // The payload is expected to be a serialized `AgentMacro`.
        if let IntelligenceAsset::Skill(m) = &params.asset {
            let payload_hash = sha256(&params.payload)?;
            if payload_hash.as_ref() != m.skill_hash {
                return Err(TransactionError::Invalid(format!(
                    "Payload integrity failed. Manifest expects {}, got {}",
                    hex::encode(m.skill_hash),
                    hex::encode(payload_hash)
                )));
            }
        }

        // 5. Persist Manifest
        state.insert(&registry_key, &asset_bytes)?;

        // 6. Persist Payload (The "Install File")
        let payload_key = [ASSET_PAYLOAD_PREFIX, &asset_hash].concat();
        state.insert(&payload_key, &params.payload)?;

        log::info!(
            "Market: Published new {:?} with hash 0x{} (Payload: {} bytes)",
            asset_type,
            hex::encode(&asset_hash),
            params.payload.len()
        );
        Ok(())
    }

    /// Purchases a license to use an asset (Hire the Agent / Buy the Skill).
    #[method]
    pub fn purchase_license(
        &self,
        state: &mut dyn StateAccess,
        params: PurchaseLicenseParams,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        // 1. Fetch Asset Manifest
        let asset_key = [ASSET_REGISTRY_PREFIX, &params.asset_hash].concat();
        let asset_bytes = state
            .get(&asset_key)?
            .ok_or(TransactionError::Invalid("Asset not found".into()))?;
        let asset: IntelligenceAsset = codec::from_bytes_canonical(&asset_bytes)?;

        // 2. Determine Price & Type
        let (price, asset_type, author) = match &asset {
            IntelligenceAsset::Skill(m) => (m.price, AssetType::Skill, m.author),
            IntelligenceAsset::Agent(m) => (m.price, AssetType::Agent, m.author),
            IntelligenceAsset::Swarm(m) => (m.price, AssetType::Swarm, m.author),
        };

        // 3. Settlement (Atomic Transfer)
        if price > 0 {
            self.transfer_funds(state, ctx.signer_account_id, author, price)?;
        }

        // 4. Mint License
        let license = AssetLicense {
            asset_hash: params.asset_hash,
            asset_type,
            licensee: ctx.signer_account_id,
            purchase_height: ctx.block_height,
            expiry: 0, // Permanent / Lifetime license for MVP
        };

        let license_key = [
            LICENSE_PREFIX,
            ctx.signer_account_id.as_ref(),
            b"::",
            &params.asset_hash,
        ]
        .concat();

        state.insert(&license_key, &codec::to_bytes_canonical(&license)?)?;

        log::info!(
            "Market: License issued for asset 0x{} to 0x{}",
            hex::encode(&params.asset_hash),
            hex::encode(&ctx.signer_account_id.as_ref()[..4])
        );

        Ok(())
    }

    /// [NEW] Deploys an Agent to Cloud Infrastructure.
    #[method]
    pub fn deploy_agent(
        &self,
        state: &mut dyn StateAccess,
        params: DeployAgentParams,
        ctx: &TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // 1. Verify License Ownership
        let license_key = [
            LICENSE_PREFIX,
            ctx.signer_account_id.as_ref(),
            b"::",
            &params.asset_hash,
        ]
        .concat();

        if state.get(&license_key)?.is_none() {
            return Err(TransactionError::Invalid(
                "No license found for this asset".into(),
            ));
        }

        // 2. Fetch Agent Manifest
        let asset_key = [ASSET_REGISTRY_PREFIX, &params.asset_hash].concat();
        let asset_bytes = state
            .get(&asset_key)?
            .ok_or(TransactionError::Invalid("Asset manifest not found".into()))?;
        let asset: IntelligenceAsset = codec::from_bytes_canonical(&asset_bytes)?;

        // Ensure it's an Agent
        match asset {
            IntelligenceAsset::Agent(_) => {}
            _ => {
                return Err(TransactionError::Invalid(
                    "Asset is not directly deployable (not an Agent)".into(),
                ))
            }
        };

        // 3. Dispatch to Router
        let ticket_id = self.next_id(state)?;
        let ticket_key = [TICKET_PREFIX, &ticket_id.to_be_bytes()].concat();
        state.insert(&ticket_key, &asset_bytes)?;

        log::info!(
            "Market: Deployment ticket #{} created for agent 0x{}",
            ticket_id,
            hex::encode(&params.asset_hash)
        );

        Ok(())
    }

    // --- INFRASTRUCTURE ASSETS (Hardware/Compute) ---

    #[method]
    pub fn request_compute(
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
        let key = [TICKET_PREFIX, &id.to_be_bytes()].concat();
        state.insert(&key, &codec::to_bytes_canonical(&ticket)?)?;
        Ok(())
    }

    #[method]
    pub fn settle_compute(
        &self,
        state: &mut dyn StateAccess,
        params: ProvisioningReceipt,
        _ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let key = [TICKET_PREFIX, &params.request_id.to_be_bytes()].concat();
        if state.get(&key)?.is_none() {
            return Err(TransactionError::Invalid(
                "Ticket not found or already settled".into(),
            ));
        }
        state.delete(&key)?;
        Ok(())
    }

    // --- Helpers ---

    fn next_id(&self, state: &mut dyn StateAccess) -> Result<u64, TransactionError> {
        let key = b"market::next_ticket_id";
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

    fn transfer_funds(
        &self,
        state: &mut dyn StateAccess,
        from: AccountId,
        to: AccountId,
        amount: u64,
    ) -> Result<(), TransactionError> {
        let from_key = [BALANCE_PREFIX, from.as_ref()].concat();
        let to_key = [BALANCE_PREFIX, to.as_ref()].concat();

        let from_bal: u128 = state
            .get(&from_key)?
            .and_then(|b| codec::from_bytes_canonical(&b).ok())
            .unwrap_or(0);

        if from_bal < amount as u128 {
            return Err(TransactionError::InsufficientFunds);
        }

        let new_from = from_bal - amount as u128;
        state.insert(&from_key, &codec::to_bytes_canonical(&new_from)?)?;

        let to_bal: u128 = state
            .get(&to_key)?
            .and_then(|b| codec::from_bytes_canonical(&b).ok())
            .unwrap_or(0);
        let new_to = to_bal + amount as u128;
        state.insert(&to_key, &codec::to_bytes_canonical(&new_to)?)?;

        Ok(())
    }
}
