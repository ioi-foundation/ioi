// Path: crates/services/src/provider_registry/mod.rs
use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use std::any::Any;

// Canonical prefix for provider records: providers::{account_id}
const PROVIDER_PREFIX: &[u8] = b"providers::";
// Canonical prefix for heartbeat timestamps: heartbeats::{account_id}::{model_hash}
const HEARTBEAT_PREFIX: &[u8] = b"heartbeats::";

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum SupplyTier {
    /// Tier 0: Foundation / Partner Nodes (Managed Supply).
    Foundation,
    /// Tier 1: Verified DePIN (Pro Supply).
    Verified,
    /// Tier 2: Community / Spot (Open Supply).
    Community,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct ProviderRecord {
    pub tier: SupplyTier,
    pub endpoint: String,
    pub capabilities: Vec<String>, // e.g. "gpu-h100", "verkle-proofs"
    pub stake: u128,
    pub status: ProviderStatus,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Active,
    Jailed,
    Slashed,
}

#[derive(Encode, Decode)]
pub struct RegisterProviderParams {
    pub tier: SupplyTier,
    pub endpoint: String,
    pub capabilities: Vec<String>,
}

#[derive(Encode, Decode)]
pub struct HeartbeatParams {
    pub model_hash: [u8; 32],
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ProviderRegistryService;

#[async_trait]
impl UpgradableService for ProviderRegistryService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait]
impl BlockchainService for ProviderRegistryService {
    fn id(&self) -> &str {
        "provider_registry"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "v1"
    }

    fn capabilities(&self) -> ioi_types::service_configs::Capabilities {
        ioi_types::service_configs::Capabilities::empty()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "register@v1" => {
                let p: RegisterProviderParams = codec::from_bytes_canonical(params)?;

                // Enforce minimum stake for Tier 1
                if p.tier == SupplyTier::Verified {
                    // TODO: Check actual staked balance via Staking/Bank service.
                    // For Phase 1, we assume the caller has locked funds via `SettlementPayload::Bond`.
                }

                let provider_id = ctx.signer_account_id;
                let key = [PROVIDER_PREFIX, provider_id.as_ref()].concat();

                if state.get(&key)?.is_some() {
                    return Err(TransactionError::Invalid(
                        "Provider already registered".into(),
                    ));
                }

                let record = ProviderRecord {
                    tier: p.tier,
                    endpoint: p.endpoint,
                    capabilities: p.capabilities,
                    stake: 0, // Should be updated by bond logic
                    status: ProviderStatus::Active,
                };

                state.insert(&key, &codec::to_bytes_canonical(&record)?)?;
                Ok(())
            }

            "heartbeat@v1" => {
                // Proof of Readiness (Warm Start)
                let p: HeartbeatParams = codec::from_bytes_canonical(params)?;

                // Validate timestamp freshness (prevent replay of old heartbeats)
                // [FIX] Convert nanoseconds (u64) to seconds for comparison
                let now = ctx.block_timestamp / 1_000_000_000;
                
                if p.timestamp > now + 10 || p.timestamp < now - 60 {
                    return Err(TransactionError::Invalid(
                        "Heartbeat timestamp out of bounds".into(),
                    ));
                }

                let provider_id = ctx.signer_account_id;
                let key = [HEARTBEAT_PREFIX, provider_id.as_ref(), b"::", &p.model_hash].concat();

                // Store last heartbeat time. This allows the Matching Engine to filter for "Warm" nodes.
                state.insert(&key, &p.timestamp.to_le_bytes())?;
                Ok(())
            }

            _ => Err(TransactionError::Unsupported(format!(
                "ProviderRegistry does not support method '{}'",
                method
            ))),
        }
    }
}