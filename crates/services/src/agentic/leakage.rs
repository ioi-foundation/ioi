// Path: crates/services/src/agentic/leakage.rs

use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::any::Any;

// --- Constants & Keys ---
const LEAKAGE_USAGE_PREFIX: &[u8] = b"leakage::usage::";
const LEAKAGE_POLICY_PREFIX: &[u8] = b"leakage::policy::";

// --- Data Structures ---

/// Defines the leakage policy for a specific session or agent class.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct LeakagePolicy {
    /// Maximum tokens allowed per epoch (or session lifetime).
    pub max_tokens_per_epoch: u64,
    /// The cost multiplier for high-entropy data (e.g., PII-dense slices).
    /// Default is 100 (1.00x).
    pub entropy_multiplier_percent: u16,
}

impl Default for LeakagePolicy {
    fn default() -> Self {
        Self {
            max_tokens_per_epoch: 1_000_000, // Conservative default
            entropy_multiplier_percent: 100,
        }
    }
}

/// Tracks current usage for a session.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, Default)]
pub struct UsageRecord {
    pub tokens_consumed: u64,
    pub last_update_height: u64,
}

// --- Service Parameters ---

#[derive(Debug, Encode, Decode)]
pub struct RegisterPolicyParams {
    pub session_id: [u8; 32],
    pub policy: LeakagePolicy,
}

#[derive(Debug, Encode, Decode)]
pub struct CheckLeakageParams {
    pub session_id: [u8; 32],
    pub tokens_requested: u64,
    pub is_high_entropy: bool,
}

/// The Leakage Controller Service.
/// Enforces limits on context export to prevent massive data exfiltration.
#[derive(Debug, Default)]
pub struct LeakageController;

// REMOVED: impl_service_base!(LeakageController, "leakage_controller");

#[async_trait::async_trait]
impl UpgradableService for LeakageController {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl LeakageController {
    fn get_usage_key(session_id: &[u8; 32]) -> Vec<u8> {
        [LEAKAGE_USAGE_PREFIX, session_id.as_slice()].concat()
    }

    fn get_policy_key(session_id: &[u8; 32]) -> Vec<u8> {
        [LEAKAGE_POLICY_PREFIX, session_id.as_slice()].concat()
    }

    /// Internal logic to check and debit the budget.
    fn debit_budget(
        state: &mut dyn StateAccess,
        session_id: &[u8; 32],
        tokens: u64,
        is_high_entropy: bool,
        current_height: u64,
    ) -> Result<(), TransactionError> {
        let policy_key = Self::get_policy_key(session_id);
        let usage_key = Self::get_usage_key(session_id);

        // 1. Load Policy
        let policy: LeakagePolicy = if let Some(bytes) = state.get(&policy_key)? {
            codec::from_bytes_canonical(&bytes)?
        } else {
            // Default policy if none registered
            LeakagePolicy::default()
        };

        // 2. Calculate Cost
        let multiplier = if is_high_entropy {
            policy.entropy_multiplier_percent as u64
        } else {
            100
        };
        let cost = (tokens * multiplier) / 100;

        // 3. Load Usage
        let mut usage: UsageRecord = if let Some(bytes) = state.get(&usage_key)? {
            codec::from_bytes_canonical(&bytes)?
        } else {
            UsageRecord::default()
        };

        // 4. Enforce Limit
        let new_total = usage.tokens_consumed.saturating_add(cost);
        
        if new_total > policy.max_tokens_per_epoch {
            return Err(TransactionError::Invalid(format!(
                "Leakage budget exceeded: Requested {}, Cost {}, Used {}, Limit {}",
                tokens, cost, usage.tokens_consumed, policy.max_tokens_per_epoch
            )));
        }

        // 5. Update State
        usage.tokens_consumed = new_total;
        usage.last_update_height = current_height;
        
        state.insert(&usage_key, &codec::to_bytes_canonical(&usage)?)?;
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl BlockchainService for LeakageController {
    fn id(&self) -> &str {
        "leakage_controller"
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
            "register_policy@v1" => {
                let p: RegisterPolicyParams = codec::from_bytes_canonical(params)?;
                let key = Self::get_policy_key(&p.session_id);
                // Allow overwrite/update
                state.insert(&key, &codec::to_bytes_canonical(&p.policy)?)?;
                Ok(())
            }
            "check_and_debit@v1" => {
                let p: CheckLeakageParams = codec::from_bytes_canonical(params)?;
                Self::debit_budget(
                    state,
                    &p.session_id,
                    p.tokens_requested,
                    p.is_high_entropy,
                    ctx.block_height,
                )
            }
            _ => Err(TransactionError::Unsupported(format!(
                "Method '{}' not supported by LeakageController",
                method
            ))),
        }
    }
}