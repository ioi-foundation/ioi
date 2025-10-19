// Path: crates/types/src/service_configs/mod.rs
//! Configuration structures for initial services.

use crate::app::SignatureSuite;
use crate::error::CoreError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Configuration for the IdentityHub service.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MigrationConfig {
    /// The number of blocks after a key rotation is initiated before the new key is promoted to active.
    pub grace_period_blocks: u64,
    /// If true, signatures from the new (staged) key are accepted during the grace period.
    pub accept_staged_during_grace: bool,
    /// A list of signature suites that accounts are allowed to rotate to.
    pub allowed_target_suites: Vec<SignatureSuite>,
    /// If true, allows rotating to a cryptographically weaker signature suite (e.g., from Dilithium back to Ed25519).
    pub allow_downgrade: bool,
    /// The unique identifier of the chain, used to prevent cross-chain replay attacks on rotation proofs.
    pub chain_id: u32,
}

/// Configuration parameters for the Governance service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParams {
    /// The minimum deposit required to submit a proposal.
    pub min_deposit: u64,
    /// The maximum duration, in blocks, that a proposal can remain in the deposit period.
    pub max_deposit_period_blocks: u64,
    /// The duration of the voting period in blocks.
    pub voting_period_blocks: u64,
    /// The percentage of total voting power that must participate for a proposal to be considered valid (e.g., 33 for 33%).
    pub quorum: u8,
    /// The percentage of non-abstaining votes that must be 'Yes' for a proposal to pass (e.g., 50 for >50%).
    pub threshold: u8,
    /// The percentage of non-abstaining votes that can be 'NoWithVeto' before a proposal is immediately rejected (e.g., 33 for >33%).
    pub veto_threshold: u8,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            min_deposit: 10000,
            max_deposit_period_blocks: 20160, // ~14 days at 60s/block
            voting_period_blocks: 20160,      // ~14 days
            quorum: 33,
            threshold: 50,
            veto_threshold: 33,
        }
    }
}

bitflags::bitflags! {
    /// A bitmask representing the capabilities (hooks) a service exposes.
    #[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
    #[serde(transparent)]
    pub struct Capabilities: u32 {
        /// Implements the TxDecorator trait and its ante_handle hook.
        const TX_DECORATOR = 0b0001;
        /// Implements the OnEndBlock trait and its on_end_block hook.
        const ON_END_BLOCK = 0b0010;
        /// Implements the IbcPayloadHandler trait.
        const IBC_HANDLER  = 0b0100;
    }
}

// --- FIX START: Manual SCALE codec implementation for bitflags struct ---
impl Encode for Capabilities {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        self.bits().encode_to(dest)
    }
}

impl Decode for Capabilities {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let bits = u32::decode(input)?;
        Self::from_bits(bits).ok_or_else(|| "Invalid bits for Capabilities".into())
    }
}
// --- FIX END ---

impl Capabilities {
    /// Parses a list of capability strings into a bitmask.
    pub fn from_strings(strings: &[String]) -> Result<Self, CoreError> {
        let mut caps = Capabilities::empty();
        for s in strings {
            match s.as_str() {
                "TxDecorator" => caps |= Capabilities::TX_DECORATOR,
                "OnEndBlock" => caps |= Capabilities::ON_END_BLOCK,
                "IbcPayloadHandler" => caps |= Capabilities::IBC_HANDLER,
                _ => return Err(CoreError::Upgrade(format!("Unknown capability: {}", s))),
            }
        }
        Ok(caps)
    }
}

/// The canonical on-chain record of an active service, used for crash-safe recovery.
#[derive(Serialize, Deserialize, Encode, Decode, Clone, Debug)]
pub struct ActiveServiceMeta {
    /// The unique identifier for the service.
    pub id: String,
    /// The ABI version the service was compiled against.
    pub abi_version: u32,
    /// The state schema version the service uses.
    pub state_schema: String,
    /// The capabilities the service implements.
    pub caps: Capabilities,
    /// The hash of the artifact (e.g., WASM bytecode) for this service.
    pub artifact_hash: [u8; 32],
    /// The block height at which this service version was activated.
    pub activated_at: u64,
}
