// Path: crates/types/src/config/consensus.rs
//! Configuration related to consensus engines.

use serde::{Deserialize, Serialize};

/// The type of consensus engine to use.
/// This enum lives in `ioi-types` to avoid a circular dependency
/// between the `validator` crate (which reads it from config) and the
/// `consensus` crate (which uses it to dispatch logic).
// --- FIX START: Add Copy trait ---
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
// --- FIX END ---
#[serde(rename_all = "PascalCase")]
pub enum ConsensusType {
    /// Proof of Stake consensus.
    ProofOfStake,
    /// Proof of Authority consensus.
    ProofOfAuthority,
    /// Aft Fault Tolerance consensus family.
    Aft,
    /// Single-authority immediate ordering with no quorum round.
    ///
    /// The local node is the sole ordering authority: it proposes, orders and
    /// finalizes in one step, so a block is final the moment it is produced.
    /// This is NOT a degenerate AFT configuration and must never be reported
    /// as one -- it carries no quorum certificate, no view change and no
    /// canonical collapse surface, so every AFT-gated lane correctly declines
    /// to run for it. It exists so the ordering/finality profile can be varied
    /// while admission, execution, state commitment, durability and receipts
    /// stay on the same path.
    Solo,
}

/// Exact runtime-selectable ordering/finality implementation identity.
///
/// This is deliberately narrower than [`ConsensusType`]: only the two M04.9
/// profiles with complete runtime contracts are representable. Compatibility
/// labels are accepted while parsing operator configuration, but serialization
/// always emits one canonical versioned identity.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFinalityProfile {
    /// AFT classic-BFT with authenticated native quorum certificates.
    #[serde(
        rename = "bft_consensus_aft_v1",
        alias = "bft_consensus",
        alias = "aft"
    )]
    BftConsensusAftV1,
    /// One admitted writer with no peer quorum round.
    #[serde(
        rename = "single_authority_v1",
        alias = "single_authority",
        alias = "solo"
    )]
    SingleAuthorityV1,
}

impl RuntimeFinalityProfile {
    /// The canonical source-neutral profile member stored in admitted records.
    pub const fn canonical_member(self) -> &'static str {
        match self {
            Self::BftConsensusAftV1 => "bft_consensus",
            Self::SingleAuthorityV1 => "single_authority",
        }
    }

    /// The exact finality-certificate implementation variant.
    pub const fn certificate_variant(self) -> &'static str {
        match self {
            Self::BftConsensusAftV1 => "bft_consensus_aft_v1",
            Self::SingleAuthorityV1 => "single_authority_v1",
        }
    }

    /// Resolve the legacy engine selector only when no explicit profile was
    /// supplied. AFT remains the default operational profile; Solo remains an
    /// explicit selection of the non-default single-authority path.
    pub const fn from_consensus_type(consensus_type: ConsensusType) -> Option<Self> {
        match consensus_type {
            ConsensusType::Aft => Some(Self::BftConsensusAftV1),
            ConsensusType::Solo => Some(Self::SingleAuthorityV1),
            ConsensusType::ProofOfAuthority | ConsensusType::ProofOfStake => None,
        }
    }

    /// Refuse a profile label that does not select the matching executable
    /// engine. A configuration label never changes engine semantics by itself.
    pub const fn matches_consensus_type(self, consensus_type: ConsensusType) -> bool {
        matches!(
            (self, consensus_type),
            (Self::BftConsensusAftV1, ConsensusType::Aft)
                | (Self::SingleAuthorityV1, ConsensusType::Solo)
        )
    }
}

/// Safety mode for the Aft Fault Tolerance consensus family.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AftSafetyMode {
    /// Classic BFT assumptions and thresholds.
    #[default]
    ClassicBft,
    /// Majority-safety mode under guardianized non-equivocation assumptions.
    GuardianMajority,
    /// Majority fast path with asynchronous asymptote sealing for stronger settlement.
    Asymptote,
    /// Experimental nested-witness mode for research-only deployments.
    /// This mode must be explicitly enabled in config before the node will start.
    ExperimentalNestedGuardian,
}
