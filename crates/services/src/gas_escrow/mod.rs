// Path: crates/services/src/gas_escrow/mod.rs

use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType};
use depin_sdk_api::state::StateManager;
use depin_sdk_types::app::{evidence_id, AccountId, FailureReport};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::keys::{EVIDENCE_REGISTRY_KEY, QUARANTINED_VALIDATORS_KEY, STAKES_KEY_NEXT};
use std::collections::{BTreeMap, BTreeSet};

/// The outcome of an operation that may result in a penalty.
/// This enum is passed to the `settle` method to determine the action to take.
pub enum SettlementOutcome {
    /// The operation was successful, and no penalty is required.
    Success,
    /// The operation failed, and a penalty should be applied based on the provided report.
    Failure {
        /// The canonical, verifiable report of the misbehavior.
        report: FailureReport,
        /// The percentage of stake to slash (for PoS) or severity of the penalty.
        penalty_percentage: u8,
    },
}

/// Typed errors for the penalty mechanism, providing clear reasons for failure.
#[derive(thiserror::Error, Debug)]
pub enum PenaltyError {
    /// The provided evidence has already been processed and penalized.
    /// This prevents replay attacks using the same or alternative proofs for the same offense.
    #[error("Duplicate evidence: this offense has already been penalized.")]
    DuplicateEvidence,
    /// A required piece of state (e.g., the stakes map) was not found.
    #[error("State not initialized: {0}")]
    StateNotInitialized(String),
    /// The offending account ID was not found in the relevant validator/staker set.
    #[error("Unknown validator: {0:?}")]
    UnknownValidator(AccountId),
    /// A failure occurred during canonical serialization or deserialization.
    #[error("Codec error: {0}")]
    Codec(String),
    /// A low-level error occurred while accessing the state manager.
    #[error("State access error: {0}")]
    State(String),
}

/// A trait for services that handle the settlement of agentic penalties.
///
/// This provides a consensus-agnostic interface for applying economic (slashing) or
/// non-economic (quarantining) penalties based on verifiable failure reports.
pub trait GasEscrowHandler: BlockchainService {
    /// Applies a penalty based on a failure report, ensuring idempotency and atomicity.
    fn settle<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        consensus_type: &ConsensusType,
        outcome: SettlementOutcome,
    ) -> Result<(), PenaltyError>;
}

/// A service responsible for applying consensus-agnostic penalties for agent misbehavior.
///
/// Despite its name, this service's primary role in this hardened design is not gas
/// management, but rather the core logic for slashing and quarantining based on
/// `FailureReport`s.
pub struct GasEscrowService;

impl BlockchainService for GasEscrowService {
    fn service_type(&self) -> ServiceType {
        // The service type remains consistent for now, but could be renamed in a future refactor.
        ServiceType::Custom("GasEscrow".to_string())
    }
}

// Implements the base `Service` trait.
impl_service_base!(GasEscrowService);

impl GasEscrowHandler for GasEscrowService {
    /// Applies a penalty based on a failure report, ensuring idempotency and atomicity.
    fn settle<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        consensus_type: &ConsensusType,
        outcome: SettlementOutcome,
    ) -> Result<(), PenaltyError> {
        // ASSUMPTION: The StateManager guarantees that all `state.insert` calls within this
        // function are part of a single atomic transaction. If this function returns
        // an error, no state changes should be committed.
        if let SettlementOutcome::Failure {
            report,
            penalty_percentage,
        } = outcome
        {
            // 1. Evidence Idempotence Check
            // Read the set of already handled evidence IDs.
            let mut handled_evidence: BTreeSet<[u8; 32]> = state
                .get(EVIDENCE_REGISTRY_KEY)
                .map_err(|e| PenaltyError::State(e.to_string()))?
                .map(|b| codec::from_bytes_canonical(&b).map_err(PenaltyError::Codec))
                .transpose()?
                .unwrap_or_default();

            let id = evidence_id(&report);
            if !handled_evidence.insert(id) {
                // If the ID was already in the set, this is duplicate evidence. Reject.
                return Err(PenaltyError::DuplicateEvidence);
            }
            // The evidence registry is written first. This ensures that even if a subsequent
            // step fails (e.g., validator not found), the evidence is still recorded and
            // cannot be re-submitted.
            state
                .insert(
                    EVIDENCE_REGISTRY_KEY,
                    &codec::to_bytes_canonical(&handled_evidence),
                )
                .map_err(|e| PenaltyError::State(e.to_string()))?;

            // 2. Apply Penalty based on Consensus Type
            match consensus_type {
                ConsensusType::ProofOfStake => {
                    let stakes_bytes = state
                        .get(STAKES_KEY_NEXT)
                        .map_err(|e| PenaltyError::State(e.to_string()))?
                        .ok_or(PenaltyError::StateNotInitialized(
                            "STAKES_KEY_NEXT missing".into(),
                        ))?;
                    let mut stakes: BTreeMap<AccountId, u64> =
                        codec::from_bytes_canonical(&stakes_bytes).map_err(PenaltyError::Codec)?;

                    if let Some(stake) = stakes.get_mut(&report.offender) {
                        // Use wide u128 arithmetic for the multiplication to prevent overflow.
                        let slash_amount =
                            (((*stake as u128) * (penalty_percentage as u128)) / 100u128) as u64;
                        // Use saturating subtraction for safety.
                        *stake = stake.saturating_sub(slash_amount);

                        // Write the updated stakes map back to state.
                        state
                            .insert(STAKES_KEY_NEXT, &codec::to_bytes_canonical(&stakes))
                            .map_err(|e| PenaltyError::State(e.to_string()))?;
                    } else {
                        // The offender is not in the upcoming validator set.
                        return Err(PenaltyError::UnknownValidator(report.offender));
                    }
                }
                ConsensusType::ProofOfAuthority => {
                    let mut quarantined: BTreeSet<AccountId> = state
                        .get(QUARANTINED_VALIDATORS_KEY)
                        .map_err(|e| PenaltyError::State(e.to_string()))?
                        .map(|b| codec::from_bytes_canonical(&b).map_err(PenaltyError::Codec))
                        .transpose()?
                        .unwrap_or_default();

                    if quarantined.insert(report.offender) {
                        state
                            .insert(
                                QUARANTINED_VALIDATORS_KEY,
                                &codec::to_bytes_canonical(&quarantined),
                            )
                            .map_err(|e| PenaltyError::State(e.to_string()))?;
                    }
                    // If the validator was already quarantined, we still accept the evidence
                    // but no state change is needed for the quarantine set.
                }
            }
        }
        Ok(())
    }
}
