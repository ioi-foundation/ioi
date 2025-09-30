// Path: crates/types/src/app/penalties.rs

//! Defines the canonical, fact-based data structures for reporting and penalizing
//! misbehavior within the system.
//!
//! This module adheres to the principle of "Fact-Based Evidence", where replay
//! protection is based on the immutable facts of an offense, not the specific
//! proof provided. This makes the system robust against attacks that use
//! alternative but equally valid proofs for the same underlying incident.

use crate::app::identity::AccountId;
use dcrypt::algorithms::xof::Blake3Xof;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Classifies the type of offense being reported.
///
/// This enum is designed to be extensible. New variants can be added
/// for future types of misbehavior without breaking existing logic.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum OffenseType {
    /// Indicates that an agent failed a required calibration probe, suggesting
    /// it is either offline, malfunctioning, or providing incorrect results.
    FailedCalibrationProbe,
    // Future offense types, such as providing provably incorrect data,
    // can be added here.
}

/// Contains the canonical, verifiable, and minimal facts that uniquely define an offense.
///
/// This data is used to generate a deterministic `evidence_id` for replay protection.
/// It must not contain any transient or non-deterministic data.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum OffenseFacts {
    /// The facts for a failed calibration probe.
    FailedCalibrationProbe {
        /// The unique, deterministic identifier of the probe that failed.
        probe_id: [u8; 32],
    },
    // Facts for other offenses would be defined here, corresponding to their OffenseType.
}

/// A comprehensive report of misbehavior submitted to the chain for penalization.
///
/// This structure is the primary payload for a `ReportMisbehavior` system transaction.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FailureReport {
    /// The canonical `AccountId` of the offending agent.
    pub offender: AccountId,
    /// The category of the offense.
    pub offense_type: OffenseType,
    /// The specific, verifiable facts of the offense. This is the basis for replay protection.
    pub facts: OffenseFacts,
    /// The supporting, opaque evidence that proves the facts. This could be a set of
    /// signed messages, log data, or other cryptographic proof. The contents of this field
    /// are NOT used for replay protection.
    pub proof: Vec<u8>,
}

/// Generates a unique, deterministic ID for a piece of evidence from its canonical facts.
///
/// This function is the cornerstone of the system's replay protection. It hashes the
/// immutable facts of the offense (`offender`, `offense_type`, `facts`) using a
/// canonical binary encoding (`SCALE codec`). The `proof` field is deliberately excluded
/// from the hash to ensure that an offense can only be penalized once, regardless of
/// what valid proof is submitted or who submits it.
///
/// # Arguments
///
/// * `report` - A reference to the `FailureReport` containing the evidence.
///
/// # Returns
///
/// A 32-byte unique identifier for the evidence.
pub fn evidence_id(report: &FailureReport) -> [u8; 32] {
    // Serialize only the canonical, fact-based fields into a deterministic byte string.
    let canonical_bytes =
        crate::codec::to_bytes_canonical(&(&report.offender, &report.offense_type, &report.facts))
            .unwrap_or_else(|e| {
                panic!(
                    "CRITICAL: Canonical serialization of facts must not fail: {}",
                    e
                )
            });

    // Hash the canonical bytes to produce the unique, replay-protected ID.
    // Use the one-shot generate function from dcrypt's Blake3Xof.
    Blake3Xof::generate(&canonical_bytes, 32)
        .unwrap_or_else(|e| panic!("CRITICAL: Blake3Xof generation must not fail: {}", e))
        .try_into()
        .unwrap_or_else(|_| panic!("CRITICAL: Blake3Xof output must be 32 bytes"))
}
