// Path: crates/types/src/app/consensus.rs

use crate::app::{AccountId, ActiveKeyRecord};
use crate::codec;
use crate::error::StateError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The state key for the single, canonical `ValidatorSetBlob` structure.
pub const VALIDATOR_SET_KEY: &[u8] = b"system::validators::current";

// --- Versioned Blob Structures for Backwards Compatibility ---

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
struct ValidatorSetBlobV1 {
    pub schema_version: u16,      // = 1
    pub payload: ValidatorSetV1, // old payload
}

/// A versioned container for the validator set blob to support future upgrades.
/// This is the structure that is stored in state under `VALIDATOR_SET_KEY`.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorSetBlob {
    /// The schema version of the payload. Starts at 1.
    pub schema_version: u16,
    /// The version-specific payload containing the validator set.
    pub payload: ValidatorSetsV1,
}

// --- Version-Aware Read/Write Helpers ---

/// Read helper that accepts:
///   - V2 blob (schema_version=2, payload: ValidatorSetsV1)
///   - V1 blob (schema_version=1, payload: ValidatorSetV1)  -> wrapped as {current=..., next=None}
///   - raw `ValidatorSetsV1` (payload only)
///   - raw `ValidatorSetV1` (payload only)
pub fn read_validator_sets(bytes: &[u8]) -> Result<ValidatorSetsV1, StateError> {
    if let Ok(v2) = codec::from_bytes_canonical::<ValidatorSetBlob>(bytes) {
        return Ok(v2.payload);
    }
    if let Ok(v1) = codec::from_bytes_canonical::<ValidatorSetBlobV1>(bytes) {
        return Ok(ValidatorSetsV1 {
            current: v1.payload,
            next: None,
        });
    }
    if let Ok(sets) = codec::from_bytes_canonical::<ValidatorSetsV1>(bytes) {
        return Ok(sets);
    }
    if let Ok(curr) = codec::from_bytes_canonical::<ValidatorSetV1>(bytes) {
        return Ok(ValidatorSetsV1 {
            current: curr,
            next: None,
        });
    }
    Err(StateError::Decode(
        "Unknown validator set encoding".into(),
    ))
}

/// Always write V2 (schema_version=2) going forward.
pub fn write_validator_sets(sets: &ValidatorSetsV1) -> Result<Vec<u8>, StateError> {
    codec::to_bytes_canonical(&ValidatorSetBlob {
        schema_version: 2,
        payload: sets.clone(),
    })
    .map_err(StateError::Decode)
}

// --- Core Data Structures ---

/// A container for both the currently active and the pending next validator set.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Default)]
pub struct ValidatorSetsV1 {
    /// The validator set that is currently active for this block height.
    pub current: ValidatorSetV1,
    /// The validator set that will become active at its `effective_from_height`.
    pub next: Option<ValidatorSetV1>,
}

/// The canonical representation of the active validator set for a given epoch.
/// It contains all information required for consensus leader selection and block verification.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Default)]
pub struct ValidatorSetV1 {
    /// The block height at which this validator set becomes active.
    pub effective_from_height: u64,
    /// The pre-calculated sum of all weights in the `validators` list.
    /// This MUST equal the actual sum for the structure to be valid.
    pub total_weight: u128,
    /// The list of active validators. This list MUST be sorted by `account_id` bytes.
    pub validators: Vec<ValidatorV1>,
}

/// Represents a single validator within the active set.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Default)]
pub struct ValidatorV1 {
    /// The stable, unique identifier for the validator's account.
    pub account_id: AccountId,
    /// The consensus weight of the validator (e.g., stake amount in PoS, or 1 in PoA).
    pub weight: u128,
    /// An embedded copy of the validator's active consensus key record for atomic retrieval.
    pub consensus_key: ActiveKeyRecord,
}