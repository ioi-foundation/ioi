// Path: crates/types/src/app/consensus.rs

use crate::app::{AccountId, ActiveKeyRecord, BlockHeader, ChainTransaction};
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

/// Writes the validator set to a canonical binary format.
///
/// **Invariant:** This function automatically sorts the validator lists in both
/// `current` and `next` (if present) by `account_id`. This ensures that
/// consensus engines can rely on the state being pre-sorted, avoiding O(N log N)
/// operations in the hot path.
pub fn write_validator_sets(sets: &ValidatorSetsV1) -> Result<Vec<u8>, StateError> {
    // Clone to sort without mutating the input reference
    let mut sorted_sets = sets.clone();

    // Sort current set
    sorted_sets
        .current
        .validators
        .sort_by(|a, b| a.account_id.cmp(&b.account_id));

    // Sort next set if it exists
    if let Some(next) = &mut sorted_sets.next {
        next.validators
            .sort_by(|a, b| a.account_id.cmp(&b.account_id));
    }

    codec::to_bytes_canonical(&ValidatorSetBlob {
        schema_version: 2,
        payload: sorted_sets,
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

/// Selects the validator set that is effective for the given height.
/// This is the canonical, single source of truth for validator set promotion logic.
pub fn effective_set_for_height(sets: &ValidatorSetsV1, h: u64) -> &ValidatorSetV1 {
    if let Some(next) = &sets.next {
        if h >= next.effective_from_height && !next.validators.is_empty() && next.total_weight > 0 {
            return next;
        }
    }
    &sets.current
}

/// 6-byte short ID is sufficient for mempool deduplication within a short time window.
pub type ShortTxId = [u8; 6];

/// A bandwidth-optimized representation of a block for gossip.
#[derive(Encode, Decode, Debug, Clone)]
pub struct CompactBlock {
    /// The full block header.
    pub header: BlockHeader,
    /// Short identifiers for all transactions in the block.
    /// Peers use this list to reconstruct the block from their local mempool.
    pub short_ids: Vec<ShortTxId>,
    /// Full bytes of transactions that the proposer predicts peers might miss (optional).
    pub prefilled_txs: Vec<ChainTransaction>,
}

// --- BFT Voting Structures ---

/// A vote for a specific block hash at a specific height/view.
/// This is the message broadcast by validators to attest to a block's validity.
/// 
/// [MODIFIED] Now uses generic Vec<u8> which can hold either a classical Ed25519 signature
/// OR a BLS signature share depending on the active scheme.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// The block height this vote is for.
    pub height: u64,
    /// The consensus view/round this vote is for.
    pub view: u64,
    /// The hash of the block being voted for.
    pub block_hash: [u8; 32],
    /// The Account ID of the validator casting the vote.
    pub voter: AccountId,
    /// The cryptographic signature (Ed25519 or BLS Share).
    pub signature: Vec<u8>, 
}

/// A cryptographic proof that a quorum (2/3+1) of validators approved a block.
/// This certificate allows a block to be considered finalized (or committed) by the network.
///
/// [MODIFIED] Added `aggregated_signature` and `signers_bitfield` for BLS optimization.
/// The `signatures` field remains for legacy/Ed25519 compatibility or as a fallback.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct QuorumCertificate {
    /// The height of the certified block.
    pub height: u64,
    /// The view of the certified block.
    pub view: u64,
    /// The hash of the certified block.
    pub block_hash: [u8; 32],
    
    // --- Legacy / Ed25519 (Explicit List) ---
    /// The individual signatures proving the quorum.
    pub signatures: Vec<(AccountId, Vec<u8>)>,

    // --- Scalable / BLS (Aggregated) ---
    /// The aggregated BLS signature.
    #[serde(default)]
    pub aggregated_signature: Vec<u8>,
    /// A bitfield representing which validators from the canonical set signed.
    #[serde(default)]
    pub signers_bitfield: Vec<u8>,
}