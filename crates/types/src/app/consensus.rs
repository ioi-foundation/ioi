// Path: crates/types/src/app/consensus.rs

use crate::app::guardianized::{
    canonical_asymptote_observer_canonical_abort_hash,
    canonical_asymptote_observer_canonical_close_hash,
    canonical_asymptote_observer_challenges_hash,
    canonical_asymptote_observer_transcripts_hash, CollapseState, FinalityTier,
    SealedFinalityProof,
};
use crate::app::{to_root_hash, AccountId, ActiveKeyRecord, BlockHeader, ChainTransaction};
use crate::app::{GuardianLogCheckpoint, GuardianQuorumCertificate};
use crate::codec;
use crate::error::StateError;
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The state key for the single, canonical `ValidatorSetBlob` structure.
pub const VALIDATOR_SET_KEY: &[u8] = b"system::validators::current";
/// State key prefix for published AFT bulletin-board commitments by height.
pub const AFT_BULLETIN_COMMITMENT_PREFIX: &[u8] = b"aft::ordering::bulletin::";
/// State key prefix for published AFT bulletin-board entries by height and tx hash.
pub const AFT_BULLETIN_ENTRY_PREFIX: &[u8] = b"aft::ordering::bulletin_entry::";
/// State key prefix for published AFT bulletin availability certificates by height.
pub const AFT_BULLETIN_AVAILABILITY_PREFIX: &[u8] =
    b"aft::ordering::bulletin_availability::";
/// State key prefix for published AFT canonical bulletin-close objects by height.
pub const AFT_BULLETIN_CLOSE_PREFIX: &[u8] = b"aft::ordering::bulletin_close::";
/// State key prefix for published AFT canonical-order certificates by height.
pub const AFT_ORDER_CERTIFICATE_PREFIX: &[u8] = b"aft::ordering::certificate::";
/// State key prefix for published AFT canonical-order abort objects by height.
pub const AFT_ORDER_ABORT_PREFIX: &[u8] = b"aft::ordering::abort::";
/// State key prefix for the protocol-wide canonical collapse object by height.
pub const AFT_COLLAPSE_OBJECT_PREFIX: &[u8] = b"aft::collapse::";
/// State key prefix for recorded AFT omission proofs by height and transaction hash.
pub const AFT_OMISSION_PROOF_PREFIX: &[u8] = b"aft::ordering::omission::";

/// Builds the canonical state key for a published AFT bulletin-board commitment.
pub fn aft_bulletin_commitment_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_COMMITMENT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT bulletin-board entry.
pub fn aft_bulletin_entry_key(height: u64, tx_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_BULLETIN_ENTRY_PREFIX,
        &height.to_be_bytes(),
        tx_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for a published AFT bulletin availability certificate.
pub fn aft_bulletin_availability_certificate_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_AVAILABILITY_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT canonical bulletin close.
pub fn aft_canonical_bulletin_close_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_CLOSE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT canonical-order certificate.
pub fn aft_order_certificate_key(height: u64) -> Vec<u8> {
    [AFT_ORDER_CERTIFICATE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT canonical-order abort object.
pub fn aft_canonical_order_abort_key(height: u64) -> Vec<u8> {
    [AFT_ORDER_ABORT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for the protocol-wide AFT collapse object.
pub fn aft_canonical_collapse_object_key(height: u64) -> Vec<u8> {
    [AFT_COLLAPSE_OBJECT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for an AFT omission proof.
pub fn aft_omission_proof_key(height: u64, tx_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_OMISSION_PROOF_PREFIX,
        &height.to_be_bytes(),
        tx_hash.as_ref(),
    ]
    .concat()
}

// --- Versioned Blob Structures for Backwards Compatibility ---

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
struct ValidatorSetBlobV1 {
    pub schema_version: u16,     // = 1
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
    Err(StateError::Decode("Unknown validator set encoding".into()))
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
    sorted_sets.current.validators.sort_by_key(|a| a.account_id);

    // Sort next set if it exists
    if let Some(next) = &mut sorted_sets.next {
        next.validators.sort_by_key(|a| a.account_id);
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

/// Published bulletin-board commitment for a slot's eligible transaction surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinCommitment {
    /// Target block height / slot.
    pub height: u64,
    /// Objective slot cutoff timestamp in milliseconds.
    pub cutoff_timestamp_ms: u64,
    /// Canonical root of the admitted bulletin-board entries.
    pub bulletin_root: [u8; 32],
    /// Number of admitted entries summarized by this commitment.
    pub entry_count: u32,
}

/// A single published bulletin-board entry for the public AFT transaction surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinSurfaceEntry {
    /// Target block height / slot.
    pub height: u64,
    /// Canonical transaction hash admitted to the bulletin surface.
    pub tx_hash: [u8; 32],
}

/// Compact proof family for proof-carrying canonical ordering.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalOrderProofSystem {
    /// Reference verifier: proof bytes are a canonical hash over public inputs.
    #[default]
    HashBindingV1,
    /// Commitment-level witness verified against the block's public transaction surface.
    CommittedSurfaceV1,
}

/// Public inputs all validators can verify cheaply when checking a canonical order certificate.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderPublicInputs {
    /// Slot / height being ordered.
    pub height: u64,
    /// Canonical root hash of the parent state.
    pub parent_state_root_hash: [u8; 32],
    /// Bulletin commitment hash used to derive the eligible set.
    pub bulletin_commitment_hash: [u8; 32],
    /// Public randomness beacon for the slot.
    pub randomness_beacon: [u8; 32],
    /// Canonical root of the ordered transaction set.
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical root hash of the resulting state.
    pub resulting_state_root_hash: [u8; 32],
    /// Objective slot cutoff bound into the order certificate.
    pub cutoff_timestamp_ms: u64,
}

/// Compact proof envelope for a canonical order certificate.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderProof {
    /// Proof system used to validate the order certificate.
    #[serde(default)]
    pub proof_system: CanonicalOrderProofSystem,
    /// Canonical hash of the encoded public inputs.
    #[serde(default)]
    pub public_inputs_hash: [u8; 32],
    /// Opaque proof bytes.
    #[serde(default)]
    pub proof_bytes: Vec<u8>,
}

/// First-class recoverability artifact for a canonical bulletin / order surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BulletinAvailabilityCertificate {
    /// Slot / height whose bulletin surface is being certified.
    pub height: u64,
    /// Canonical hash of the bulletin commitment the certificate is bound to.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical recoverability root over the bound bulletin / ordering / state surface.
    #[serde(default)]
    pub recoverability_root: [u8; 32],
}

/// Canonical closed bulletin object binding the publication surface to a unique slot close.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalBulletinClose {
    /// Slot / height whose bulletin surface is being closed.
    pub height: u64,
    /// Objective cutoff timestamp the close commits to.
    pub cutoff_timestamp_ms: u64,
    /// Canonical hash of the bulletin commitment carried by the close.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bulletin availability certificate carried by the close.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Number of admitted bulletin entries sealed by the close.
    pub entry_count: u32,
}

/// Atomic publication bundle for the ordering bulletin surface and its canonical order object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderPublicationBundle {
    /// Slot bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment: BulletinCommitment,
    /// Published bulletin surface entries for the slot.
    #[serde(default)]
    pub bulletin_entries: Vec<BulletinSurfaceEntry>,
    /// First-class bulletin availability certificate bound to the order surface.
    #[serde(default)]
    pub bulletin_availability_certificate: BulletinAvailabilityCertificate,
    /// Canonical order certificate over the same bulletin surface.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
}

/// Locally derived canonical execution object for a slot's proof-carried ordering surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderExecutionObject {
    /// Slot bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment: BulletinCommitment,
    /// Published bulletin surface entries for the slot.
    #[serde(default)]
    pub bulletin_entries: Vec<BulletinSurfaceEntry>,
    /// Explicit bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate: BulletinAvailabilityCertificate,
    /// Canonical bulletin-close object derived from the publication surface.
    #[serde(default)]
    pub bulletin_close: CanonicalBulletinClose,
    /// Canonical order certificate bound to the same surface.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
}

/// Objective negative outcome for ordering extraction when the proof-carried surface is missing or
/// invalid.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalOrderAbortReason {
    /// The committed block does not carry the required canonical-order certificate.
    #[default]
    MissingOrderCertificate,
    /// The committed block's bulletin surface cannot be reconstructed canonically.
    BulletinSurfaceReconstructionFailure,
    /// The reconstructed bulletin surface does not match the proof-carried bulletin commitment.
    BulletinSurfaceMismatch,
    /// The committed block's bulletin-close object is invalid or cannot be derived.
    InvalidBulletinClose,
    /// The committed block's canonical-order certificate is dominated by objective omissions.
    OmissionDominated,
    /// The certificate, bulletin commitment, or availability certificate height does not match
    /// the slot height.
    CertificateHeightMismatch,
    /// The certificate randomness beacon does not match the canonical slot schedule.
    RandomnessMismatch,
    /// The certificate ordered-transactions root does not match the committed block surface.
    OrderedTransactionsRootMismatch,
    /// The certificate resulting-state root does not match the committed block surface.
    ResultingStateRootMismatch,
    /// The canonical-order proof public-input binding is inconsistent.
    InvalidPublicInputsHash,
    /// The bulletin availability certificate or its recoverability binding is invalid.
    InvalidBulletinAvailabilityCertificate,
    /// The proof binding carried by the order certificate is invalid.
    InvalidProofBinding,
}

/// Canonical abort object emitted when local ordering extraction fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderAbort {
    /// Slot / height whose ordering surface aborted.
    pub height: u64,
    /// Objective reason the close path was rejected.
    #[serde(default)]
    pub reason: CanonicalOrderAbortReason,
    /// Human-readable extraction failure detail.
    #[serde(default)]
    pub details: String,
    /// Canonical hash of the bulletin commitment carried by the candidate certificate, if present.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the bulletin availability certificate carried by the candidate
    /// certificate, if present.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the locally derived bulletin-close object, if derivation succeeded.
    #[serde(default)]
    pub bulletin_close_hash: [u8; 32],
    /// Canonical hash of the candidate canonical-order certificate, if present.
    #[serde(default)]
    pub canonical_order_certificate_hash: [u8; 32],
}

/// Canonical close-or-abort outcome tag shared across ordering and sealing collapse surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalCollapseKind {
    /// The positive close path survived all objective checks.
    #[default]
    Close,
    /// Objective negative evidence dominated the close path.
    Abort,
}

/// Ordering-side component of the protocol-wide canonical collapse object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderingCollapse {
    /// Slot / height whose ordering surface collapsed.
    pub height: u64,
    /// Whether ordering resolved to the positive close or negative abort path.
    #[serde(default)]
    pub kind: CanonicalCollapseKind,
    /// Canonical hash of the ordering bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical hash of the ordering bulletin availability certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical hash of the ordering bulletin-close object.
    #[serde(default)]
    pub bulletin_close_hash: [u8; 32],
    /// Canonical hash of the canonical-order certificate when the positive close path survives.
    #[serde(default)]
    pub canonical_order_certificate_hash: [u8; 32],
}

/// Sealing-side component of the protocol-wide canonical collapse object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalSealingCollapse {
    /// Epoch in which the sealing surface was derived.
    pub epoch: u64,
    /// Slot / height whose sealing surface collapsed.
    pub height: u64,
    /// Consensus view of the sealed slot.
    pub view: u64,
    /// Whether sealing resolved to the positive close or negative abort path.
    #[serde(default)]
    pub kind: CanonicalCollapseKind,
    /// Finality tier admitted by the canonical sealing outcome.
    #[serde(default)]
    pub finality_tier: FinalityTier,
    /// Underlying sealing collapse state carried by the proof.
    #[serde(default)]
    pub collapse_state: CollapseState,
    /// Canonical root of the observer transcript surface.
    #[serde(default)]
    pub transcripts_root: [u8; 32],
    /// Canonical root of the observer challenge surface.
    #[serde(default)]
    pub challenges_root: [u8; 32],
    /// Canonical hash of the decisive sealing close-or-abort object.
    #[serde(default)]
    pub resolution_hash: [u8; 32],
}

/// Protocol-wide close-or-abort object persisted with AFT durable state.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseObject {
    /// Slot / height whose public execution surface collapsed.
    pub height: u64,
    /// Canonical hash of the previous slot's predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Rolling accumulator hash binding this collapse object to the full prior continuity chain.
    #[serde(default)]
    pub continuity_accumulator_hash: [u8; 32],
    /// Recursive proof-carrying continuity step for this collapse object.
    #[serde(default)]
    pub continuity_recursive_proof: CanonicalCollapseRecursiveProof,
    /// Ordering outcome for the slot.
    #[serde(default)]
    pub ordering: CanonicalOrderingCollapse,
    /// Sealing outcome for the slot, when the block carries a sealed-finality proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing: Option<CanonicalSealingCollapse>,
    /// Canonical root hash of the committed transaction surface.
    #[serde(default)]
    pub transactions_root_hash: [u8; 32],
    /// Canonical root hash of the committed post-state.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
}

/// Succinct predecessor commitment used on the live proposal path.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseCommitment {
    /// Slot / height of the committed predecessor collapse object.
    pub height: u64,
    /// Recursive continuity accumulator already binding the predecessor to its prior chain.
    #[serde(default)]
    pub continuity_accumulator_hash: [u8; 32],
    /// Canonical post-state root produced by the predecessor collapse object.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
}

/// Reference proof system for recursive canonical-collapse continuity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default,
)]
pub enum CanonicalCollapseContinuityProofSystem {
    /// Reference verifier: proof bytes are a canonical hash over the current statement and the
    /// previous recursive proof hash.
    #[default]
    HashPcdV1,
    /// Mock/native succinct verifier surface with explicit recursive public inputs.
    SuccinctSp1V1,
}

/// Recursive proof-carrying continuity witness for a canonical collapse object.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseRecursiveProof {
    /// Succinct commitment to the collapse object this proof step certifies.
    #[serde(default)]
    pub commitment: CanonicalCollapseCommitment,
    /// Canonical hash of the previous slot's predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Canonical payload hash of the collapse object this proof certifies.
    #[serde(default)]
    pub payload_hash: [u8; 32],
    /// Proof-system variant used to interpret `proof_bytes`.
    #[serde(default)]
    pub proof_system: CanonicalCollapseContinuityProofSystem,
    /// Canonical hash of the previous recursive proof step.
    #[serde(default)]
    pub previous_recursive_proof_hash: [u8; 32],
    /// Opaque proof bytes for the current recursive step.
    #[serde(default)]
    pub proof_bytes: Vec<u8>,
}

/// Proof-carrying recursive-continuity certificate for live proposal extension.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseExtensionCertificate {
    /// Succinct predecessor commitment for the slot being extended.
    #[serde(default)]
    pub predecessor_commitment: CanonicalCollapseCommitment,
    /// Canonical hash of the predecessor slot's recursive continuity proof.
    #[serde(default)]
    pub predecessor_recursive_proof_hash: [u8; 32],
}

/// Public inputs for a recursive canonical-collapse continuity proof step.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalCollapseContinuityPublicInputs {
    /// Succinct commitment to the collapse object this proof step certifies.
    #[serde(default)]
    pub commitment: CanonicalCollapseCommitment,
    /// Canonical hash of the previous slot's predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Canonical payload hash of the collapse object this proof certifies.
    #[serde(default)]
    pub payload_hash: [u8; 32],
    /// Canonical hash of the previous recursive proof step.
    #[serde(default)]
    pub previous_recursive_proof_hash: [u8; 32],
}

/// Succinct witness payload for the committed-surface canonical-order verifier.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CommittedSurfaceCanonicalOrderProof {
    /// Canonical hash of the bulletin availability certificate carried by the order certificate.
    #[serde(default)]
    pub bulletin_availability_certificate_hash: [u8; 32],
    /// Canonical commitment over the omission set for the slot.
    #[serde(default)]
    pub omission_commitment_root: [u8; 32],
}

/// Objective proof that a candidate canonical order omitted an eligible transaction.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct OmissionProof {
    /// Slot / height the omission applies to.
    pub height: u64,
    /// Validator accountable for the conflicting candidate order this proof dominates.
    #[serde(default)]
    pub offender_account_id: AccountId,
    /// Canonical hash of the omitted transaction.
    pub tx_hash: [u8; 32],
    /// Bulletin commitment root that admitted the omitted transaction.
    pub bulletin_root: [u8; 32],
    /// Human-readable explanation for the omission.
    #[serde(default)]
    pub details: String,
}

/// Proof-carrying certificate for the canonical order of a slot.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalOrderCertificate {
    /// Slot / height being certified.
    pub height: u64,
    /// Published bulletin-board commitment for the slot.
    #[serde(default)]
    pub bulletin_commitment: BulletinCommitment,
    /// Explicit recoverability certificate for the slot's bulletin / order surface.
    #[serde(default)]
    pub bulletin_availability_certificate: BulletinAvailabilityCertificate,
    /// Public randomness beacon used to rank eligible transactions.
    #[serde(default)]
    pub randomness_beacon: [u8; 32],
    /// Canonical root of the ordered transaction set.
    #[serde(default)]
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical root hash of the resulting state.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Compact proof binding the certificate to the canonical order inputs.
    #[serde(default)]
    pub proof: CanonicalOrderProof,
    /// Objective omission proofs, if any. A non-empty set dominates the candidate order.
    #[serde(default)]
    pub omission_proofs: Vec<OmissionProof>,
}

fn hash_consensus_bytes<T: Encode>(value: &T) -> Result<[u8; 32], String> {
    let bytes = value.encode();
    let digest = DcryptSha256::digest(&bytes).map_err(|e| e.to_string())?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| "invalid sha256 digest length".into())
}

/// Returns the canonical hash of a bulletin commitment.
pub fn canonical_bulletin_commitment_hash(
    commitment: &BulletinCommitment,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(commitment)
}

/// Returns the canonical hash of a bulletin availability certificate.
pub fn canonical_bulletin_availability_certificate_hash(
    certificate: &BulletinAvailabilityCertificate,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(certificate)
}

/// Returns the canonical hash of a bulletin-close object.
pub fn canonical_bulletin_close_hash(close: &CanonicalBulletinClose) -> Result<[u8; 32], String> {
    hash_consensus_bytes(close)
}

/// Returns the canonical hash of a canonical-order certificate.
pub fn canonical_order_certificate_hash(
    certificate: &CanonicalOrderCertificate,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(certificate)
}

/// Returns the canonical hash of a canonical-order abort object.
pub fn canonical_order_abort_hash(abort: &CanonicalOrderAbort) -> Result<[u8; 32], String> {
    hash_consensus_bytes(abort)
}

/// Returns the canonical hash of a protocol-wide canonical collapse object.
pub fn canonical_collapse_object_hash(
    collapse: &CanonicalCollapseObject,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(collapse)
}

/// Returns the succinct predecessor commitment for a canonical collapse object.
pub fn canonical_collapse_commitment(
    collapse: &CanonicalCollapseObject,
) -> CanonicalCollapseCommitment {
    CanonicalCollapseCommitment {
        height: collapse.height,
        continuity_accumulator_hash: collapse.continuity_accumulator_hash,
        resulting_state_root_hash: collapse.resulting_state_root_hash,
    }
}

/// Returns the canonical hash of a collapse predecessor commitment.
pub fn canonical_collapse_commitment_hash(
    commitment: &CanonicalCollapseCommitment,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(commitment)
}

/// Returns the canonical hash of the collapse predecessor commitment implied by a full object.
pub fn canonical_collapse_commitment_hash_from_object(
    collapse: &CanonicalCollapseObject,
) -> Result<[u8; 32], String> {
    canonical_collapse_commitment_hash(&canonical_collapse_commitment(collapse))
}

/// Returns the statement hash certified by a recursive canonical-collapse proof step.
pub fn canonical_collapse_recursive_statement_hash(
    commitment: &CanonicalCollapseCommitment,
    previous_canonical_collapse_commitment_hash: [u8; 32],
    payload_hash: [u8; 32],
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(&(
        b"aft::canonical-collapse::pcd-statement::v1",
        commitment,
        previous_canonical_collapse_commitment_hash,
        payload_hash,
    ))
}

/// Returns the public inputs bound by a recursive canonical-collapse proof step.
pub fn canonical_collapse_continuity_public_inputs(
    commitment: &CanonicalCollapseCommitment,
    previous_canonical_collapse_commitment_hash: [u8; 32],
    payload_hash: [u8; 32],
    previous_recursive_proof_hash: [u8; 32],
) -> CanonicalCollapseContinuityPublicInputs {
    CanonicalCollapseContinuityPublicInputs {
        commitment: commitment.clone(),
        previous_canonical_collapse_commitment_hash,
        payload_hash,
        previous_recursive_proof_hash,
    }
}

/// Returns the mock proof bytes for the succinct recursive continuity backend.
pub fn canonical_collapse_succinct_mock_proof_bytes(
    public_inputs: &CanonicalCollapseContinuityPublicInputs,
) -> Result<Vec<u8>, String> {
    Ok(
        hash_consensus_bytes(&(
            b"aft::canonical-collapse::succinct-mock-proof::v1",
            public_inputs,
        ))?
        .to_vec(),
    )
}

fn canonical_collapse_continuity_proof_system_from_env() -> CanonicalCollapseContinuityProofSystem {
    match std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM") {
        Ok(value) if value.eq_ignore_ascii_case("succinct-sp1-v1") => {
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1
        }
        _ => CanonicalCollapseContinuityProofSystem::HashPcdV1,
    }
}

/// Returns the reference proof bytes for a recursive canonical-collapse proof step.
pub fn canonical_collapse_recursive_proof_bytes(
    proof_system: CanonicalCollapseContinuityProofSystem,
    statement_hash: [u8; 32],
    previous_recursive_proof_hash: [u8; 32],
    public_inputs: &CanonicalCollapseContinuityPublicInputs,
) -> Result<Vec<u8>, String> {
    match proof_system {
        CanonicalCollapseContinuityProofSystem::HashPcdV1 => Ok(
            hash_consensus_bytes(&(
                b"aft::canonical-collapse::pcd-proof::v1",
                proof_system as u8,
                statement_hash,
                previous_recursive_proof_hash,
            ))?
            .to_vec(),
        ),
        CanonicalCollapseContinuityProofSystem::SuccinctSp1V1 => {
            canonical_collapse_succinct_mock_proof_bytes(public_inputs)
        }
    }
}

/// Returns the canonical hash of a recursive canonical-collapse proof step.
pub fn canonical_collapse_recursive_proof_hash(
    proof: &CanonicalCollapseRecursiveProof,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(proof)
}

/// Builds the recursive proof step for a canonical collapse object.
pub fn canonical_collapse_recursive_proof(
    collapse: &CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseRecursiveProof>,
) -> Result<CanonicalCollapseRecursiveProof, String> {
    let proof_system = canonical_collapse_continuity_proof_system_from_env();
    let previous_recursive_proof_hash = if collapse.height <= 1 {
        if previous.is_some() {
            return Err(format!(
                "canonical collapse proof at height {} must not carry a previous proof",
                collapse.height
            ));
        }
        [0u8; 32]
    } else {
        canonical_collapse_recursive_proof_hash(previous.ok_or_else(|| {
            format!(
                "canonical collapse proof at height {} requires a previous proof",
                collapse.height
            )
        })?)?
    };
    let commitment = canonical_collapse_commitment(collapse);
    let payload_hash = canonical_collapse_payload_hash(collapse)?;
    let statement_hash = canonical_collapse_recursive_statement_hash(
        &commitment,
        collapse.previous_canonical_collapse_commitment_hash,
        payload_hash,
    )?;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &commitment,
        collapse.previous_canonical_collapse_commitment_hash,
        payload_hash,
        previous_recursive_proof_hash,
    );
    let proof_bytes = canonical_collapse_recursive_proof_bytes(
        proof_system,
        statement_hash,
        previous_recursive_proof_hash,
        &public_inputs,
    )?;
    Ok(CanonicalCollapseRecursiveProof {
        commitment,
        previous_canonical_collapse_commitment_hash: collapse
            .previous_canonical_collapse_commitment_hash,
        payload_hash,
        proof_system,
        previous_recursive_proof_hash,
        proof_bytes,
    })
}

/// Verifies the self-contained syntax and proof bytes of a recursive canonical-collapse proof
/// step without consulting anchored predecessor state.
pub fn verify_canonical_collapse_recursive_proof(
    proof: &CanonicalCollapseRecursiveProof,
) -> Result<(), String> {
    if proof.commitment.height <= 1 {
        if proof.previous_canonical_collapse_commitment_hash != [0u8; 32] {
            return Err(format!(
                "canonical collapse proof at height {} must carry a zero predecessor commitment hash",
                proof.commitment.height
            ));
        }
    } else {
        if proof.previous_canonical_collapse_commitment_hash == [0u8; 32] {
            return Err(format!(
                "canonical collapse proof at height {} must carry a non-zero predecessor commitment hash",
                proof.commitment.height
            ));
        }
    }

    let statement_hash = canonical_collapse_recursive_statement_hash(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
    )?;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
        proof.previous_recursive_proof_hash,
    );
    let expected_proof_bytes = canonical_collapse_recursive_proof_bytes(
        proof.proof_system,
        statement_hash,
        proof.previous_recursive_proof_hash,
        &public_inputs,
    )?;
    if proof.proof_bytes != expected_proof_bytes {
        return Err(format!(
            "canonical collapse proof bytes mismatch for height {}",
            proof.commitment.height
        ));
    }
    Ok(())
}

/// Verifies that a recursive proof step matches a concrete canonical collapse object and its
/// anchored predecessor state when required.
pub fn verify_canonical_collapse_recursive_proof_matches_collapse(
    collapse: &CanonicalCollapseObject,
    proof: &CanonicalCollapseRecursiveProof,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    verify_canonical_collapse_recursive_proof(proof)?;
    if proof.commitment != canonical_collapse_commitment(collapse) {
        return Err(format!(
            "canonical collapse proof commitment mismatch for height {}",
            collapse.height
        ));
    }
    if proof.previous_canonical_collapse_commitment_hash
        != collapse.previous_canonical_collapse_commitment_hash
    {
        return Err(format!(
            "canonical collapse proof predecessor hash mismatch for height {}",
            collapse.height
        ));
    }
    let expected_payload_hash = canonical_collapse_payload_hash(collapse)?;
    if proof.payload_hash != expected_payload_hash {
        return Err(format!(
            "canonical collapse proof payload hash mismatch for height {}",
            collapse.height
        ));
    }
    if collapse.height <= 1 {
        if proof.previous_recursive_proof_hash != [0u8; 32] {
            return Err(format!(
                "canonical collapse proof at height {} must carry a zero predecessor proof hash",
                collapse.height
            ));
        }
        return Ok(());
    }
    let previous = previous.ok_or_else(|| {
        format!(
            "canonical collapse proof at height {} requires an anchored predecessor collapse object",
            collapse.height
        )
    })?;
    if previous.height + 1 != collapse.height {
        return Err(format!(
            "canonical collapse proof expected anchored predecessor height {}, found {}",
            collapse.height - 1,
            previous.height
        ));
    }
    let previous_commitment_hash = canonical_collapse_commitment_hash(&canonical_collapse_commitment(previous))?;
    if proof.previous_canonical_collapse_commitment_hash != previous_commitment_hash {
        return Err(format!(
            "canonical collapse proof predecessor commitment hash mismatch for height {}",
            collapse.height
        ));
    }
    let expected_accumulator = hash_consensus_bytes(&(
        b"aft::canonical-collapse::accumulator::v1",
        proof.commitment.height,
        previous.continuity_accumulator_hash,
        proof.payload_hash,
    ))?;
    if proof.commitment.continuity_accumulator_hash != expected_accumulator {
        return Err(format!(
            "canonical collapse proof continuity accumulator mismatch for height {}",
            collapse.height
        ));
    }
    let expected_previous_proof_hash =
        canonical_collapse_recursive_proof_hash(&previous.continuity_recursive_proof)?;
    if proof.previous_recursive_proof_hash != expected_previous_proof_hash {
        return Err(format!(
            "canonical collapse proof predecessor proof hash mismatch for height {}",
            collapse.height
        ));
    }
    Ok(())
}

/// Builds the live proposal-time recursive-continuity certificate for extending a predecessor
/// canonical collapse object into `covered_height`.
pub fn canonical_collapse_extension_certificate(
    covered_height: u64,
    predecessor: &CanonicalCollapseObject,
) -> Result<CanonicalCollapseExtensionCertificate, String> {
    if predecessor.height + 1 != covered_height {
        return Err(format!(
            "canonical collapse extension expected predecessor height {}, found {}",
            covered_height - 1,
            predecessor.height
        ));
    }
    verify_canonical_collapse_recursive_proof(&predecessor.continuity_recursive_proof)?;
    Ok(CanonicalCollapseExtensionCertificate {
        predecessor_commitment: canonical_collapse_commitment(predecessor),
        predecessor_recursive_proof_hash: canonical_collapse_recursive_proof_hash(
            &predecessor.continuity_recursive_proof,
        )?,
    })
}

/// Reconstructs the predecessor commitment implied by an extension certificate.
pub fn canonical_collapse_extension_predecessor_commitment(
    covered_height: u64,
    certificate: &CanonicalCollapseExtensionCertificate,
) -> Result<CanonicalCollapseCommitment, String> {
    if covered_height <= 1 {
        return Err(
            "genesis or height-1 block headers do not admit a predecessor commitment".into(),
        );
    }
    let commitment = certificate.predecessor_commitment.clone();
    if commitment.height + 1 != covered_height {
        return Err(format!(
            "canonical collapse extension expected predecessor height {}, found {}",
            covered_height - 1,
            commitment.height
        ));
    }
    Ok(commitment)
}

/// Returns the predecessor-commitment hash implied by an extension certificate.
pub fn canonical_collapse_extension_predecessor_commitment_hash(
    covered_height: u64,
    certificate: &CanonicalCollapseExtensionCertificate,
) -> Result<[u8; 32], String> {
    canonical_collapse_commitment_hash(&canonical_collapse_extension_predecessor_commitment(
        covered_height,
        certificate,
    )?)
}

/// Returns the canonical payload hash of a protocol-wide canonical collapse object, excluding the
/// recursive accumulator field.
pub fn canonical_collapse_payload_hash(
    collapse: &CanonicalCollapseObject,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(&(
        b"aft::canonical-collapse::payload::v1",
        collapse.height,
        collapse.previous_canonical_collapse_commitment_hash,
        &collapse.ordering,
        &collapse.sealing,
        collapse.transactions_root_hash,
        collapse.resulting_state_root_hash,
    ))
}

/// Returns the predecessor-commitment hash that a collapse object at `height` must carry.
pub fn expected_previous_canonical_collapse_commitment_hash(
    height: u64,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<[u8; 32], String> {
    if height <= 1 {
        return Ok([0u8; 32]);
    }

    let previous = previous.ok_or_else(|| {
        format!(
            "canonical collapse continuity requires a previous collapse object for height {}",
            height
        )
    })?;
    if previous.height + 1 != height {
        return Err(format!(
            "canonical collapse continuity expected previous height {}, found {}",
            height - 1,
            previous.height
        ));
    }

    canonical_collapse_commitment_hash_from_object(previous)
}

/// Returns the continuity accumulator hash that a collapse object at `height` must carry.
pub fn expected_previous_canonical_collapse_accumulator_hash(
    height: u64,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<[u8; 32], String> {
    if height <= 1 {
        return Ok([0u8; 32]);
    }

    let previous = previous.ok_or_else(|| {
        format!(
            "canonical collapse accumulator requires a previous collapse object for height {}",
            height
        )
    })?;
    if previous.height + 1 != height {
        return Err(format!(
            "canonical collapse accumulator expected previous height {}, found {}",
            height - 1,
            previous.height
        ));
    }
    Ok(previous.continuity_accumulator_hash)
}

/// Computes the rolling continuity accumulator hash for a collapse object.
pub fn canonical_collapse_continuity_accumulator_hash(
    collapse: &CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<[u8; 32], String> {
    let previous_accumulator =
        expected_previous_canonical_collapse_accumulator_hash(collapse.height, previous)?;
    let payload_hash = canonical_collapse_payload_hash(collapse)?;
    hash_consensus_bytes(&(
        b"aft::canonical-collapse::accumulator::v1",
        collapse.height,
        previous_accumulator,
        payload_hash,
    ))
}

/// Canonically binds both the previous-collapse hash and rolling accumulator for a collapse object.
pub fn bind_canonical_collapse_continuity(
    collapse: &mut CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    collapse.previous_canonical_collapse_commitment_hash =
        expected_previous_canonical_collapse_commitment_hash(collapse.height, previous)?;
    collapse.continuity_accumulator_hash =
        canonical_collapse_continuity_accumulator_hash(collapse, previous)?;
    collapse.continuity_recursive_proof = canonical_collapse_recursive_proof(
        collapse,
        previous.map(|item| &item.continuity_recursive_proof),
    )?;
    Ok(())
}

/// Verifies that a collapse object correctly links to the previous slot.
pub fn verify_canonical_collapse_continuity(
    collapse: &CanonicalCollapseObject,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    let expected = expected_previous_canonical_collapse_commitment_hash(collapse.height, previous)?;
    if collapse.previous_canonical_collapse_commitment_hash != expected {
        return Err(format!(
            "canonical collapse continuity commitment hash mismatch for height {}",
            collapse.height
        ));
    }
    let expected_accumulator = canonical_collapse_continuity_accumulator_hash(collapse, previous)?;
    if collapse.continuity_accumulator_hash != expected_accumulator {
        return Err(format!(
            "canonical collapse continuity accumulator mismatch for height {}",
            collapse.height
        ));
    }
    verify_canonical_collapse_recursive_proof_matches_collapse(
        collapse,
        &collapse.continuity_recursive_proof,
        previous,
    )?;
    Ok(())
}

/// Verifies that a block header carries the correct recursive-continuity link.
pub fn verify_block_header_canonical_collapse_link(
    header: &BlockHeader,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    let expected = expected_previous_canonical_collapse_commitment_hash(header.height, previous)?;
    if header.previous_canonical_collapse_commitment_hash != expected {
        return Err(format!(
            "block header canonical collapse continuity commitment hash mismatch for height {}",
            header.height
        ));
    }
    Ok(())
}

/// Verifies the recursive-continuity certificate carried by a block header.
pub fn verify_canonical_collapse_extension_certificate(
    header_height: u64,
    certificate: &CanonicalCollapseExtensionCertificate,
    expected_parent_state_root: [u8; 32],
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    if header_height <= 1 {
        return Err(
            "genesis or height-1 block headers must not carry a canonical collapse extension certificate"
                .into(),
        );
    }

    let predecessor = canonical_collapse_extension_predecessor_commitment(header_height, certificate)?;
    if predecessor.resulting_state_root_hash != expected_parent_state_root {
        return Err(format!(
            "canonical collapse extension certificate parent state root mismatch for height {}",
            header_height
        ));
    }
    let previous = previous.ok_or_else(|| {
        format!(
            "missing previous canonical collapse object required to verify extension certificate for height {}",
            header_height
        )
    })?;
    verify_canonical_collapse_recursive_proof(&previous.continuity_recursive_proof)?;
    if canonical_collapse_commitment(previous) != predecessor {
        return Err(format!(
            "canonical collapse extension certificate predecessor commitment does not match locally expected predecessor for height {}",
            header_height
        ));
    }
    let expected_proof_hash =
        canonical_collapse_recursive_proof_hash(&previous.continuity_recursive_proof)?;
    if certificate.predecessor_recursive_proof_hash != expected_proof_hash {
        return Err(format!(
            "canonical collapse extension certificate predecessor proof hash mismatch for height {}",
            header_height
        ));
    }
    Ok(())
}

/// Verifies that a block header carries proof-carrying recursive-continuity evidence.
pub fn verify_block_header_canonical_collapse_evidence(
    header: &BlockHeader,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<(), String> {
    if header.height <= 1 {
        verify_block_header_canonical_collapse_link(header, previous)?;
        if header.canonical_collapse_extension_certificate.is_some() {
            return Err(
                "genesis or height-1 block headers must not carry a canonical collapse extension certificate"
                    .into(),
            );
        }
        return Ok(());
    }

    let certificate = header
        .canonical_collapse_extension_certificate
        .as_ref()
        .ok_or_else(|| {
            format!(
                "missing proof-carrying canonical collapse extension certificate for height {}",
                header.height
            )
        })?;
    let expected_parent_state_root =
        to_root_hash(&header.parent_state_root.0).map_err(|e| e.to_string())?;
    verify_canonical_collapse_extension_certificate(
        header.height,
        certificate,
        expected_parent_state_root,
        previous,
    )?;

    let predecessor_commitment_hash =
        canonical_collapse_extension_predecessor_commitment_hash(header.height, certificate)?;
    if predecessor_commitment_hash != header.previous_canonical_collapse_commitment_hash {
        return Err(format!(
            "canonical collapse extension certificate predecessor hash mismatch for height {}",
            header.height
        ));
    }
    if let Some(previous) = previous {
        let expected = expected_previous_canonical_collapse_commitment_hash(
            header.height,
            Some(previous),
        )?;
        if header.previous_canonical_collapse_commitment_hash != expected {
            return Err(format!(
                "block header canonical collapse continuity commitment hash mismatch for height {}",
                header.height
            ));
        }
    }

    Ok(())
}

fn ensure_sorted_unique_tx_hashes(tx_hashes: &[[u8; 32]]) -> Result<(), String> {
    for window in tx_hashes.windows(2) {
        if window[0] >= window[1] {
            return Err(
                "published bulletin surface must contain strictly increasing unique tx hashes"
                    .into(),
            );
        }
    }
    Ok(())
}

fn build_bulletin_commitment_from_hashes(
    height: u64,
    cutoff_timestamp_ms: u64,
    tx_hashes: &[[u8; 32]],
) -> Result<BulletinCommitment, String> {
    ensure_sorted_unique_tx_hashes(tx_hashes)?;
    let entry_count = u32::try_from(tx_hashes.len())
        .map_err(|_| "too many admitted transactions for bulletin commitment".to_string())?;
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::bulletin::v1".len()
            + std::mem::size_of::<u64>() * 2
            + std::mem::size_of::<u32>()
            + tx_hashes.len() * 32,
    );
    material.extend_from_slice(b"aft::canonical-order::bulletin::v1");
    material.extend_from_slice(&height.to_be_bytes());
    material.extend_from_slice(&cutoff_timestamp_ms.to_be_bytes());
    material.extend_from_slice(&entry_count.to_be_bytes());
    for tx_hash in tx_hashes {
        material.extend_from_slice(tx_hash);
    }
    let bulletin_root = hash_consensus_bytes(&material)?;

    Ok(BulletinCommitment {
        height,
        cutoff_timestamp_ms,
        bulletin_root,
        entry_count,
    })
}

fn canonical_recoverability_root(
    bulletin_commitment: &BulletinCommitment,
    randomness_beacon: &[u8; 32],
    ordered_transactions_root_hash: &[u8; 32],
    resulting_state_root_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(&(
        b"aft::canonical-order::recoverability::v1".as_slice(),
        bulletin_commitment,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
    ))
}

/// Builds the explicit bulletin availability certificate for a canonical order surface.
pub fn build_bulletin_availability_certificate(
    bulletin_commitment: &BulletinCommitment,
    randomness_beacon: &[u8; 32],
    ordered_transactions_root_hash: &[u8; 32],
    resulting_state_root_hash: &[u8; 32],
) -> Result<BulletinAvailabilityCertificate, String> {
    Ok(BulletinAvailabilityCertificate {
        height: bulletin_commitment.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        recoverability_root: canonical_recoverability_root(
            bulletin_commitment,
            randomness_beacon,
            ordered_transactions_root_hash,
            resulting_state_root_hash,
        )?,
    })
}

/// Verifies a bulletin availability certificate against its public binding inputs.
pub fn verify_bulletin_availability_binding(
    certificate: &BulletinAvailabilityCertificate,
    bulletin_commitment: &BulletinCommitment,
) -> Result<(), String> {
    if certificate.height != bulletin_commitment.height {
        return Err("bulletin availability certificate height does not match bulletin commitment"
            .into());
    }
    let expected_commitment_hash = canonical_bulletin_commitment_hash(bulletin_commitment)?;
    if certificate.bulletin_commitment_hash != expected_commitment_hash {
        return Err(
            "bulletin availability certificate does not match the bulletin commitment hash".into(),
        );
    }
    Ok(())
}

/// Verifies a bulletin availability certificate against its public binding inputs.
pub fn verify_bulletin_availability_certificate(
    certificate: &BulletinAvailabilityCertificate,
    bulletin_commitment: &BulletinCommitment,
    randomness_beacon: &[u8; 32],
    ordered_transactions_root_hash: &[u8; 32],
    resulting_state_root_hash: &[u8; 32],
) -> Result<(), String> {
    verify_bulletin_availability_binding(certificate, bulletin_commitment)?;
    let expected_recoverability_root = canonical_recoverability_root(
        bulletin_commitment,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
    )?;
    if certificate.recoverability_root != expected_recoverability_root {
        return Err(
            "bulletin availability certificate does not match the recoverability root".into(),
        );
    }
    Ok(())
}

/// Builds the canonical bulletin-close object for a closed bulletin surface.
pub fn build_canonical_bulletin_close(
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
) -> Result<CanonicalBulletinClose, String> {
    if bulletin_commitment.height != bulletin_availability_certificate.height {
        return Err(
            "canonical bulletin close requires same-height commitment and availability certificate"
                .into(),
        );
    }
    Ok(CanonicalBulletinClose {
        height: bulletin_commitment.height,
        cutoff_timestamp_ms: bulletin_commitment.cutoff_timestamp_ms,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(bulletin_commitment)?,
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            bulletin_availability_certificate,
        )?,
        entry_count: bulletin_commitment.entry_count,
    })
}

/// Verifies a canonical bulletin-close object against its public bulletin artifacts.
pub fn verify_canonical_bulletin_close(
    close: &CanonicalBulletinClose,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
) -> Result<(), String> {
    if close.height != bulletin_commitment.height
        || close.height != bulletin_availability_certificate.height
    {
        return Err("canonical bulletin close height does not match its public artifacts".into());
    }
    if close.cutoff_timestamp_ms != bulletin_commitment.cutoff_timestamp_ms {
        return Err("canonical bulletin close cutoff does not match the bulletin commitment".into());
    }
    if close.entry_count != bulletin_commitment.entry_count {
        return Err("canonical bulletin close entry count does not match the bulletin commitment".into());
    }
    let expected_commitment_hash = canonical_bulletin_commitment_hash(bulletin_commitment)?;
    if close.bulletin_commitment_hash != expected_commitment_hash {
        return Err("canonical bulletin close does not match the bulletin commitment hash".into());
    }
    let expected_availability_hash =
        canonical_bulletin_availability_certificate_hash(bulletin_availability_certificate)?;
    if close.bulletin_availability_certificate_hash != expected_availability_hash {
        return Err(
            "canonical bulletin close does not match the bulletin availability certificate hash"
                .into(),
        );
    }
    Ok(())
}

fn canonical_omission_commitment_root(omissions: &[OmissionProof]) -> Result<[u8; 32], String> {
    let mut normalized = omissions.to_vec();
    normalized.sort_unstable_by(|left, right| {
        left.height
            .cmp(&right.height)
            .then(left.tx_hash.cmp(&right.tx_hash))
            .then(left.bulletin_root.cmp(&right.bulletin_root))
            .then(left.details.cmp(&right.details))
    });
    for window in normalized.windows(2) {
        if window[0].height == window[1].height && window[0].tx_hash == window[1].tx_hash {
            return Err(
                "canonical omission set must not contain duplicate transaction hashes".into(),
            );
        }
    }
    hash_consensus_bytes(&(
        b"aft::canonical-order::omissions::v1".as_slice(),
        &normalized,
    ))
}

fn canonical_order_score(
    randomness_beacon: &[u8; 32],
    tx_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::rank::v1".len() + randomness_beacon.len() + tx_hash.len(),
    );
    material.extend_from_slice(b"aft::canonical-order::rank::v1");
    material.extend_from_slice(randomness_beacon);
    material.extend_from_slice(tx_hash);
    hash_consensus_bytes(&material)
}

/// Returns the deterministic canonical ordering of a bulletin-surface tx-hash set.
pub fn canonical_order_tx_hashes(
    randomness_beacon: &[u8; 32],
    tx_hashes: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, String> {
    ensure_sorted_unique_tx_hashes(tx_hashes)?;
    let mut ranked = Vec::with_capacity(tx_hashes.len());
    for tx_hash in tx_hashes {
        ranked.push((canonical_order_score(randomness_beacon, tx_hash)?, *tx_hash));
    }
    ranked.sort_unstable_by(|left, right| left.cmp(right));
    Ok(ranked.into_iter().map(|(_, tx_hash)| tx_hash).collect())
}

/// Returns the canonical ordered transaction root for an ordered transaction-hash list.
pub fn canonical_transaction_root_from_hashes(tx_hashes: &[[u8; 32]]) -> Result<Vec<u8>, String> {
    hash_consensus_bytes(&tx_hashes).map(|digest| digest.to_vec())
}

/// Returns the canonical ordered transaction root for a concrete ordered transaction list.
pub fn canonical_transactions_root(transactions: &[ChainTransaction]) -> Result<Vec<u8>, String> {
    let mut tx_hashes = Vec::with_capacity(transactions.len());
    for tx in transactions {
        tx_hashes.push(tx.hash().map_err(|e| e.to_string())?);
    }
    canonical_transaction_root_from_hashes(&tx_hashes)
}

/// Returns the sorted unique bulletin-surface entries for a candidate slot.
pub fn build_bulletin_surface_entries(
    height: u64,
    transactions: &[ChainTransaction],
) -> Result<Vec<BulletinSurfaceEntry>, String> {
    let mut tx_hashes = Vec::with_capacity(transactions.len());
    for tx in transactions {
        tx_hashes.push(tx.hash().map_err(|e| e.to_string())?);
    }
    tx_hashes.sort_unstable();
    ensure_sorted_unique_tx_hashes(&tx_hashes)?;
    Ok(tx_hashes
        .into_iter()
        .map(|tx_hash| BulletinSurfaceEntry { height, tx_hash })
        .collect())
}

/// Orders a candidate transaction batch according to the slot's canonical order rule.
pub fn canonicalize_transactions_for_header(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<Vec<ChainTransaction>, String> {
    let randomness_beacon = derive_reference_ordering_randomness_beacon(header)?;
    let mut ranked = Vec::with_capacity(transactions.len());
    for tx in transactions {
        let tx_hash = tx.hash().map_err(|e| e.to_string())?;
        ranked.push((
            canonical_order_score(&randomness_beacon, &tx_hash)?,
            tx_hash,
            tx.clone(),
        ));
    }
    ranked.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    for window in ranked.windows(2) {
        if window[0].1 == window[1].1 {
            return Err("canonical order requires unique transaction hashes per slot".into());
        }
    }
    Ok(ranked.into_iter().map(|(_, _, tx)| tx).collect())
}

/// Derives the reference public randomness beacon for a canonical order certificate.
pub fn derive_reference_ordering_randomness_beacon(
    header: &BlockHeader,
) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::randomness::v1".len()
            + std::mem::size_of::<u64>() * 2
            + header.parent_hash.len()
            + header.producer_account_id.0.len(),
    );
    material.extend_from_slice(b"aft::canonical-order::randomness::v1");
    material.extend_from_slice(&header.height.to_be_bytes());
    material.extend_from_slice(&header.view.to_be_bytes());
    material.extend_from_slice(&header.parent_hash);
    material.extend_from_slice(&header.producer_account_id.0);
    hash_consensus_bytes(&material)
}

/// Builds the reference bulletin-board commitment for a block's admitted transaction surface.
pub fn build_reference_bulletin_commitment(
    height: u64,
    cutoff_timestamp_ms: u64,
    transactions: &[ChainTransaction],
) -> Result<BulletinCommitment, String> {
    let entries = build_bulletin_surface_entries(height, transactions)?;
    let tx_hashes: Vec<[u8; 32]> = entries.into_iter().map(|entry| entry.tx_hash).collect();
    build_bulletin_commitment_from_hashes(height, cutoff_timestamp_ms, &tx_hashes)
}

/// Returns the canonical public inputs for a block header and candidate order certificate.
pub fn canonical_order_public_inputs(
    header: &BlockHeader,
    certificate: &CanonicalOrderCertificate,
) -> Result<CanonicalOrderPublicInputs, String> {
    Ok(CanonicalOrderPublicInputs {
        height: header.height,
        parent_state_root_hash: to_root_hash(&header.parent_state_root.0)
            .map_err(|e| e.to_string())?,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(
            &certificate.bulletin_commitment,
        )?,
        randomness_beacon: certificate.randomness_beacon,
        ordered_transactions_root_hash: to_root_hash(&header.transactions_root)
            .map_err(|e| e.to_string())?,
        resulting_state_root_hash: to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?,
        cutoff_timestamp_ms: certificate.bulletin_commitment.cutoff_timestamp_ms,
    })
}

/// Returns the canonical hash of a canonical-order public-input set.
pub fn canonical_order_public_inputs_hash(
    public_inputs: &CanonicalOrderPublicInputs,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(public_inputs)
}

/// Builds the reference proof bytes for a canonical order certificate.
pub fn build_reference_canonical_order_proof_bytes(
    public_inputs_hash: [u8; 32],
) -> Result<Vec<u8>, String> {
    let mut material = Vec::with_capacity(
        b"aft::canonical-order::hash-binding::v1".len() + public_inputs_hash.len(),
    );
    material.extend_from_slice(b"aft::canonical-order::hash-binding::v1");
    material.extend_from_slice(&public_inputs_hash);
    Ok(DcryptSha256::digest(&material)
        .map_err(|e| e.to_string())?
        .to_vec())
}

/// Builds the reference canonical-order certificate for a finalized block.
pub fn build_reference_canonical_order_certificate(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderCertificate, String> {
    let bulletin_commitment = build_reference_bulletin_commitment(
        header.height,
        header.timestamp.saturating_mul(1000),
        transactions,
    )?;
    let ordered_transactions_root_hash =
        to_root_hash(&header.transactions_root).map_err(|e| e.to_string())?;
    let resulting_state_root_hash =
        to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?;
    let randomness_beacon = derive_reference_ordering_randomness_beacon(header)?;
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin_commitment,
        &randomness_beacon,
        &ordered_transactions_root_hash,
        &resulting_state_root_hash,
    )?;

    let mut certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment,
        bulletin_availability_certificate,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
        proof: CanonicalOrderProof::default(),
        omission_proofs: Vec::new(),
    };
    let public_inputs = canonical_order_public_inputs(header, &certificate)?;
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs)?;
    certificate.proof = CanonicalOrderProof {
        proof_system: CanonicalOrderProofSystem::HashBindingV1,
        public_inputs_hash,
        proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash)?,
    };
    Ok(certificate)
}

/// Builds a succinct committed-surface canonical-order certificate for a finalized block.
pub fn build_committed_surface_canonical_order_certificate(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderCertificate, String> {
    let entries = build_bulletin_surface_entries(header.height, transactions)?;
    let tx_hashes: Vec<[u8; 32]> = entries.iter().map(|entry| entry.tx_hash).collect();
    let bulletin_commitment = build_bulletin_commitment_from_hashes(
        header.height,
        header.timestamp.saturating_mul(1000),
        &tx_hashes,
    )?;
    let randomness_beacon = derive_reference_ordering_randomness_beacon(header)?;
    let expected_order = canonical_order_tx_hashes(&randomness_beacon, &tx_hashes)?;
    let expected_transactions_root = canonical_transaction_root_from_hashes(&expected_order)?;
    if header.transactions_root != expected_transactions_root {
        return Err("block transactions do not match the committed canonical order".into());
    }
    let ordered_transactions_root_hash =
        to_root_hash(&expected_transactions_root).map_err(|e| e.to_string())?;
    let resulting_state_root_hash =
        to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?;
    let omission_proofs = Vec::new();
    let bulletin_availability_certificate = build_bulletin_availability_certificate(
        &bulletin_commitment,
        &randomness_beacon,
        &ordered_transactions_root_hash,
        &resulting_state_root_hash,
    )?;
    let proof = CommittedSurfaceCanonicalOrderProof {
        bulletin_availability_certificate_hash: canonical_bulletin_availability_certificate_hash(
            &bulletin_availability_certificate,
        )?,
        omission_commitment_root: canonical_omission_commitment_root(&omission_proofs)?,
    };

    let mut certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment,
        bulletin_availability_certificate,
        randomness_beacon,
        ordered_transactions_root_hash,
        resulting_state_root_hash,
        proof: CanonicalOrderProof::default(),
        omission_proofs,
    };
    let public_inputs = canonical_order_public_inputs(header, &certificate)?;
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs)?;
    certificate.proof = CanonicalOrderProof {
        proof_system: CanonicalOrderProofSystem::CommittedSurfaceV1,
        public_inputs_hash,
        proof_bytes: codec::to_bytes_canonical(&proof).map_err(|e| e.to_string())?,
    };
    Ok(certificate)
}

/// Verifies a canonical order certificate against a block header and optional published bulletin.
pub fn verify_canonical_order_certificate(
    header: &BlockHeader,
    certificate: &CanonicalOrderCertificate,
    published_bulletin: Option<&BulletinCommitment>,
    published_bulletin_availability: Option<&BulletinAvailabilityCertificate>,
    published_bulletin_close: Option<&CanonicalBulletinClose>,
) -> Result<(), String> {
    if certificate.height != header.height
        || certificate.bulletin_commitment.height != header.height
        || certificate.bulletin_availability_certificate.height != header.height
    {
        return Err("canonical order certificate height does not match block height".into());
    }
    if certificate.randomness_beacon != derive_reference_ordering_randomness_beacon(header)? {
        return Err(
            "canonical order certificate randomness beacon does not match the slot schedule".into(),
        );
    }
    if let Some(published_bulletin) = published_bulletin {
        if published_bulletin != &certificate.bulletin_commitment {
            return Err(
                "canonical order certificate bulletin commitment does not match published bulletin"
                    .into(),
            );
        }
    }
    if let Some(published_bulletin_availability) = published_bulletin_availability {
        if published_bulletin_availability != &certificate.bulletin_availability_certificate {
            return Err(
                "canonical order certificate bulletin availability certificate does not match published bulletin availability"
                    .into(),
            );
        }
    }
    if let Some(published_bulletin_close) = published_bulletin_close {
        verify_canonical_bulletin_close(
            published_bulletin_close,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )?;
    }
    if !certificate.omission_proofs.is_empty() {
        return Err("canonical order certificate is dominated by objective omission proofs".into());
    }
    let public_inputs = canonical_order_public_inputs(header, certificate)?;
    if certificate.ordered_transactions_root_hash != public_inputs.ordered_transactions_root_hash {
        return Err(
            "canonical order certificate transactions root does not match block header".into(),
        );
    }
    if certificate.resulting_state_root_hash != public_inputs.resulting_state_root_hash {
        return Err(
            "canonical order certificate resulting state root does not match block header".into(),
        );
    }
    let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs)?;
    if certificate.proof.public_inputs_hash != public_inputs_hash {
        return Err("canonical order proof does not match canonical public inputs".into());
    }
    verify_bulletin_availability_certificate(
        &certificate.bulletin_availability_certificate,
        &certificate.bulletin_commitment,
        &certificate.randomness_beacon,
        &certificate.ordered_transactions_root_hash,
        &certificate.resulting_state_root_hash,
    )?;
    match certificate.proof.proof_system {
        CanonicalOrderProofSystem::HashBindingV1 => {
            let expected = build_reference_canonical_order_proof_bytes(public_inputs_hash)?;
            if certificate.proof.proof_bytes != expected {
                return Err("canonical order hash-binding proof bytes are invalid".into());
            }
        }
        CanonicalOrderProofSystem::CommittedSurfaceV1 => {
            let proof: CommittedSurfaceCanonicalOrderProof =
                codec::from_bytes_canonical(&certificate.proof.proof_bytes)
                    .map_err(|e| e.to_string())?;
            let availability_certificate_hash =
                canonical_bulletin_availability_certificate_hash(
                    &certificate.bulletin_availability_certificate,
                )?;
            if availability_certificate_hash != proof.bulletin_availability_certificate_hash {
                return Err(
                    "committed-surface canonical order proof does not match the bulletin availability certificate"
                        .into(),
                );
            }
            let omission_commitment_root =
                canonical_omission_commitment_root(&certificate.omission_proofs)?;
            if omission_commitment_root != proof.omission_commitment_root {
                return Err(
                    "committed-surface canonical order proof does not match the omission commitment root"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

/// Verifies that a published bulletin surface rebuilds the specified bulletin commitment.
pub fn verify_bulletin_surface_entries(
    height: u64,
    bulletin_commitment: &BulletinCommitment,
    entries: &[BulletinSurfaceEntry],
) -> Result<(), String> {
    let entry_height = entries.first().map(|entry| entry.height).unwrap_or(height);
    if entry_height != height || entries.iter().any(|entry| entry.height != height)
    {
        return Err("bulletin surface entries do not match the target slot height".into());
    }
    let tx_hashes: Vec<[u8; 32]> = entries.iter().map(|entry| entry.tx_hash).collect();
    let rebuilt_commitment = build_bulletin_commitment_from_hashes(
        height,
        bulletin_commitment.cutoff_timestamp_ms,
        &tx_hashes,
    )?;
    if rebuilt_commitment != *bulletin_commitment {
        return Err("published bulletin surface does not rebuild the bulletin commitment".into());
    }
    Ok(())
}

/// Verifies that a published bulletin surface rebuilds the bulletin commitment carried by a
/// canonical-order certificate.
pub fn verify_bulletin_surface_publication(
    certificate: &CanonicalOrderCertificate,
    entries: &[BulletinSurfaceEntry],
) -> Result<(), String> {
    verify_bulletin_surface_entries(certificate.height, &certificate.bulletin_commitment, entries)
}

/// Deterministically extracts the canonical closed bulletin surface from published artifacts.
pub fn extract_canonical_bulletin_surface(
    close: &CanonicalBulletinClose,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    entries: &[BulletinSurfaceEntry],
) -> Result<Vec<BulletinSurfaceEntry>, String> {
    verify_canonical_bulletin_close(close, bulletin_commitment, bulletin_availability_certificate)?;
    let mut canonical_entries = entries.to_vec();
    canonical_entries.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
    verify_bulletin_surface_entries(close.height, bulletin_commitment, &canonical_entries)?;
    let expected_entry_count = usize::try_from(close.entry_count)
        .map_err(|_| "canonical bulletin close entry count does not fit into usize".to_string())?;
    if canonical_entries.len() != expected_entry_count {
        return Err("canonical bulletin close entry count does not match the published bulletin surface".into());
    }
    Ok(canonical_entries)
}

/// Verifies that an atomic canonical-order publication bundle is self-consistent and
/// deterministically yields one canonical bulletin-close object.
pub fn verify_canonical_order_publication_bundle(
    bundle: &CanonicalOrderPublicationBundle,
) -> Result<CanonicalBulletinClose, String> {
    if bundle.bulletin_commitment.height == 0
        || bundle.bulletin_availability_certificate.height == 0
        || bundle.canonical_order_certificate.height == 0
    {
        return Err("canonical order publication bundle requires non-zero heights".into());
    }
    if bundle.canonical_order_certificate.bulletin_commitment != bundle.bulletin_commitment {
        return Err(
            "canonical order publication bundle certificate does not match the bulletin commitment"
                .into(),
        );
    }
    if bundle.canonical_order_certificate.bulletin_availability_certificate
        != bundle.bulletin_availability_certificate
    {
        return Err(
            "canonical order publication bundle certificate does not match the bulletin availability certificate"
                .into(),
        );
    }
    let close = build_canonical_bulletin_close(
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
    )?;
    let _ = extract_canonical_bulletin_surface(
        &close,
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
        &bundle.bulletin_entries,
    )?;
    Ok(close)
}

fn build_canonical_order_abort(
    height: u64,
    reason: CanonicalOrderAbortReason,
    details: impl Into<String>,
    certificate: Option<&CanonicalOrderCertificate>,
    close: Option<&CanonicalBulletinClose>,
) -> CanonicalOrderAbort {
    let bulletin_commitment_hash = certificate
        .and_then(|candidate| canonical_bulletin_commitment_hash(&candidate.bulletin_commitment).ok())
        .unwrap_or([0u8; 32]);
    let bulletin_availability_certificate_hash = certificate
        .and_then(|candidate| {
            canonical_bulletin_availability_certificate_hash(
                &candidate.bulletin_availability_certificate,
            )
            .ok()
        })
        .unwrap_or([0u8; 32]);
    let bulletin_close_hash = close
        .and_then(|candidate| canonical_bulletin_close_hash(candidate).ok())
        .unwrap_or([0u8; 32]);
    let canonical_order_certificate_hash = certificate
        .and_then(|candidate| canonical_order_certificate_hash(candidate).ok())
        .unwrap_or([0u8; 32]);

    CanonicalOrderAbort {
        height,
        reason,
        details: details.into(),
        bulletin_commitment_hash,
        bulletin_availability_certificate_hash,
        bulletin_close_hash,
        canonical_order_certificate_hash,
    }
}

fn classify_canonical_order_certificate_error(error: &str) -> CanonicalOrderAbortReason {
    if error.contains("height does not match block height") {
        CanonicalOrderAbortReason::CertificateHeightMismatch
    } else if error.contains("randomness beacon does not match the slot schedule") {
        CanonicalOrderAbortReason::RandomnessMismatch
    } else if error.contains("transactions root does not match block header") {
        CanonicalOrderAbortReason::OrderedTransactionsRootMismatch
    } else if error.contains("resulting state root does not match block header") {
        CanonicalOrderAbortReason::ResultingStateRootMismatch
    } else if error.contains("proof does not match canonical public inputs") {
        CanonicalOrderAbortReason::InvalidPublicInputsHash
    } else if error.contains("recoverability root")
        || error.contains("bulletin commitment hash")
        || error.contains("published bulletin availability")
    {
        CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate
    } else {
        CanonicalOrderAbortReason::InvalidProofBinding
    }
}

/// Deterministically derives the canonical public execution object for a committed ordering slot.
/// If the slot's proof-carried public surface is missing or invalid, returns the canonical abort
/// object that dominates the positive close path.
pub fn derive_canonical_order_execution_object(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalOrderExecutionObject, CanonicalOrderAbort> {
    let Some(certificate) = header.canonical_order_certificate.as_ref() else {
        return Err(build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::MissingOrderCertificate,
            "committed block does not carry a canonical-order certificate",
            None,
            None,
        ));
    };

    let bulletin_close = build_canonical_bulletin_close(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
    )
    .map_err(|error| {
        build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::InvalidBulletinClose,
            format!("failed to derive canonical bulletin close: {error}"),
            Some(certificate),
            None,
        )
    })?;

    if !certificate.omission_proofs.is_empty() {
        return Err(build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::OmissionDominated,
            "objective omission proofs dominate the candidate canonical order",
            Some(certificate),
            Some(&bulletin_close),
        ));
    }

    if let Err(error) = verify_canonical_order_certificate(
        header,
        certificate,
        Some(&certificate.bulletin_commitment),
        Some(&certificate.bulletin_availability_certificate),
        Some(&bulletin_close),
    ) {
        return Err(build_canonical_order_abort(
            header.height,
            classify_canonical_order_certificate_error(&error),
            format!("canonical-order certificate verification failed: {error}"),
            Some(certificate),
            Some(&bulletin_close),
        ));
    }

    let bulletin_entries =
        build_bulletin_surface_entries(header.height, transactions).map_err(|error| {
            build_canonical_order_abort(
                header.height,
                CanonicalOrderAbortReason::BulletinSurfaceReconstructionFailure,
                format!("failed to reconstruct canonical bulletin surface: {error}"),
                Some(certificate),
                Some(&bulletin_close),
            )
        })?;

    if let Err(error) = verify_bulletin_surface_publication(certificate, &bulletin_entries) {
        return Err(build_canonical_order_abort(
            header.height,
            CanonicalOrderAbortReason::BulletinSurfaceMismatch,
            format!("proof-carried bulletin surface is invalid: {error}"),
            Some(certificate),
            Some(&bulletin_close),
        ));
    }

    Ok(CanonicalOrderExecutionObject {
        bulletin_commitment: certificate.bulletin_commitment.clone(),
        bulletin_entries,
        bulletin_availability_certificate: certificate.bulletin_availability_certificate.clone(),
        bulletin_close,
        canonical_order_certificate: certificate.clone(),
    })
}

/// Derives the canonical public obstruction for a committed ordering slot, if one exists.
pub fn derive_canonical_order_public_obstruction(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Option<CanonicalOrderAbort> {
    derive_canonical_order_execution_object(header, transactions).err()
}

/// Derives the sealing-side component of the protocol-wide canonical collapse object.
pub fn derive_canonical_sealing_collapse(
    proof: &SealedFinalityProof,
) -> Result<CanonicalSealingCollapse, String> {
    let transcripts_root = canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)?;
    let challenges_root = canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)?;

    if let Some(commitment) = proof.observer_transcript_commitment.as_ref() {
        if commitment.transcripts_root != transcripts_root {
            return Err(
                "sealed finality proof transcript commitment does not match the canonical transcript surface"
                    .into(),
            );
        }
        if commitment.transcript_count != proof.observer_transcripts.len() as u16 {
            return Err(
                "sealed finality proof transcript commitment count does not match the transcript surface"
                    .into(),
            );
        }
    }
    if let Some(commitment) = proof.observer_challenge_commitment.as_ref() {
        if commitment.challenges_root != challenges_root {
            return Err(
                "sealed finality proof challenge commitment does not match the canonical challenge surface"
                    .into(),
            );
        }
        if commitment.challenge_count != proof.observer_challenges.len() as u16 {
            return Err(
                "sealed finality proof challenge commitment count does not match the challenge surface"
                    .into(),
            );
        }
    }

    match proof.collapse_state {
        CollapseState::SealedFinal => {
            if proof.finality_tier != FinalityTier::SealedFinal {
                return Err(
                    "sealed finality proof close path must carry the SealedFinal tier".into(),
                );
            }
            let close = proof
                .observer_canonical_close
                .as_ref()
                .ok_or_else(|| "sealed finality proof is missing a canonical observer close".to_string())?;
            if proof.observer_canonical_abort.is_some() {
                return Err(
                    "sealed finality proof close path may not also carry a canonical observer abort"
                        .into(),
                );
            }
            if close.transcripts_root != transcripts_root
                || close.challenges_root != challenges_root
            {
                return Err(
                    "sealed finality proof close path does not match the canonical observer surface"
                        .into(),
                );
            }
            if close.transcript_count != proof.observer_transcripts.len() as u16
                || close.challenge_count != proof.observer_challenges.len() as u16
            {
                return Err(
                    "sealed finality proof close counts do not match the canonical observer surface"
                        .into(),
                );
            }
            if !proof.observer_challenges.is_empty() || close.challenge_count != 0 {
                return Err(
                    "sealed finality proof close path is challenge-dominated and therefore not decisive"
                        .into(),
                );
            }
            Ok(CanonicalSealingCollapse {
                epoch: proof.epoch,
                height: close.height,
                view: close.view,
                kind: CanonicalCollapseKind::Close,
                finality_tier: proof.finality_tier.clone(),
                collapse_state: proof.collapse_state,
                transcripts_root,
                challenges_root,
                resolution_hash: canonical_asymptote_observer_canonical_close_hash(close)?,
            })
        }
        CollapseState::Abort => {
            if proof.finality_tier != FinalityTier::BaseFinal {
                return Err("sealed finality proof abort path must carry the BaseFinal tier".into());
            }
            let abort = proof
                .observer_canonical_abort
                .as_ref()
                .ok_or_else(|| "sealed finality proof is missing a canonical observer abort".to_string())?;
            if proof.observer_canonical_close.is_some() {
                return Err(
                    "sealed finality proof abort path may not also carry a canonical observer close"
                        .into(),
                );
            }
            if abort.transcripts_root != transcripts_root
                || abort.challenges_root != challenges_root
            {
                return Err(
                    "sealed finality proof abort path does not match the canonical observer surface"
                        .into(),
                );
            }
            if abort.transcript_count != proof.observer_transcripts.len() as u16
                || abort.challenge_count != proof.observer_challenges.len() as u16
            {
                return Err(
                    "sealed finality proof abort counts do not match the canonical observer surface"
                        .into(),
                );
            }
            if proof.observer_challenges.is_empty() || abort.challenge_count == 0 {
                return Err(
                    "sealed finality proof abort path must bind a non-empty canonical challenge surface"
                        .into(),
                );
            }
            Ok(CanonicalSealingCollapse {
                epoch: proof.epoch,
                height: abort.height,
                view: abort.view,
                kind: CanonicalCollapseKind::Abort,
                finality_tier: proof.finality_tier.clone(),
                collapse_state: proof.collapse_state,
                transcripts_root,
                challenges_root,
                resolution_hash: canonical_asymptote_observer_canonical_abort_hash(abort)?,
            })
        }
        state => Err(format!(
            "sealed finality proof is not in a decisive canonical collapse state: {:?}",
            state
        )),
    }
}

/// Derives the protocol-wide canonical collapse object for a committed AFT block.
pub fn derive_canonical_collapse_object(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
) -> Result<CanonicalCollapseObject, String> {
    derive_canonical_collapse_object_with_previous(header, transactions, None)
}

/// Derives the protocol-wide canonical collapse object while binding the previous slot's
/// collapse commitment into the current slot's continuity surface.
pub fn derive_canonical_collapse_object_with_previous(
    header: &BlockHeader,
    transactions: &[ChainTransaction],
    previous: Option<&CanonicalCollapseObject>,
) -> Result<CanonicalCollapseObject, String> {
    let ordering = match derive_canonical_order_execution_object(header, transactions) {
        Ok(execution_object) => CanonicalOrderingCollapse {
            height: header.height,
            kind: CanonicalCollapseKind::Close,
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &execution_object.bulletin_commitment,
            )?,
            bulletin_availability_certificate_hash:
                canonical_bulletin_availability_certificate_hash(
                    &execution_object.bulletin_availability_certificate,
                )?,
            bulletin_close_hash: canonical_bulletin_close_hash(&execution_object.bulletin_close)?,
            canonical_order_certificate_hash: canonical_order_certificate_hash(
                &execution_object.canonical_order_certificate,
            )?,
        },
        Err(abort) => CanonicalOrderingCollapse {
            height: abort.height,
            kind: CanonicalCollapseKind::Abort,
            bulletin_commitment_hash: abort.bulletin_commitment_hash,
            bulletin_availability_certificate_hash: abort.bulletin_availability_certificate_hash,
            bulletin_close_hash: abort.bulletin_close_hash,
            canonical_order_certificate_hash: abort.canonical_order_certificate_hash,
        },
    };
    let sealing = header
        .sealed_finality_proof
        .as_ref()
        .map(derive_canonical_sealing_collapse)
        .transpose()?;
    verify_block_header_canonical_collapse_evidence(header, previous)?;

    let mut collapse = CanonicalCollapseObject {
        height: header.height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering,
        sealing,
        transactions_root_hash: to_root_hash(&header.transactions_root)
            .map_err(|e| e.to_string())?,
        resulting_state_root_hash: to_root_hash(&header.state_root.0).map_err(|e| e.to_string())?,
    };
    bind_canonical_collapse_continuity(&mut collapse, previous)?;
    Ok(collapse)
}

#[cfg(test)]
mod tests {
    use super::{
        build_canonical_bulletin_close, build_committed_surface_canonical_order_certificate,
        build_reference_canonical_order_certificate, canonical_transaction_root_from_hashes,
        canonicalize_transactions_for_header, canonical_collapse_extension_certificate,
        canonical_collapse_recursive_proof_hash,
        canonical_collapse_commitment_hash_from_object,
        canonical_collapse_object_hash,
        bind_canonical_collapse_continuity,
        canonical_order_certificate_hash, derive_canonical_collapse_object,
        derive_canonical_collapse_object_with_previous,
        expected_previous_canonical_collapse_commitment_hash,
        derive_canonical_order_execution_object, derive_canonical_order_public_obstruction,
        extract_canonical_bulletin_surface, verify_bulletin_surface_publication,
        verify_block_header_canonical_collapse_evidence, verify_canonical_collapse_continuity,
        verify_canonical_collapse_recursive_proof,
        verify_canonical_collapse_recursive_proof_matches_collapse,
        verify_canonical_order_certificate, verify_canonical_order_publication_bundle,
        CanonicalCollapseContinuityProofSystem, CanonicalCollapseKind, CanonicalOrderAbortReason,
    };
    use crate::app::{
        canonical_asymptote_observer_canonical_close_hash,
        canonical_asymptote_observer_challenges_hash,
        canonical_asymptote_observer_transcripts_hash, to_root_hash, AccountId,
        AsymptoteObserverCanonicalClose, BlockHeader, ChainId, ChainTransaction, CollapseState,
        CanonicalCollapseExtensionCertificate, CanonicalOrderCertificate,
        CanonicalCollapseObject, CanonicalOrderingCollapse, FinalityTier, OmissionProof,
        QuorumCertificate,
        SealedFinalityProof, SignHeader, SignatureProof, SignatureSuite, StateRoot,
        SystemPayload, SystemTransaction,
    };
    use std::sync::{Mutex, OnceLock};

    fn certificate_from_predecessor(
        predecessor: &CanonicalCollapseObject,
    ) -> CanonicalCollapseExtensionCertificate {
        canonical_collapse_extension_certificate(predecessor.height + 1, predecessor)
            .expect("extension certificate")
    }

    fn sample_canonical_collapse_object(
        height: u64,
        previous: Option<&CanonicalCollapseObject>,
        seed: u8,
    ) -> CanonicalCollapseObject {
        let mut collapse = CanonicalCollapseObject {
            height,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [seed; 32],
                bulletin_availability_certificate_hash: [seed.wrapping_add(1); 32],
                bulletin_close_hash: [seed.wrapping_add(2); 32],
                canonical_order_certificate_hash: [seed.wrapping_add(3); 32],
            },
            sealing: None,
            transactions_root_hash: [seed.wrapping_add(4); 32],
            resulting_state_root_hash: [seed.wrapping_add(5); 32],
        };
        bind_canonical_collapse_continuity(&mut collapse, previous)
            .expect("bind canonical collapse continuity");
        collapse
    }

    fn sample_ordering_header(height: u64, view: u64, seed: u8) -> BlockHeader {
        BlockHeader {
            height,
            view,
            parent_hash: [seed.wrapping_add(1); 32],
            parent_state_root: StateRoot(vec![seed.wrapping_add(2); 32]),
            state_root: StateRoot(vec![seed.wrapping_add(3); 32]),
            transactions_root: vec![],
            timestamp: 1_750_000_000 + height,
            timestamp_ms: (1_750_000_000 + height) * 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([seed.wrapping_add(4); 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [seed.wrapping_add(5); 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        }
    }

    fn sample_ordering_transactions(seed: u8) -> Vec<ChainTransaction> {
        vec![
            ChainTransaction::System(Box::new(SystemTransaction {
                header: SignHeader {
                    account_id: AccountId([seed.wrapping_add(10); 32]),
                    nonce: 1,
                    chain_id: ChainId(1),
                    tx_version: 1,
                    session_auth: None,
                },
                payload: SystemPayload::CallService {
                    service_id: "guardian_registry".into(),
                    method: "publish_aft_bulletin_commitment@v1".into(),
                    params: vec![seed],
                },
                signature_proof: SignatureProof::default(),
            })),
            ChainTransaction::System(Box::new(SystemTransaction {
                header: SignHeader {
                    account_id: AccountId([seed.wrapping_add(11); 32]),
                    nonce: 1,
                    chain_id: ChainId(1),
                    tx_version: 1,
                    session_auth: None,
                },
                payload: SystemPayload::CallService {
                    service_id: "guardian_registry".into(),
                    method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                    params: vec![seed.wrapping_add(1)],
                },
                signature_proof: SignatureProof::default(),
            })),
        ]
    }

    fn sample_committed_surface_ordering_fixture(
        height: u64,
        view: u64,
        seed: u8,
    ) -> (BlockHeader, Vec<ChainTransaction>, CanonicalOrderCertificate) {
        let mut header = sample_ordering_header(height, view, seed);
        let transactions = canonicalize_transactions_for_header(
            &header,
            &sample_ordering_transactions(seed),
        )
        .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();
        header.transactions_root =
            canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &transactions)
                .expect("build committed-surface certificate");
        header.canonical_order_certificate = Some(certificate.clone());
        (header, transactions, certificate)
    }

    fn continuity_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn reference_canonical_order_certificate_verifies_for_empty_block() {
        let header = BlockHeader {
            height: 7,
            view: 2,
            parent_hash: [9u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_000_123,
            timestamp_ms: 1_750_000_123_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([4u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [5u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let certificate =
            build_reference_canonical_order_certificate(&header, &[]).expect("build certificate");
        assert!(certificate.omission_proofs.is_empty());
        assert_ne!(certificate.bulletin_commitment.bulletin_root, [0u8; 32]);
        let bulletin_close = build_canonical_bulletin_close(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build bulletin close");
        verify_canonical_order_certificate(
            &header,
            &certificate,
            Some(&certificate.bulletin_commitment),
            Some(&certificate.bulletin_availability_certificate),
            Some(&bulletin_close),
        )
        .expect("verify canonical order certificate");
    }

    #[test]
    fn committed_surface_canonical_order_certificate_verifies_for_canonical_block() {
        let base_header = BlockHeader {
            height: 11,
            view: 4,
            parent_hash: [19u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![],
            timestamp: 1_750_000_777,
            timestamp_ms: 1_750_000_777_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([4u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [5u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([12u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![3],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([13u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![4],
            },
            signature_proof: SignatureProof::default(),
        }));

        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
                .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root =
            canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");

        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate");
        let bulletin_close = build_canonical_bulletin_close(
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
        )
        .expect("build bulletin close");
        verify_canonical_order_certificate(
            &header,
            &certificate,
            Some(&certificate.bulletin_commitment),
            Some(&certificate.bulletin_availability_certificate),
            Some(&bulletin_close),
        )
        .expect("verify committed-surface certificate");
        let entries = super::build_bulletin_surface_entries(header.height, &ordered_transactions)
            .expect("build bulletin surface entries");
        verify_bulletin_surface_publication(&certificate, &entries)
            .expect("verify bulletin surface publication");
        let extracted = extract_canonical_bulletin_surface(
            &bulletin_close,
            &certificate.bulletin_commitment,
            &certificate.bulletin_availability_certificate,
            &entries,
        )
        .expect("extract bulletin surface");
        assert_eq!(extracted, entries);
        let rebuilt_close = verify_canonical_order_publication_bundle(
            &super::CanonicalOrderPublicationBundle {
                bulletin_commitment: certificate.bulletin_commitment.clone(),
                bulletin_entries: entries.clone(),
                bulletin_availability_certificate: certificate
                    .bulletin_availability_certificate
                    .clone(),
                canonical_order_certificate: certificate.clone(),
            },
        )
        .expect("verify publication bundle");
        assert_eq!(rebuilt_close, bulletin_close);

        header.canonical_order_certificate = Some(certificate.clone());
        let execution_object =
            derive_canonical_order_execution_object(&header, &ordered_transactions)
                .expect("derive canonical order execution object");
        assert_eq!(execution_object.bulletin_commitment, certificate.bulletin_commitment);
        assert_eq!(
            execution_object.bulletin_availability_certificate,
            certificate.bulletin_availability_certificate
        );
        assert_eq!(execution_object.bulletin_close, bulletin_close);
        assert_eq!(execution_object.canonical_order_certificate, certificate);
        assert_eq!(execution_object.bulletin_entries, entries);
    }

    #[test]
    fn derive_canonical_order_execution_object_returns_abort_without_certificate() {
        let header = BlockHeader {
            height: 13,
            view: 1,
            parent_hash: [31u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_000_888,
            timestamp_ms: 1_750_000_888_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([14u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [15u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let abort = derive_canonical_order_execution_object(&header, &[])
            .expect_err("missing canonical-order certificate must derive abort");
        assert_eq!(abort.height, header.height);
        assert_eq!(abort.reason, CanonicalOrderAbortReason::MissingOrderCertificate);
        assert_eq!(abort.canonical_order_certificate_hash, [0u8; 32]);
        assert!(abort
            .details
            .contains("does not carry a canonical-order certificate"));
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_surface() {
        let (header, ordered_transactions, _certificate) =
            sample_committed_surface_ordering_fixture(19, 2, 16);
        let invalid_surface = vec![ordered_transactions[0].clone()];

        let abort = derive_canonical_order_public_obstruction(&header, &invalid_surface)
            .expect("invalid surface should derive obstruction");
        assert_eq!(abort.height, header.height);
        assert_eq!(abort.reason, CanonicalOrderAbortReason::BulletinSurfaceMismatch);
        assert_ne!(abort.canonical_order_certificate_hash, [0u8; 32]);
        assert!(abort
            .details
            .contains("proof-carried bulletin surface is invalid"));
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_surface_reconstruction_failure() {
        let (header, ordered_transactions, _) = sample_committed_surface_ordering_fixture(29, 3, 24);
        let duplicate_transactions = vec![
            ordered_transactions[0].clone(),
            ordered_transactions[0].clone(),
        ];
        let abort = derive_canonical_order_public_obstruction(&header, &duplicate_transactions)
            .expect("duplicate tx surface should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::BulletinSurfaceReconstructionFailure
        );
        assert!(abort
            .details
            .contains("failed to reconstruct canonical bulletin surface"));
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_bulletin_close() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(31, 4, 30);
        certificate.bulletin_availability_certificate.height += 1;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("invalid bulletin close should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::InvalidBulletinClose);
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_omission_dominance() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(33, 5, 35);
        let tx_hash = ordered_transactions[0].hash().expect("tx hash");
        certificate.omission_proofs.push(OmissionProof {
            height: header.height,
            offender_account_id: AccountId([99u8; 32]),
            tx_hash,
            bulletin_root: certificate.bulletin_commitment.bulletin_root,
            details: "objective omission".into(),
        });
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("omissions should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::OmissionDominated);
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_certificate_height_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(35, 6, 40);
        certificate.height += 1;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("height mismatch should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::CertificateHeightMismatch
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_randomness_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(37, 7, 45);
        certificate.randomness_beacon[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("randomness mismatch should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::RandomnessMismatch);
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_transactions_root_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(39, 8, 50);
        certificate.ordered_transactions_root_hash[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("ordered transactions root mismatch should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::OrderedTransactionsRootMismatch
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_state_root_mismatch() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(41, 9, 55);
        certificate.resulting_state_root_hash[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("resulting state root mismatch should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::ResultingStateRootMismatch
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_public_inputs_hash() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(43, 10, 60);
        certificate.proof.public_inputs_hash[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("public-input mismatch should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::InvalidPublicInputsHash);
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_availability_certificate() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(45, 11, 65);
        certificate.bulletin_availability_certificate.recoverability_root[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("invalid availability certificate should derive obstruction");
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::InvalidBulletinAvailabilityCertificate
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_proof_binding() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(47, 12, 70);
        certificate.proof.proof_bytes[0] ^= 0xFF;
        header.canonical_order_certificate = Some(certificate);
        let abort = derive_canonical_order_public_obstruction(&header, &ordered_transactions)
            .expect("invalid proof binding should derive obstruction");
        assert_eq!(abort.reason, CanonicalOrderAbortReason::InvalidProofBinding);
    }

    #[test]
    fn derive_canonical_collapse_object_returns_order_abort_without_certificate() {
        let header = BlockHeader {
            height: 23,
            view: 3,
            parent_hash: [51u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_001_111,
            timestamp_ms: 1_750_001_111_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([21u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [22u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let collapse =
            derive_canonical_collapse_object(&header, &[]).expect("derive collapse object");
        assert_eq!(collapse.height, header.height);
        assert_eq!(collapse.previous_canonical_collapse_commitment_hash, [0u8; 32]);
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Abort);
        assert!(collapse.sealing.is_none());
        assert_eq!(collapse.transactions_root_hash, to_root_hash(&header.transactions_root).unwrap());
        assert_eq!(
            collapse.resulting_state_root_hash,
            to_root_hash(&header.state_root.0).unwrap()
        );
    }

    #[test]
    fn derive_canonical_collapse_object_binds_order_close_and_sealed_close() {
        let base_header = BlockHeader {
            height: 29,
            view: 5,
            parent_hash: [61u8; 32],
            parent_state_root: StateRoot(vec![1u8; 32]),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![],
            timestamp: 1_750_001_222,
            timestamp_ms: 1_750_001_222_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([23u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [24u8; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        let tx_one = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([25u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_bulletin_commitment@v1".into(),
                params: vec![7],
            },
            signature_proof: SignatureProof::default(),
        }));
        let tx_two = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([26u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "publish_aft_canonical_order_artifact_bundle@v1".into(),
                params: vec![8],
            },
            signature_proof: SignatureProof::default(),
        }));
        let ordered_transactions =
            canonicalize_transactions_for_header(&base_header, &[tx_one, tx_two])
                .expect("canonicalized transactions");
        let tx_hashes: Vec<[u8; 32]> = ordered_transactions
            .iter()
            .map(|tx| tx.hash().expect("tx hash"))
            .collect();

        let mut header = base_header;
        header.transactions_root =
            canonical_transaction_root_from_hashes(&tx_hashes).expect("transactions root");
        let certificate =
            build_committed_surface_canonical_order_certificate(&header, &ordered_transactions)
                .expect("build committed-surface certificate");
        header.canonical_order_certificate = Some(certificate.clone());
        header.state_root = StateRoot(certificate.resulting_state_root_hash.to_vec());

        let transcripts_root = canonical_asymptote_observer_transcripts_hash(&[]).unwrap();
        let challenges_root = canonical_asymptote_observer_challenges_hash(&[]).unwrap();
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: 9,
            height: header.height,
            view: header.view,
            assignments_hash: [91u8; 32],
            transcripts_root,
            challenges_root,
            transcript_count: 0,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 1_750_001_333,
        };
        let sealed_finality_proof = SealedFinalityProof {
            epoch: 9,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: [92u8; 32],
            guardian_decision_hash: [93u8; 32],
            guardian_counter: 3,
            guardian_trace_hash: [94u8; 32],
            guardian_measurement_root: [95u8; 32],
            policy_hash: [96u8; 32],
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: Some(canonical_close.clone()),
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        };
        header.sealed_finality_proof = Some(sealed_finality_proof);

        let collapse =
            derive_canonical_collapse_object(&header, &ordered_transactions).expect("derive collapse object");
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Close);
        assert_eq!(
            collapse.ordering.canonical_order_certificate_hash,
            canonical_order_certificate_hash(&certificate).unwrap()
        );
        let sealing = collapse.sealing.clone().expect("sealing collapse");
        assert_eq!(sealing.kind, CanonicalCollapseKind::Close);
        assert_eq!(sealing.collapse_state, CollapseState::SealedFinal);
        assert_eq!(
            sealing.resolution_hash,
            canonical_asymptote_observer_canonical_close_hash(&canonical_close).unwrap()
        );
        assert_eq!(
            canonical_collapse_object_hash(&collapse).unwrap(),
            canonical_collapse_object_hash(&collapse).unwrap()
        );
    }

    #[test]
    fn derive_canonical_collapse_object_binds_previous_collapse_hash() {
        let previous = CanonicalCollapseObject {
            height: 6,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 6,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [1u8; 32],
                bulletin_availability_certificate_hash: [2u8; 32],
                bulletin_close_hash: [3u8; 32],
                canonical_order_certificate_hash: [4u8; 32],
            },
            sealing: None,
            transactions_root_hash: [5u8; 32],
            resulting_state_root_hash: [6u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 7,
            view: 2,
            parent_hash: [9u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![2u8; 32]),
            transactions_root: vec![3u8; 32],
            timestamp: 1_750_000_123,
            timestamp_ms: 1_750_000_123_000,
            gas_used: 0,
            validator_set: vec![vec![4u8; 32]],
            producer_account_id: AccountId([5u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [6u8; 32],
            producer_pubkey: vec![7u8; 32],
            oracle_counter: 1,
            oracle_trace_hash: [8u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous)
                    .expect("previous canonical collapse commitment hash"),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(
                &previous,
            )),
            signature: vec![],
        };
        let collapse = derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous))
            .expect("derive continuity-bound collapse");
        let previous_hash =
            canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
        assert_eq!(collapse.previous_canonical_collapse_commitment_hash, previous_hash);
        verify_canonical_collapse_continuity(&collapse, Some(&previous))
            .expect("continuity should verify");
        assert_eq!(
            expected_previous_canonical_collapse_commitment_hash(collapse.height, Some(&previous))
                .unwrap(),
            previous_hash
        );
    }

    #[test]
    fn block_header_canonical_collapse_evidence_requires_carried_certificate() {
        let previous = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 6,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [11u8; 32],
                bulletin_availability_certificate_hash: [12u8; 32],
                bulletin_close_hash: [13u8; 32],
                canonical_order_certificate_hash: [14u8; 32],
            },
            sealing: None,
            transactions_root_hash: [15u8; 32],
            resulting_state_root_hash: [16u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 2,
            view: 0,
            parent_hash: [17u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![18u8; 32]),
            transactions_root: vec![19u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![20u8; 32]],
            producer_account_id: AccountId([21u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [22u8; 32],
            producer_pubkey: vec![23u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [24u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: None,
            signature: vec![],
        };

        assert!(
            verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err()
        );
    }

    #[test]
    fn block_header_canonical_collapse_evidence_rejects_missing_previous_anchor() {
        let previous = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 1,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [0x21u8; 32],
                bulletin_availability_certificate_hash: [0x22u8; 32],
                bulletin_close_hash: [0x23u8; 32],
                canonical_order_certificate_hash: [0x24u8; 32],
            },
            sealing: None,
            transactions_root_hash: [0x25u8; 32],
            resulting_state_root_hash: [0x26u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 2,
            view: 0,
            parent_hash: [0x27u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![0x28u8; 32]),
            transactions_root: vec![0x29u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![0x2Au8; 32]],
            producer_account_id: AccountId([0x2Bu8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0x2Cu8; 32],
            producer_pubkey: vec![0x2Du8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [0x2Eu8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(
                &previous,
            )),
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, None).is_err());
    }

    #[test]
    fn block_header_canonical_collapse_evidence_rejects_parent_state_root_mismatch() {
        let previous = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 6,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [31u8; 32],
                bulletin_availability_certificate_hash: [32u8; 32],
                bulletin_close_hash: [33u8; 32],
                canonical_order_certificate_hash: [34u8; 32],
            },
            sealing: None,
            transactions_root_hash: [35u8; 32],
            resulting_state_root_hash: [36u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, None).expect("bind previous continuity");
        let header = BlockHeader {
            height: 2,
            view: 0,
            parent_hash: [37u8; 32],
            parent_state_root: StateRoot(vec![0xFFu8; 32]),
            state_root: StateRoot(vec![38u8; 32]),
            transactions_root: vec![39u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![40u8; 32]],
            producer_account_id: AccountId([41u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [42u8; 32],
            producer_pubkey: vec![43u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [44u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(
                &previous,
            )),
            signature: vec![],
        };

        assert!(
            verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err()
        );
    }

    #[test]
    fn block_header_canonical_collapse_evidence_accepts_recursive_proof_backed_predecessor() {
        let grandparent = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 1,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [51u8; 32],
                bulletin_availability_certificate_hash: [52u8; 32],
                bulletin_close_hash: [53u8; 32],
                canonical_order_certificate_hash: [54u8; 32],
            },
            sealing: None,
            transactions_root_hash: [55u8; 32],
            resulting_state_root_hash: [56u8; 32],
        };
        let mut grandparent = grandparent;
        bind_canonical_collapse_continuity(&mut grandparent, None)
            .expect("bind grandparent continuity");
        let previous = CanonicalCollapseObject {
            height: 2,
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&grandparent).unwrap(),
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 2,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [57u8; 32],
                bulletin_availability_certificate_hash: [58u8; 32],
                bulletin_close_hash: [59u8; 32],
                canonical_order_certificate_hash: [60u8; 32],
            },
            sealing: None,
            transactions_root_hash: [61u8; 32],
            resulting_state_root_hash: [62u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, Some(&grandparent))
            .expect("bind previous continuity");
        let header = BlockHeader {
            height: 3,
            view: 0,
            parent_hash: [63u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![64u8; 32]),
            transactions_root: vec![65u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![66u8; 32]],
            producer_account_id: AccountId([67u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [68u8; 32],
            producer_pubkey: vec![69u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [70u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(
                &previous,
            )),
            signature: vec![],
        };

        verify_block_header_canonical_collapse_evidence(&header, Some(&previous))
            .expect("extension certificate should verify");
    }

    #[test]
    fn canonical_collapse_recursive_proof_rejects_missing_predecessor_step() {
        let previous = sample_canonical_collapse_object(1, None, 0x31);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0x41);
        let mut proof = current.continuity_recursive_proof.clone();
        proof.previous_canonical_collapse_commitment_hash = [0u8; 32];

        assert!(verify_canonical_collapse_recursive_proof(&proof).is_err());
    }

    #[test]
    fn canonical_collapse_recursive_proof_rejects_previous_proof_hash_mismatch() {
        let previous = sample_canonical_collapse_object(1, None, 0x51);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0x61);
        let mut proof = current.continuity_recursive_proof.clone();
        proof.previous_recursive_proof_hash[0] ^= 0xFF;

        assert!(verify_canonical_collapse_recursive_proof(&proof).is_err());
    }

    #[test]
    fn canonical_collapse_recursive_proof_rejects_corrupted_proof_bytes() {
        let previous = sample_canonical_collapse_object(1, None, 0x71);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0x81);
        let mut proof = current.continuity_recursive_proof.clone();
        proof.proof_bytes[0] ^= 0xFF;

        assert!(verify_canonical_collapse_recursive_proof(&proof).is_err());
    }

    #[test]
    fn canonical_collapse_recursive_proof_matches_collapse_rejects_payload_mismatch() {
        let previous = sample_canonical_collapse_object(1, None, 0x91);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0xA1);
        let proof = current.continuity_recursive_proof.clone();
        let mut mismatched = current.clone();
        mismatched.ordering.bulletin_commitment_hash[0] ^= 0xFF;

        assert!(
            verify_canonical_collapse_recursive_proof_matches_collapse(
                &mismatched,
                &proof,
                Some(&previous),
            )
                .is_err()
        );
    }

    #[test]
    fn canonical_collapse_recursive_proof_hash_changes_when_previous_step_changes() {
        let genesis = sample_canonical_collapse_object(1, None, 0xB1);
        let step_two = sample_canonical_collapse_object(2, Some(&genesis), 0xB2);
        let step_three = sample_canonical_collapse_object(3, Some(&step_two), 0xB3);
        let mut carried = step_three.continuity_recursive_proof.clone();
        carried.previous_recursive_proof_hash[0] ^= 0x55;

        let expected_hash =
            canonical_collapse_recursive_proof_hash(&step_three.continuity_recursive_proof)
                .expect("expected recursive proof hash");
        let tampered_hash =
            canonical_collapse_recursive_proof_hash(&carried).expect("tampered recursive proof hash");

        assert_ne!(expected_hash, tampered_hash);
        assert!(verify_canonical_collapse_recursive_proof(&carried).is_err());
    }

    #[test]
    fn bind_canonical_collapse_continuity_can_emit_succinct_sp1_reference_proof() {
        let _guard = continuity_env_lock().lock().expect("continuity env lock");
        let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

        let previous = sample_canonical_collapse_object(1, None, 0xC1);
        let current = sample_canonical_collapse_object(2, Some(&previous), 0xC2);

        assert_eq!(
            current.continuity_recursive_proof.proof_system,
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1
        );
        verify_canonical_collapse_continuity(&current, Some(&previous))
            .expect("succinct continuity proof should verify");

        if let Some(value) = previous_env {
            std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
        } else {
            std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
        }
    }

    #[test]
    fn block_header_canonical_collapse_evidence_rejects_mismatched_predecessor_head() {
        let grandparent = CanonicalCollapseObject {
            height: 1,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 1,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [71u8; 32],
                bulletin_availability_certificate_hash: [72u8; 32],
                bulletin_close_hash: [73u8; 32],
                canonical_order_certificate_hash: [74u8; 32],
            },
            sealing: None,
            transactions_root_hash: [75u8; 32],
            resulting_state_root_hash: [76u8; 32],
        };
        let mut grandparent = grandparent;
        bind_canonical_collapse_continuity(&mut grandparent, None)
            .expect("bind grandparent continuity");
        let previous = CanonicalCollapseObject {
            height: 2,
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&grandparent).unwrap(),
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: CanonicalOrderingCollapse {
                height: 2,
                kind: CanonicalCollapseKind::Close,
                bulletin_commitment_hash: [77u8; 32],
                bulletin_availability_certificate_hash: [78u8; 32],
                bulletin_close_hash: [79u8; 32],
                canonical_order_certificate_hash: [80u8; 32],
            },
            sealing: None,
            transactions_root_hash: [81u8; 32],
            resulting_state_root_hash: [82u8; 32],
        };
        let mut previous = previous;
        bind_canonical_collapse_continuity(&mut previous, Some(&grandparent))
            .expect("bind previous continuity");
        let mut wrong_certificate = certificate_from_predecessor(&previous);
        wrong_certificate.predecessor_recursive_proof_hash[0] ^= 0xFF;

        let header = BlockHeader {
            height: 3,
            view: 0,
            parent_hash: [83u8; 32],
            parent_state_root: StateRoot(previous.resulting_state_root_hash.to_vec()),
            state_root: StateRoot(vec![84u8; 32]),
            transactions_root: vec![85u8; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: vec![vec![86u8; 32]],
            producer_account_id: AccountId([87u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [88u8; 32],
            producer_pubkey: vec![89u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [90u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash:
                canonical_collapse_commitment_hash_from_object(&previous).unwrap(),
            canonical_collapse_extension_certificate: Some(wrong_certificate),
            signature: vec![],
        };

        assert!(
            verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err()
        );
    }
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

/// A vote from a validator to change the view at a specific height.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ViewChangeVote {
    /// The block height whose proposer timed out.
    pub height: u64,
    /// The recovery view being requested for that height.
    pub view: u64,
    /// The validator casting the timeout vote.
    pub voter: AccountId,
    /// The validator's signature over the `(height, view)` timeout payload.
    pub signature: Vec<u8>,
}

/// A proof that a majority of validators agreed to move to a new view.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct TimeoutCertificate {
    /// The block height for which the timeout quorum was formed.
    pub height: u64,
    /// The recovery view authorized by the timeout quorum.
    pub view: u64,
    /// The set of timeout votes that established the quorum.
    pub votes: Vec<ViewChangeVote>,
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

// --- Protocol Apex: Aft deterministic Echo Protocol Structures ---

/// An Echo message broadcast by validators upon receiving a valid proposal.
/// Validates the leader's intent across Mirror partitions before voting.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct EchoMessage {
    /// The block height.
    pub height: u64,
    /// The consensus view.
    pub view: u64,
    /// The hash of the block proposal being echoed.
    pub block_hash: [u8; 32],
    /// The raw signature provided by the leader on the block header.
    /// This proves the leader actually committed to this proposal.
    pub leader_signature: Vec<u8>,
    /// The oracle counter from the leader's header, ensuring monotonicity.
    pub oracle_counter: u64,
    /// The identity of the node sending this Echo.
    pub sender_id: AccountId,
    /// The sender's signature over the Echo payload:
    /// H("ECHO_V1" || chain_id || height || view || block_hash || leader_sig)
    pub signature: Vec<u8>,
}

/// Cryptographic evidence that a validator has equivocated (signed two different
/// payloads for the same slot). This implies a hardware TEE breach.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ProofOfDivergence {
    /// The account ID of the equivocating validator.
    pub offender: AccountId,

    /// The first conflicting block header (containing the signature).
    pub evidence_a: BlockHeader,

    /// The second conflicting block header (containing the signature).
    pub evidence_b: BlockHeader,
    /// Optional conflicting guardian certificates extracted from the evidentiary headers.
    #[serde(default)]
    pub guardian_certificates: Vec<GuardianQuorumCertificate>,
    /// Optional witness-log checkpoints relevant to the divergence proof.
    #[serde(default)]
    pub log_checkpoints: Vec<GuardianLogCheckpoint>,
}

/// A high-priority divergence alert broadcast when conflicting signed evidence is detected.
/// In guardianized deployments this triggers quarantine and evidence propagation,
/// not a production engine switch.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PanicMessage {
    /// The cryptographic proof of the hardware violation.
    pub proof: ProofOfDivergence,
    /// Signature of the node raising the alarm (to prevent griefing).
    pub sender_sig: Vec<u8>,
}

// --- Research-only witness/audit sampling structures ---

/// A probabilistic confidence report for witness/audit research flows.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ConfidenceVote {
    /// The hash of the block being voted for (the preferred tip).
    pub block_hash: [u8; 32],
    /// The block height.
    pub height: u64,
    /// The local confidence score (C_B) for this block.
    pub confidence: u32,
    /// The VRF proof authorizing this vote (Anti-Sybil).
    pub vrf_proof: Vec<u8>,
    /// The voter's signature.
    pub signature: Vec<u8>,
}

/// A request to sample a peer's preferred tip for witness/audit observations.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SampleRequest {
    /// The height we are querying about.
    pub height: u64,
}

/// The response to a research-only witness/audit sample request.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SampleResponse {
    /// The responder's preferred block hash at that height.
    pub block_hash: [u8; 32],
    /// The responder's current confidence score.
    pub confidence: u32,
}

// --- Legacy recovery / governance structures ---

/// Governance payload for an explicit aft epoch reset or recovery ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftEpochUpgrade {
    /// The new Epoch ID.
    pub new_epoch: u64,
    /// List of BootAttestations from patched Guardians.
    pub attestations: Vec<crate::app::BootAttestation>,
}
