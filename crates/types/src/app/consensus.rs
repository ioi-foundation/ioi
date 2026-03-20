// Path: crates/types/src/app/consensus.rs

use crate::app::guardianized::{
    canonical_asymptote_observer_canonical_abort_hash,
    canonical_asymptote_observer_canonical_close_hash,
    canonical_asymptote_observer_challenges_hash, canonical_asymptote_observer_transcripts_hash,
    CollapseState, FinalityTier, GuardianWitnessRecoveryBinding, SealedFinalityProof,
};
use crate::app::{
    timestamp_millis_to_legacy_seconds, to_root_hash, AccountId, ActiveKeyRecord, BlockHeader,
    ChainTransaction, SignatureSuite, StateRoot,
};
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
pub const AFT_BULLETIN_AVAILABILITY_PREFIX: &[u8] = b"aft::ordering::bulletin_availability::";
/// State key prefix for published AFT canonical bulletin-close objects by height.
pub const AFT_BULLETIN_CLOSE_PREFIX: &[u8] = b"aft::ordering::bulletin_close::";
/// State key prefix for published AFT canonical-order certificates by height.
pub const AFT_ORDER_CERTIFICATE_PREFIX: &[u8] = b"aft::ordering::certificate::";
/// State key prefix for published AFT canonical-order abort objects by height.
pub const AFT_ORDER_ABORT_PREFIX: &[u8] = b"aft::ordering::abort::";
/// State key prefix for published compact publication-frontier summaries by height.
pub const AFT_PUBLICATION_FRONTIER_PREFIX: &[u8] = b"aft::publication::frontier::";
/// State key prefix for published publication-frontier contradiction objects by height.
pub const AFT_PUBLICATION_CONTRADICTION_PREFIX: &[u8] = b"aft::publication::contradiction::";
/// State key prefix for exploratory recovery capsules by height.
pub const AFT_RECOVERY_CAPSULE_PREFIX: &[u8] = b"aft::recovery::capsule::";
/// State key prefix for exploratory recovery witness certificates by height and witness account.
pub const AFT_RECOVERY_WITNESS_CERTIFICATE_PREFIX: &[u8] = b"aft::recovery::witness_certificate::";
/// State key prefix for exploratory recovery share receipts by height, witness account, and block commitment.
pub const AFT_RECOVERY_SHARE_RECEIPT_PREFIX: &[u8] = b"aft::recovery::share_receipt::";
/// State key prefix for exploratory recovery share-reveal material by height, witness account, and block commitment.
pub const AFT_RECOVERY_SHARE_MATERIAL_PREFIX: &[u8] = b"aft::recovery::share_material::";
/// State key prefix for compact recovered-publication bundle objects by height, block, and witness-support set.
pub const AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX: &[u8] =
    b"aft::recovery::recovered_publication_bundle::";
/// State key prefix for archived recovered-history segment descriptors by covered range.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_segment::";
/// State key prefix for content-addressed archived recovered-history segment descriptors.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_segment_hash::";
/// State key prefix for content-addressed archived recovered-history profiles.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_hash::";
/// State key prefix for archived recovered-history profile activations by profile hash.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_activation::";
/// State key prefix for archived recovered-history profile activations by activation end height.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HEIGHT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_activation_height::";
/// State key prefix for content-addressed archived recovered-history profile activations.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_activation_hash::";
/// State key prefix for content-addressed archived recovered restart-page payloads.
pub const AFT_ARCHIVED_RECOVERED_RESTART_PAGE_PREFIX: &[u8] =
    b"aft::recovery::archived_restart_page::";
/// State key prefix for archived recovered-history checkpoint descriptors by covered range.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_checkpoint::";
/// State key prefix for content-addressed archived recovered-history checkpoints.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_checkpoint_hash::";
/// State key prefix for archived recovered-history retention receipts by checkpoint hash.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_RETENTION_RECEIPT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_retention_receipt::";
/// State key for the latest archived recovered-history checkpoint tip.
pub const AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY: &[u8] =
    b"aft::recovery::archived_history_checkpoint::latest";
/// State key for the active archived recovered-history profile.
pub const AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY: &[u8] =
    b"aft::recovery::archived_history_profile::active";
/// State key for the latest archived recovered-history profile activation.
pub const AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY: &[u8] =
    b"aft::recovery::archived_history_profile_activation::latest";
/// State key prefix for exploratory missing recovery-share claims by height and witness account.
pub const AFT_MISSING_RECOVERY_SHARE_PREFIX: &[u8] = b"aft::recovery::missing_share::";
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

/// Builds the canonical state key for a published compact AFT publication frontier.
pub fn aft_publication_frontier_key(height: u64) -> Vec<u8> {
    [AFT_PUBLICATION_FRONTIER_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT publication-frontier contradiction object.
pub fn aft_publication_frontier_contradiction_key(height: u64) -> Vec<u8> {
    [AFT_PUBLICATION_CONTRADICTION_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for an exploratory AFT recovery capsule.
pub fn aft_recovery_capsule_key(height: u64) -> Vec<u8> {
    [AFT_RECOVERY_CAPSULE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for an exploratory AFT recovery witness certificate.
pub fn aft_recovery_witness_certificate_key(
    height: u64,
    witness_manifest_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_WITNESS_CERTIFICATE_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
}

/// Builds the prefix for exploratory AFT recovery share receipts for one witness at one height.
pub fn aft_recovery_share_receipt_prefix(height: u64, witness_manifest_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_RECEIPT_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for an exploratory AFT recovery share receipt.
pub fn aft_recovery_share_receipt_key(
    height: u64,
    witness_manifest_hash: &[u8; 32],
    block_commitment_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_RECEIPT_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
        block_commitment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the prefix for exploratory AFT recovery share-reveal material for one witness at one height.
pub fn aft_recovery_share_material_prefix(
    height: u64,
    witness_manifest_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_MATERIAL_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for exploratory AFT recovery share-reveal material.
pub fn aft_recovery_share_material_key(
    height: u64,
    witness_manifest_hash: &[u8; 32],
    block_commitment_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_MATERIAL_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
        block_commitment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the prefix for compact recovered-publication bundle objects for one slot surface.
pub fn aft_recovered_publication_bundle_prefix(
    height: u64,
    block_commitment_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &height.to_be_bytes(),
        block_commitment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one compact recovered-publication bundle object.
pub fn aft_recovered_publication_bundle_key(
    height: u64,
    block_commitment_hash: &[u8; 32],
    supporting_witness_manifest_hashes: &[[u8; 32]],
) -> Result<Vec<u8>, String> {
    let support_hash =
        canonical_recovered_publication_bundle_support_hash(supporting_witness_manifest_hashes)?;
    Ok([
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &height.to_be_bytes(),
        block_commitment_hash.as_ref(),
        support_hash.as_ref(),
    ]
    .concat())
}

/// Builds the prefix for archived recovered-history segment descriptors that start at one height.
pub fn aft_archived_recovered_history_segment_prefix(start_height: u64) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_PREFIX,
        &start_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history segment descriptor.
pub fn aft_archived_recovered_history_segment_key(start_height: u64, end_height: u64) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_PREFIX,
        &start_height.to_be_bytes(),
        &end_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history segment descriptor.
pub fn aft_archived_recovered_history_segment_hash_key(segment_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_HASH_PREFIX,
        segment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history profile.
pub fn aft_archived_recovered_history_profile_hash_key(profile_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_HASH_PREFIX,
        profile_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history profile activation by
/// profile hash.
pub fn aft_archived_recovered_history_profile_activation_key(profile_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_PREFIX,
        profile_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history profile activation by
/// activation end height.
pub fn aft_archived_recovered_history_profile_activation_height_key(
    activation_end_height: u64,
) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HEIGHT_PREFIX,
        &activation_end_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history profile
/// activation.
pub fn aft_archived_recovered_history_profile_activation_hash_key(
    activation_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HASH_PREFIX,
        activation_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered restart-page payload.
pub fn aft_archived_recovered_restart_page_key(segment_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_RESTART_PAGE_PREFIX,
        segment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history checkpoint descriptor.
pub fn aft_archived_recovered_history_checkpoint_key(
    start_height: u64,
    end_height: u64,
) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_PREFIX,
        &start_height.to_be_bytes(),
        &end_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history checkpoint.
pub fn aft_archived_recovered_history_checkpoint_hash_key(checkpoint_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_HASH_PREFIX,
        checkpoint_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history retention receipt.
pub fn aft_archived_recovered_history_retention_receipt_key(checkpoint_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_RETENTION_RECEIPT_PREFIX,
        checkpoint_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for an exploratory missing AFT recovery share claim.
pub fn aft_missing_recovery_share_key(height: u64, witness_manifest_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_MISSING_RECOVERY_SHARE_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
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
    /// This is a commitment-only seed: it does not encode witness assignment,
    /// shard layout, or any exploratory coded-recovery carrier by itself.
    #[serde(default)]
    pub recoverability_root: [u8; 32],
}

/// Declares which exploratory recovery-carrier family a capsule or reveal is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCodingFamily {
    /// Deterministic single-witness scaffold derived from the committed bulletin surface.
    #[default]
    DeterministicScaffoldV1,
    /// Transparent preimage over the committed slot surface, not a non-trivial coded shard.
    TransparentCommittedSurfaceV1,
    /// Parametric k-of-(k+1) systematic XOR parity carrier over the publication-oriented slot payload.
    SystematicXorKOfKPlus1V1,
    /// Parametric k-of-n GF(256) systematic carrier over the publication-oriented slot payload.
    SystematicGf256KOfNV1,
}

/// Compact recovery coding descriptor carried across capsules, share materials, and recovered
/// bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct RecoveryCodingDescriptor {
    /// Coding family semantics.
    #[serde(default)]
    pub family: RecoveryCodingFamily,
    /// Total number of witness shares in the deterministic plan.
    pub share_count: u16,
    /// Threshold of matching shares required for reconstruction.
    pub recovery_threshold: u16,
}

impl Default for RecoveryCodingDescriptor {
    fn default() -> Self {
        Self::deterministic_scaffold()
    }
}

impl RecoveryCodingDescriptor {
    /// Default single-witness scaffold geometry.
    pub const fn deterministic_scaffold() -> Self {
        Self {
            family: RecoveryCodingFamily::DeterministicScaffoldV1,
            share_count: 1,
            recovery_threshold: 1,
        }
    }

    /// Returns the number of data shards implied by the descriptor.
    pub const fn data_shard_count(self) -> u16 {
        self.recovery_threshold
    }

    /// Returns the number of parity shards implied by the descriptor.
    pub const fn parity_shard_count(self) -> u16 {
        self.share_count.saturating_sub(self.recovery_threshold)
    }

    /// Whether the descriptor requires a recoverable slot payload carrier.
    pub const fn uses_recoverable_payload(self) -> bool {
        matches!(
            self.family,
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1
                | RecoveryCodingFamily::SystematicGf256KOfNV1
        )
    }

    /// Whether the descriptor is the transparent committed-surface lane.
    pub const fn is_transparent_committed_surface(self) -> bool {
        matches!(
            self.family,
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
        )
    }

    /// Whether the descriptor is the deterministic scaffold lane.
    pub const fn is_deterministic_scaffold(self) -> bool {
        matches!(self.family, RecoveryCodingFamily::DeterministicScaffoldV1)
    }

    /// Whether the descriptor is in the XOR parity family.
    pub const fn is_systematic_xor_parity_family(self) -> bool {
        matches!(self.family, RecoveryCodingFamily::SystematicXorKOfKPlus1V1)
    }

    /// Whether the descriptor is in the GF(256) k-of-n family.
    pub const fn is_systematic_gf256_k_of_n_family(self) -> bool {
        matches!(self.family, RecoveryCodingFamily::SystematicGf256KOfNV1)
    }

    /// Human-readable family/geometry label for diagnostics.
    pub fn label(self) -> String {
        match self.family {
            RecoveryCodingFamily::DeterministicScaffoldV1 => "deterministic scaffold".into(),
            RecoveryCodingFamily::TransparentCommittedSurfaceV1 => {
                format!(
                    "transparent committed surface {}-of-{}",
                    self.recovery_threshold, self.share_count
                )
            }
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                format!(
                    "systematic xor parity {}-of-{}",
                    self.recovery_threshold, self.share_count
                )
            }
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                format!(
                    "systematic gf256 {}-of-{}",
                    self.recovery_threshold, self.share_count
                )
            }
        }
    }

    /// Checks that the descriptor's family and geometry are internally consistent.
    pub fn validate(self) -> Result<(), String> {
        if self.share_count == 0 {
            return Err("recovery coding descriptor has zero share count".into());
        }
        if self.recovery_threshold == 0 {
            return Err("recovery coding descriptor has zero recovery threshold".into());
        }
        if self.recovery_threshold > self.share_count {
            return Err("recovery coding descriptor recovery threshold exceeds share count".into());
        }

        match self.family {
            RecoveryCodingFamily::DeterministicScaffoldV1 => {
                if self.share_count != 1 || self.recovery_threshold != 1 {
                    return Err(
                        "deterministic scaffold descriptor requires share_count = recovery_threshold = 1"
                            .into(),
                    );
                }
            }
            RecoveryCodingFamily::TransparentCommittedSurfaceV1 => {
                if self.recovery_threshold < 2 {
                    return Err(
                        "transparent committed-surface descriptor requires threshold at least two"
                            .into(),
                    );
                }
            }
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                if self.recovery_threshold < 2 {
                    return Err(
                        "systematic xor parity descriptor requires threshold at least two".into(),
                    );
                }
                if self.share_count != self.recovery_threshold.saturating_add(1) {
                    return Err(
                        "systematic xor parity descriptor requires share_count = recovery_threshold + 1"
                            .into(),
                    );
                }
            }
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                if self.recovery_threshold < 2 {
                    return Err(
                        "systematic gf256 descriptor requires threshold at least two".into(),
                    );
                }
                if self.share_count < self.recovery_threshold.saturating_add(2) {
                    return Err(
                        "systematic gf256 descriptor requires at least two parity shares".into(),
                    );
                }
                if self.parity_shard_count() > u16::from(u8::MAX) {
                    return Err(
                        "systematic gf256 descriptor supports at most 255 parity shares".into(),
                    );
                }
                if self.share_count > u16::from(u8::MAX) + 1 {
                    return Err(
                        "systematic gf256 descriptor supports at most 256 total shares".into(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Resolves this descriptor into the abstract recovery-family contract it
    /// satisfies.
    pub fn family_contract(self) -> Result<RecoveryFamilyContract, String> {
        self.validate()?;
        Ok(RecoveryFamilyContract { descriptor: self })
    }
}

/// Abstract recovery-family contract satisfied by all admitted exploratory
/// recovery carriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryFamilyContract {
    descriptor: RecoveryCodingDescriptor,
}

impl RecoveryFamilyContract {
    /// Returns the validated descriptor this contract is bound to.
    pub const fn descriptor(self) -> RecoveryCodingDescriptor {
        self.descriptor
    }

    /// Human-readable contract label for diagnostics and theorem text.
    pub const fn theorem_label(self) -> &'static str {
        match self.descriptor.family {
            RecoveryCodingFamily::DeterministicScaffoldV1 => "deterministic scaffold",
            RecoveryCodingFamily::TransparentCommittedSurfaceV1 => "transparent committed surface",
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => "systematic xor recovery family",
            RecoveryCodingFamily::SystematicGf256KOfNV1 => "systematic gf256 recovery family",
        }
    }

    /// Whether this family is a true coded recoverable-payload carrier.
    pub const fn supports_coded_payload_reconstruction(self) -> bool {
        matches!(
            self.descriptor.family,
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1
                | RecoveryCodingFamily::SystematicGf256KOfNV1
        )
    }

    /// Whether this family requires a recoverable slot payload carrier.
    pub const fn uses_recoverable_payload(self) -> bool {
        self.descriptor.uses_recoverable_payload()
    }

    /// Domain separator for coded share commitments under this family contract.
    pub fn coded_share_commitment_domain(self) -> Result<&'static [u8], String> {
        match self.descriptor.family {
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => Ok(
                b"aft::recovery::multi_witness::systematic_xor_k_of_k_plus_1::share_commitment::v1",
            ),
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                Ok(b"aft::recovery::multi_witness::systematic_gf256_k_of_n::share_commitment::v1")
            }
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
            | RecoveryCodingFamily::DeterministicScaffoldV1 => Err(
                "coded share commitment domain requires a coded recovery-family contract".into(),
            ),
        }
    }

    /// Encodes a recoverable slot payload into the canonical shard plan for
    /// this family contract.
    pub fn encode_payload_shards(self, payload_bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        match self.descriptor.family {
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                encode_systematic_xor_k_of_k_plus_1_shards(
                    payload_bytes,
                    self.descriptor.recovery_threshold,
                )
            }
            RecoveryCodingFamily::SystematicGf256KOfNV1 => encode_systematic_gf256_k_of_n_shards(
                payload_bytes,
                self.descriptor.share_count,
                self.descriptor.recovery_threshold,
            ),
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
            | RecoveryCodingFamily::DeterministicScaffoldV1 => Err(
                "coded recovery shard encoding requires a coded recovery-family contract".into(),
            ),
        }
    }

    /// Reconstructs recoverable payload bytes from the public reveal set under
    /// this family contract.
    pub fn recover_payload_bytes_from_materials(
        self,
        materials: &[RecoveryShareMaterial],
    ) -> Result<Vec<u8>, String> {
        match self.descriptor.family {
            RecoveryCodingFamily::SystematicGf256KOfNV1 => {
                if materials
                    .iter()
                    .any(|material| material.coding != self.descriptor)
                {
                    return Err(
                        "recoverable slot payload reconstruction requires a uniform gf256 materialization kind"
                            .into(),
                    );
                }
                recover_systematic_gf256_k_of_n_slot_payload_bytes(materials)
            }
            RecoveryCodingFamily::SystematicXorKOfKPlus1V1 => {
                if materials
                    .iter()
                    .any(|material| !is_systematic_xor_parity_coding(material.coding))
                {
                    return Err(
                        "recoverable slot payload reconstruction requires a uniform parity-family materialization kind"
                            .into(),
                    );
                }
                recover_systematic_xor_k_of_k_plus_1_slot_payload_bytes(materials)
            }
            RecoveryCodingFamily::TransparentCommittedSurfaceV1
            | RecoveryCodingFamily::DeterministicScaffoldV1 => Err(
                "recoverable slot payload reconstruction requires non-transparent coded share reveals"
                    .into(),
            ),
        }
    }
}

/// Exploratory witness-coded recovery capsule for constructive lower-bound variants.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryCapsule {
    /// Slot / height whose recovery surface is being bound.
    pub height: u64,
    /// Declares whether the capsule is a true coded carrier or a deterministic scaffold.
    #[serde(default)]
    pub coding: RecoveryCodingDescriptor,
    /// Compact root committing the assigned witness recovery committee.
    #[serde(default)]
    pub recovery_committee_root_hash: [u8; 32],
    /// Commitment to the slot surface recoverable from threshold shares.
    #[serde(default)]
    pub payload_commitment_hash: [u8; 32],
    /// Commitment to the coding / shard layout referenced by witness shares.
    #[serde(default)]
    pub coding_root_hash: [u8; 32],
    /// Deterministic recovery-window close bound to the capsule.
    pub recovery_window_close_ms: u64,
}

/// Exploratory witness certificate binding one assigned recovery share to a capsule.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryWitnessCertificate {
    /// Slot / height whose recovery capsule is being witnessed.
    pub height: u64,
    /// Witness committee epoch.
    pub epoch: u64,
    /// Hash of the registered witness manifest that carries the recovery duty.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Canonical hash of the bound recovery capsule.
    #[serde(default)]
    pub recovery_capsule_hash: [u8; 32],
    /// Commitment to the witness's coded share.
    #[serde(default)]
    pub share_commitment_hash: [u8; 32],
}

/// Compact public receipt revealing that one assigned witness bound a share to one slot surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryShareReceipt {
    /// Slot / height whose recovery share is being published.
    pub height: u64,
    /// Witness manifest that revealed the share receipt.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Commitment of the candidate slot surface / block the share supports.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Commitment to the witness's coded share.
    #[serde(default)]
    pub share_commitment_hash: [u8; 32],
}

/// Canonical compact slot payload used by exploratory witness-coded recovery experiments.
///
/// This payload is intentionally smaller than the full bulletin surface. It is
/// the first honest payload carrier we can derive endogenously today without
/// reintroducing dense reconstruction onto the validator hot path.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV1 {
    /// Slot / height whose compact payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the compact slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Ordered transaction hashes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_hashes: Vec<[u8; 32]>,
}

/// Canonical widened slot payload used by the intermediate coded-share experiments.
///
/// This keeps the same compact certificate carrier as `RecoverableSlotPayloadV1`
/// but widens the ordered payload from transaction hashes to canonical encoded
/// ordered transaction bytes so the recovery lane can reconstruct a real slot
/// payload rather than only a digest list.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV2 {
    /// Slot / height whose widened payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the widened slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
}

/// Canonical publication-oriented slot payload used by the live coded-share experiments.
///
/// This keeps the widened ordered transaction bytes from `RecoverableSlotPayloadV2`
/// and adds canonical encoded publication-bundle bytes so the shard lane can
/// recover the already-derived publication artifact surface without reaching
/// outside current endogenous finalization artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV3 {
    /// Slot / height whose publication-oriented payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the widened slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the committed slot header.
    #[serde(default)]
    pub parent_block_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
    /// Canonical encoded publication-bundle bytes derived from the same slot surface.
    #[serde(default)]
    pub canonical_order_publication_bundle_bytes: Vec<u8>,
}

/// Canonical close-extraction slot payload derived from the live coded-share experiments.
///
/// This extends `RecoverableSlotPayloadV3` with the exact canonical
/// bulletin-close bytes that the positive ordering lane ultimately needs to
/// materialize the ordinary close surface. The close object is still verified
/// from the recovered publication bundle, but `V4` makes that full positive
/// close-extraction surface explicit.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV4 {
    /// Slot / height whose close-extraction payload is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the close-extraction payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the committed slot header.
    #[serde(default)]
    pub parent_block_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
    /// Canonical encoded publication-bundle bytes derived from the same slot surface.
    #[serde(default)]
    pub canonical_order_publication_bundle_bytes: Vec<u8>,
    /// Canonical encoded bulletin-close bytes derived from the verifying publication bundle.
    #[serde(default)]
    pub canonical_bulletin_close_bytes: Vec<u8>,
}

/// Explicit extractable bulletin-surface payload derived from the live coded-share experiments.
///
/// This extends `RecoverableSlotPayloadV4` with the exact bulletin-surface
/// artifacts that the registry's extracted closed-slot surface depends on:
/// canonical encoded bulletin-availability bytes plus the sorted bulletin
/// entry surface itself.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoverableSlotPayloadV5 {
    /// Slot / height whose full extractable bulletin surface is being materialized.
    pub height: u64,
    /// Consensus view of the committed slot.
    pub view: u64,
    /// Producer whose slot surface is being encoded.
    pub producer_account_id: AccountId,
    /// Block commitment anchoring the full extractable surface.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the committed slot header.
    #[serde(default)]
    pub parent_block_hash: [u8; 32],
    /// Canonical order certificate bound to the same slot.
    #[serde(default)]
    pub canonical_order_certificate: CanonicalOrderCertificate,
    /// Canonical ordered transaction bytes carried by the committed slot.
    #[serde(default)]
    pub ordered_transaction_bytes: Vec<Vec<u8>>,
    /// Canonical encoded publication-bundle bytes derived from the same slot surface.
    #[serde(default)]
    pub canonical_order_publication_bundle_bytes: Vec<u8>,
    /// Canonical encoded bulletin-close bytes derived from the verifying publication bundle.
    #[serde(default)]
    pub canonical_bulletin_close_bytes: Vec<u8>,
    /// Canonical encoded bulletin-availability bytes extracted from the recovered bundle.
    #[serde(default)]
    pub canonical_bulletin_availability_certificate_bytes: Vec<u8>,
    /// Sorted canonical bulletin-entry surface extracted from the recovered bundle.
    #[serde(default)]
    pub bulletin_surface_entries: Vec<BulletinSurfaceEntry>,
}

/// Cold-path share-reveal material for one exploratory witness-coded recovery share.
///
/// The current constructive route supports either a transparent preimage over
/// already committed slot-surface facts, the parametric XOR parity family, or
/// bounded GF(256) systematic shards over a publication-oriented recoverable
/// slot payload. This keeps reveal verification cold-path and deterministic
/// while testing whether non-trivial coded recovery can stay endogenous to the
/// current protocol surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveryShareMaterial {
    /// Slot / height whose recovery share is being revealed.
    pub height: u64,
    /// Witness manifest that owns the revealed share commitment.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Commitment of the candidate slot surface / block this reveal supports.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Declares whether this material is a true coded shard or a transparent preimage.
    #[serde(default)]
    pub coding: RecoveryCodingDescriptor,
    /// Position of this share inside the deterministic threshold-k plan.
    pub share_index: u16,
    /// Commitment hash bound by the witness certificate and derived receipt.
    #[serde(default)]
    pub share_commitment_hash: [u8; 32],
    /// Material bytes that hash to `share_commitment_hash`.
    #[serde(default)]
    pub material_bytes: Vec<u8>,
}

impl RecoveryShareMaterial {
    /// Derives the compact public share receipt for this revealed share material.
    pub fn to_recovery_share_receipt(&self) -> RecoveryShareReceipt {
        RecoveryShareReceipt {
            height: self.height,
            witness_manifest_hash: self.witness_manifest_hash,
            block_commitment_hash: self.block_commitment_hash,
            share_commitment_hash: self.share_commitment_hash,
        }
    }
}

/// Compact public resolution object proving that threshold-many share reveals
/// reconstruct one verifying positive canonical-order close surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveredPublicationBundle {
    /// Slot / height whose publication bundle was recovered.
    pub height: u64,
    /// Block commitment anchoring the recovered slot payload.
    #[serde(default)]
    pub block_commitment_hash: [u8; 32],
    /// Canonical parent block hash recovered from the same slot surface.
    #[serde(default)]
    pub parent_block_commitment_hash: [u8; 32],
    /// Reveal semantics used by the recovered share set.
    #[serde(default)]
    pub coding: RecoveryCodingDescriptor,
    /// Distinct witness manifests whose public reveals supported the recovery.
    #[serde(default)]
    pub supporting_witness_manifest_hashes: Vec<[u8; 32]>,
    /// Canonical hash of the reconstructed `RecoverableSlotPayloadV4`.
    #[serde(default)]
    pub recoverable_slot_payload_hash: [u8; 32],
    /// Canonical hash of the reconstructed `RecoverableSlotPayloadV5`.
    #[serde(default)]
    pub recoverable_full_surface_hash: [u8; 32],
    /// Canonical hash of the verifying recovered publication bundle bytes.
    #[serde(default)]
    pub canonical_order_publication_bundle_hash: [u8; 32],
    /// Canonical hash of the verifying recovered bulletin-close bytes.
    #[serde(default)]
    pub canonical_bulletin_close_hash: [u8; 32],
}

/// Compact archival descriptor for a recovered-history segment.
///
/// This is a cold-path publication object. It names a recovered-history range,
/// commits to the recovered publication-bundle hashes inside that range, and
/// chains to the previous archived segment without enlarging hot-path messages.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistorySegment {
    /// First recovered slot height covered by this archived segment.
    pub start_height: u64,
    /// Last recovered slot height covered by this archived segment.
    pub end_height: u64,
    /// Canonical hash of the archived recovered-history profile that governs this segment.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// segment.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// Canonical recovered-publication bundle hash for the oldest slot in range.
    #[serde(default)]
    pub first_recovered_publication_bundle_hash: [u8; 32],
    /// Canonical recovered-publication bundle hash for the newest slot in range.
    #[serde(default)]
    pub last_recovered_publication_bundle_hash: [u8; 32],
    /// Canonical hash of the immediately previous archived recovered-history segment.
    #[serde(default)]
    pub previous_archived_segment_hash: [u8; 32],
    /// Canonical root hash of the recovered-publication bundle hashes in this range.
    #[serde(default)]
    pub segment_root_hash: [u8; 32],
    /// First height inside this segment's exact-overlap anchor, or zero when absent.
    pub overlap_start_height: u64,
    /// Last height inside this segment's exact-overlap anchor, or zero when absent.
    pub overlap_end_height: u64,
    /// Canonical root hash of the overlap anchor's recovered-publication bundle hashes.
    #[serde(default)]
    pub overlap_root_hash: [u8; 32],
}

/// Published update rule for archived recovered-history checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub enum ArchivedRecoveredHistoryCheckpointUpdateRule {
    /// Publish a fresh archival checkpoint for every published archived segment/page tip.
    #[default]
    EveryPublishedSegmentV1,
}

/// Compact active profile naming the archived recovered-history availability geometry.
///
/// This keeps the archival retention and exact-overlap page geometry protocol-native
/// instead of leaving it as an implementation-side constant.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryProfile {
    /// Height horizon through which archived checkpoints are retained.
    pub retention_horizon: u64,
    /// Restart-page window width used by archived exact-overlap paging.
    pub restart_page_window: u64,
    /// Restart-page overlap width used by archived exact-overlap paging.
    pub restart_page_overlap: u64,
    /// Number of recovered windows folded into one archived segment page.
    pub windows_per_segment: u64,
    /// Number of segments folded into one archived page range.
    pub segments_per_fold: u64,
    /// Published checkpoint update rule for this archived-history profile.
    #[serde(default)]
    pub checkpoint_update_rule: ArchivedRecoveredHistoryCheckpointUpdateRule,
}

/// Cold-path activation event making archived recovered-history profile evolution protocol-native.
///
/// This object names which archived profile governs archived recovered-history outputs starting at
/// one archived tip end height. Historical replay must validate archived objects against the
/// profile hash they reference and the activation chain that made that profile active.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryProfileActivation {
    /// Canonical hash of the archived recovered-history profile that becomes active.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the previously active archived recovered-history profile, or zero at
    /// bootstrap.
    #[serde(default)]
    pub previous_archived_profile_hash: [u8; 32],
    /// First archived tip end height governed by `archived_profile_hash`.
    pub activation_end_height: u64,
    /// Optional canonical hash of the first archived checkpoint tip governed by this profile.
    #[serde(default)]
    pub activation_checkpoint_hash: [u8; 32],
}

/// Content-addressed archived restart payload for one archived recovered-history segment.
///
/// This is the cold-path restart-consumer surface. It archives the recovered
/// restart block-header entries needed to resume bounded ancestry lookup when
/// the retained recovered publication surface is no longer locally available.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredRestartPage {
    /// Canonical hash of the archived recovered-history segment this page satisfies.
    #[serde(default)]
    pub segment_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile that governs this page.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// page.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// First height covered by the archived restart page.
    pub start_height: u64,
    /// Last height covered by the archived restart page.
    pub end_height: u64,
    /// Archived recovered restart headers for the covered range.
    #[serde(default)]
    pub restart_headers: Vec<RecoveredRestartBlockHeaderEntry>,
}

/// Compact archival checkpoint naming the current archived recovered-history tip.
///
/// This is the cold-path bootstrap surface for restart-time ancestry paging. It
/// commits to the latest archived segment/page pair, the covered height range,
/// and the previous checkpoint hash so archived recovered-history availability
/// is named by AFT itself instead of inferred from local retained state.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryCheckpoint {
    /// First height covered by the latest archived range.
    pub covered_start_height: u64,
    /// Last height covered by the latest archived range.
    pub covered_end_height: u64,
    /// Canonical hash of the archived recovered-history profile that governs this checkpoint.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// checkpoint.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// Canonical hash of the latest archived recovered-history segment.
    #[serde(default)]
    pub latest_archived_segment_hash: [u8; 32],
    /// Canonical hash of the latest archived recovered restart-page payload.
    #[serde(default)]
    pub latest_archived_restart_page_hash: [u8; 32],
    /// Canonical hash of the previous archived recovered-history checkpoint.
    #[serde(default)]
    pub previous_archived_checkpoint_hash: [u8; 32],
}

/// Compact archival retention receipt binding an archived checkpoint to the
/// validator-set commitment currently retaining it.
///
/// This is the cold-path accountability surface that says the current archived
/// recovered-history checkpoint is not only named by AFT, but is also retained
/// by the active validator-set commitment through a declared height horizon.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct ArchivedRecoveredHistoryRetentionReceipt {
    /// First height covered by the retained archived checkpoint.
    pub covered_start_height: u64,
    /// Last height covered by the retained archived checkpoint.
    pub covered_end_height: u64,
    /// Canonical hash of the archived recovered-history profile that governs this receipt.
    #[serde(default)]
    pub archived_profile_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history profile activation that governs this
    /// receipt.
    #[serde(default)]
    pub archived_profile_activation_hash: [u8; 32],
    /// Canonical hash of the retained archived recovered-history checkpoint.
    #[serde(default)]
    pub archived_checkpoint_hash: [u8; 32],
    /// Canonical hash of the validator-set commitment retaining this checkpoint.
    #[serde(default)]
    pub validator_set_commitment_hash: [u8; 32],
    /// Height through which this archived checkpoint is retained.
    pub retained_through_height: u64,
}

/// Off-chain witness-local delivery envelope for an assigned recovery share.
///
/// This is deliberately not a hot-path publication object. It exists so the
/// assigned witness committee can durably store the exact share material it is
/// about to bind in its signed witness certificate before any member signs.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AssignedRecoveryShareEnvelopeV1 {
    /// Canonical hash of the bound recovery capsule.
    #[serde(default)]
    pub recovery_capsule_hash: [u8; 32],
    /// Share commitment the witness statement is expected to sign.
    #[serde(default)]
    pub expected_share_commitment_hash: [u8; 32],
    /// Full cold-path share material the witness stores for later reveal.
    #[serde(default)]
    pub share_material: RecoveryShareMaterial,
}

impl AssignedRecoveryShareEnvelopeV1 {
    /// Reconstructs the signed recovery binding this envelope is expected to satisfy.
    pub fn recovery_binding(&self) -> GuardianWitnessRecoveryBinding {
        GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: self.recovery_capsule_hash,
            share_commitment_hash: self.expected_share_commitment_hash,
        }
    }

    /// Checks the envelope's basic witness-local invariants before it is stored.
    pub fn validate_for_witness(
        &self,
        expected_manifest_hash: [u8; 32],
        expected_height: u64,
    ) -> Result<(), String> {
        if self.recovery_capsule_hash == [0u8; 32] {
            return Err(
                "assigned recovery share envelope is missing a recovery capsule hash".into(),
            );
        }
        if self.expected_share_commitment_hash == [0u8; 32] {
            return Err(
                "assigned recovery share envelope is missing an expected share commitment hash"
                    .into(),
            );
        }
        if self.share_material.height != expected_height {
            return Err(
                "assigned recovery share envelope height does not match the signed witness statement"
                    .into(),
            );
        }
        if self.share_material.witness_manifest_hash != expected_manifest_hash {
            return Err(
                "assigned recovery share envelope witness manifest does not match the assigned witness"
                    .into(),
            );
        }
        if self.share_material.share_commitment_hash != self.expected_share_commitment_hash {
            return Err(
                "assigned recovery share envelope material does not match the expected share commitment hash"
                    .into(),
            );
        }
        if self.share_material.block_commitment_hash == [0u8; 32] {
            return Err(
                "assigned recovery share envelope is missing the bound block commitment hash"
                    .into(),
            );
        }
        self.share_material.coding.validate().map_err(|error| {
            format!("assigned recovery share envelope has invalid coding: {error}")
        })?;
        if self.share_material.share_index >= self.share_material.coding.share_count {
            return Err("assigned recovery share envelope share index exceeds share count".into());
        }
        if self.share_material.material_bytes.is_empty() {
            return Err("assigned recovery share envelope is missing share material bytes".into());
        }
        Ok(())
    }
}

/// Compact public claim that an assigned recovery share was missing at window close.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct MissingRecoveryShare {
    /// Slot / height whose recovery share is missing.
    pub height: u64,
    /// Witness manifest that failed to reveal its assigned share.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Canonical hash of the bound recovery capsule.
    #[serde(default)]
    pub recovery_capsule_hash: [u8; 32],
    /// Deterministic recovery-window close used to make missingness objective.
    pub recovery_window_close_ms: u64,
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

/// Compact receipt carried by the live protocol for a publication surface's availability binding.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct PublicationAvailabilityReceipt {
    /// Slot / height whose publication surface is being summarized.
    pub height: u64,
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical root of the ordered transaction surface.
    #[serde(default)]
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical root of the resulting post-state.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Compact recoverability / availability receipt root bound into the live frontier.
    #[serde(default)]
    pub receipt_root: [u8; 32],
}

/// Compact signed publication-frontier summary carried in the block header preimage.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct PublicationFrontier {
    /// Slot / height whose publication surface is summarized.
    pub height: u64,
    /// Consensus view that carried this signed frontier.
    pub view: u64,
    /// Monotone slot counter for the publication trace.
    pub counter: u64,
    /// Canonical hash of the previous slot's publication frontier.
    #[serde(default)]
    pub parent_frontier_hash: [u8; 32],
    /// Canonical hash of the bound bulletin commitment.
    #[serde(default)]
    pub bulletin_commitment_hash: [u8; 32],
    /// Canonical root of the ordered live message / transaction surface.
    #[serde(default)]
    pub ordered_transactions_root_hash: [u8; 32],
    /// Canonical hash of the compact availability receipt carried by the frontier.
    #[serde(default)]
    pub availability_receipt_hash: [u8; 32],
}

/// First objective contradiction family for publication-frontier disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PublicationFrontierContradictionKind {
    /// Two same-slot frontiers disagree on the signed compact publication summary.
    #[default]
    ConflictingFrontier,
    /// A frontier does not extend the previous published / committed frontier.
    StaleParentLink,
}

/// Short objective contradiction witness over compact publication-frontier summaries.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct PublicationFrontierContradiction {
    /// Slot / height whose frontier is contradicted.
    pub height: u64,
    /// Contradiction family.
    #[serde(default)]
    pub kind: PublicationFrontierContradictionKind,
    /// The candidate frontier being rejected.
    #[serde(default)]
    pub candidate_frontier: PublicationFrontier,
    /// The conflicting same-slot frontier or the expected predecessor frontier.
    #[serde(default)]
    pub reference_frontier: PublicationFrontier,
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
    /// The committed block does not carry the required signed publication frontier.
    MissingPublicationFrontier,
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
    /// A same-slot compact publication frontier conflicts with an already published frontier.
    PublicationFrontierConflict,
    /// A compact publication frontier does not extend the previous frontier.
    PublicationFrontierStale,
    /// Distinct recovered publication bundles disagree on the recovered slot surface.
    RecoverySupportConflict,
    /// Published recovery receipts / missingness make threshold reconstruction impossible.
    RecoveryThresholdImpossible,
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
    /// Canonical hash of the latest archived recovered-history checkpoint named by ordinary
    /// canonical history at this slot.
    #[serde(default)]
    pub archived_recovered_history_checkpoint_hash: [u8; 32],
    /// Canonical hash of the governing archived recovered-history profile activation referenced by
    /// ordinary canonical history at this slot.
    #[serde(default)]
    pub archived_recovered_history_profile_activation_hash: [u8; 32],
    /// Canonical hash of the archived recovered-history retention receipt referenced by ordinary
    /// canonical history at this slot.
    #[serde(default)]
    pub archived_recovered_history_retention_receipt_hash: [u8; 32],
}

/// Compact durable prefix entry exposed to replay / checkpoint consumers.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CanonicalReplayPrefixEntry {
    /// Slot / height of the durable prefix entry.
    pub height: u64,
    /// Canonical root hash of the committed post-state for this slot.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Canonical block hash / next-parent hash when objectively derivable from the recovered slot
    /// surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_block_commitment_hash: Option<[u8; 32]>,
    /// Canonical parent block hash carried by this slot when objectively derivable from the
    /// recovered slot surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_block_commitment_hash: Option<[u8; 32]>,
    /// Canonical hash of this slot's collapse predecessor commitment.
    #[serde(default)]
    pub canonical_collapse_commitment_hash: [u8; 32],
    /// Canonical hash of the previous slot's collapse predecessor commitment.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
    /// Whether ordering resolved to the positive close or negative abort path.
    #[serde(default)]
    pub ordering_kind: CanonicalCollapseKind,
    /// Canonical hash of the close-or-abort ordering resolution carried by this slot.
    #[serde(default)]
    pub ordering_resolution_hash: [u8; 32],
    /// Canonical hash of the latest compact publication frontier when one exists for this slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_frontier_hash: Option<[u8; 32]>,
    /// Whether the ordinary extracted bulletin surface is present for this slot.
    #[serde(default)]
    pub extracted_bulletin_surface_present: bool,
    /// Canonical hash of the archived recovered-history checkpoint named by ordinary canonical
    /// history at this slot, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_recovered_history_checkpoint_hash: Option<[u8; 32]>,
    /// Canonical hash of the governing archived recovered-history profile activation named by
    /// ordinary canonical history at this slot, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_recovered_history_profile_activation_hash: Option<[u8; 32]>,
    /// Canonical hash of the archived recovered-history retention receipt named by ordinary
    /// canonical history at this slot, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_recovered_history_retention_receipt_hash: Option<[u8; 32]>,
}

/// Compact ordinary-AFT continuation anchor naming the deeper historical continuation root.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AftHistoricalContinuationAnchor {
    /// Canonical hash of the historical checkpoint named by ordinary AFT history.
    #[serde(default)]
    pub checkpoint_hash: [u8; 32],
    /// Canonical hash of the governing historical profile activation named by ordinary AFT
    /// history.
    #[serde(default)]
    pub profile_activation_hash: [u8; 32],
    /// Canonical hash of the retention receipt binding the historical checkpoint into ordinary AFT
    /// history.
    #[serde(default)]
    pub retention_receipt_hash: [u8; 32],
}

/// AFT-native alias for the compact archived checkpoint carried by the ordinary historical
/// continuation surface.
pub type AftHistoricalCheckpoint = ArchivedRecoveredHistoryCheckpoint;

/// AFT-native alias for the profile that governs the ordinary historical continuation surface.
pub type AftHistoricalProfile = ArchivedRecoveredHistoryProfile;

/// AFT-native alias for the activation that governs the ordinary historical continuation surface.
pub type AftHistoricalProfileActivation = ArchivedRecoveredHistoryProfileActivation;

/// AFT-native alias for the retention receipt that binds the ordinary historical continuation
/// surface into authoritative AFT state.
pub type AftHistoricalRetentionReceipt = ArchivedRecoveredHistoryRetentionReceipt;

/// Ordinary AFT historical-continuation bundle carried alongside the recovered-state surface.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AftHistoricalContinuationSurface {
    /// Compact anchor named by ordinary canonical AFT history.
    pub anchor: AftHistoricalContinuationAnchor,
    /// Historical checkpoint reached by the ordinary continuation anchor.
    pub checkpoint: AftHistoricalCheckpoint,
    /// Governing historical profile activation reached by the ordinary continuation anchor.
    pub profile_activation: AftHistoricalProfileActivation,
    /// Retention receipt binding the anchored continuation into authoritative AFT state.
    pub retention_receipt: AftHistoricalRetentionReceipt,
}

/// Compact recovered header entry exposed to bounded restart / ancestry consumers.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveredCanonicalHeaderEntry {
    /// Slot / height of the recovered header entry.
    pub height: u64,
    /// Canonical view carried by the recovered slot surface.
    #[serde(default)]
    pub view: u64,
    /// Canonical block hash / next-parent hash recovered for this slot.
    #[serde(default)]
    pub canonical_block_commitment_hash: [u8; 32],
    /// Canonical parent block hash carried by the recovered slot surface.
    #[serde(default)]
    pub parent_block_commitment_hash: [u8; 32],
    /// Canonical ordered-transactions root hash carried by the recovered slot surface.
    #[serde(default)]
    pub transactions_root_hash: [u8; 32],
    /// Canonical resulting state root carried by the recovered slot surface.
    #[serde(default)]
    pub resulting_state_root_hash: [u8; 32],
    /// Canonical predecessor collapse commitment hash that this slot extends.
    #[serde(default)]
    pub previous_canonical_collapse_commitment_hash: [u8; 32],
}

impl RecoveredCanonicalHeaderEntry {
    /// Builds the restart-only synthetic quorum certificate certified by this recovered slot.
    pub fn synthetic_quorum_certificate(&self) -> QuorumCertificate {
        QuorumCertificate {
            height: self.height,
            view: self.view,
            block_hash: self.canonical_block_commitment_hash,
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        }
    }
}

/// Compact recovered certified-header entry exposed to bounded restart / QC consumers.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct RecoveredCertifiedHeaderEntry {
    /// Recovered canonical-header identity for this certified slot.
    pub header: RecoveredCanonicalHeaderEntry,
    /// Synthetic parent QC implied by the bounded recovered prefix for this slot.
    #[serde(default)]
    pub certified_parent_quorum_certificate: QuorumCertificate,
    /// Canonical resulting state root carried by the certified parent slot.
    #[serde(default)]
    pub certified_parent_resulting_state_root_hash: [u8; 32],
}

impl RecoveredCertifiedHeaderEntry {
    /// Builds the restart-only synthetic quorum certificate certified by this recovered slot.
    pub fn certified_quorum_certificate(&self) -> QuorumCertificate {
        self.header.synthetic_quorum_certificate()
    }
}

/// Restart-only recovered block-header cache entry for bounded QC/header lookup.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct RecoveredRestartBlockHeaderEntry {
    /// Compact recovered certified-header linkage for this slot.
    pub certified_header: RecoveredCertifiedHeaderEntry,
    /// Restart-only synthetic block header derived from the recovered closed-slot surface.
    pub header: BlockHeader,
}

impl RecoveredRestartBlockHeaderEntry {
    /// Builds the restart-only synthetic quorum certificate certified by this recovered slot.
    pub fn certified_quorum_certificate(&self) -> QuorumCertificate {
        self.certified_header.certified_quorum_certificate()
    }
}

/// AFT-native alias for the compact replay-prefix entry exposed to restart and replay consumers.
pub type AftRecoveredReplayEntry = CanonicalReplayPrefixEntry;

/// AFT-native alias for the compact recovered consensus-header entry exposed to restart consumers.
pub type AftRecoveredConsensusHeaderEntry = RecoveredCanonicalHeaderEntry;

/// AFT-native alias for the compact recovered certified-header entry exposed to restart consumers.
pub type AftRecoveredCertifiedHeaderEntry = RecoveredCertifiedHeaderEntry;

/// AFT-native alias for the restart-only recovered block-header cache entry exposed to restart
/// consumers.
pub type AftRecoveredRestartHeaderEntry = RecoveredRestartBlockHeaderEntry;

/// AFT-native recovered-state contract consumed by replay, restart, and bounded ancestry
/// continuation.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct AftRecoveredStateSurface {
    /// Compact durable replay prefix recovered for the requested height window.
    #[serde(default)]
    pub replay_prefix: Vec<AftRecoveredReplayEntry>,
    /// Compact recovered consensus-header prefix for the requested height window.
    #[serde(default)]
    pub consensus_headers: Vec<AftRecoveredConsensusHeaderEntry>,
    /// Compact recovered certified-header prefix for the requested height window.
    #[serde(default)]
    pub certified_headers: Vec<AftRecoveredCertifiedHeaderEntry>,
    /// Restart-only recovered block-header cache entries for the requested height window.
    #[serde(default)]
    pub restart_headers: Vec<AftRecoveredRestartHeaderEntry>,
    /// Ordinary historical continuation bundle named by canonical AFT history at the recovered tip,
    /// when deeper paging beyond the retained suffix is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub historical_continuation: Option<AftHistoricalContinuationSurface>,
}

/// Summary of how much of an AFT recovered-state surface a consensus engine accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AftRecoveredStateObservationStats {
    /// Number of recovered consensus-header entries accepted by the engine.
    pub accepted_consensus_headers: usize,
    /// Number of recovered certified-header entries accepted by the engine.
    pub accepted_certified_headers: usize,
    /// Number of recovered restart-header entries accepted by the engine.
    pub accepted_restart_headers: usize,
}

impl AftRecoveredStateObservationStats {
    /// Returns true when the engine accepted at least one recovered-state hint.
    pub fn accepted_any(&self) -> bool {
        self.accepted_consensus_headers > 0
            || self.accepted_certified_headers > 0
            || self.accepted_restart_headers > 0
    }
}

/// One cold-path page of exact-overlap recovered certified-branch ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCertifiedBranchPage {
    /// First height covered by this page.
    pub start_height: u64,
    /// Last height covered by this page.
    pub end_height: u64,
    /// Exact-overlap window ranges grouped into segment slices.
    pub segments: Vec<Vec<(u64, u64)>>,
}

/// Deterministic cold-path cursor for paging older recovered certified-branch pages.
///
/// The cursor starts from an already loaded bounded recovered suffix and then
/// pages one older exact-overlap segment fold at a time while keeping only the
/// current loaded page plus the next overlap candidate in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCertifiedBranchCursor {
    loaded_page: RecoveredCertifiedBranchPage,
    next_page_end_height: u64,
    next_overlap_candidate_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
}

/// Backwards-compatible alias for a cold-path recovered certified-branch page.
pub type RecoveredSegmentFoldPage = RecoveredCertifiedBranchPage;
/// Backwards-compatible alias for a cold-path recovered certified-branch cursor.
pub type RecoveredSegmentFoldCursor = RecoveredCertifiedBranchCursor;

impl RecoveredCertifiedBranchCursor {
    /// Builds a cursor for paging older recovered segment folds that precede an
    /// already loaded bounded suffix ending at `end_height`.
    pub fn new(
        end_height: u64,
        window: u64,
        overlap: u64,
        windows_per_segment: u64,
        segments_per_fold: u64,
        initial_fold_count: u64,
    ) -> Result<Self, String> {
        if end_height == 0 {
            return Err("recovered segment-fold cursor requires a non-zero end height".into());
        }
        if window == 0
            || windows_per_segment == 0
            || segments_per_fold == 0
            || initial_fold_count == 0
        {
            return Err(
                "recovered segment-fold cursor requires non-zero window, segment, and fold budgets"
                    .into(),
            );
        }

        let initial_start_height = recovered_segment_fold_start_height(
            end_height,
            window,
            overlap,
            windows_per_segment,
            segments_per_fold,
            initial_fold_count,
        );
        let loaded_page = RecoveredCertifiedBranchPage {
            start_height: initial_start_height,
            end_height,
            segments: recovered_segment_ranges(
                initial_start_height,
                end_height,
                window,
                overlap,
                windows_per_segment,
            ),
        };

        let next_page_end_height = if loaded_page.start_height <= 1 {
            0
        } else {
            loaded_page.start_height
                + recovered_segment_fold_overlap(
                    window,
                    overlap,
                    windows_per_segment,
                    segments_per_fold,
                )?
                - 1
        };
        let next_overlap_candidate_height = if next_page_end_height == 0 {
            0
        } else {
            next_page_end_height
        };

        Ok(Self {
            loaded_page,
            next_page_end_height,
            next_overlap_candidate_height,
            window,
            overlap,
            windows_per_segment,
            segments_per_fold,
        })
    }

    /// Returns the currently loaded bounded recovered page.
    pub fn loaded_page(&self) -> &RecoveredCertifiedBranchPage {
        &self.loaded_page
    }

    /// Returns the oldest height currently loaded by this cursor.
    pub fn oldest_loaded_height(&self) -> u64 {
        self.loaded_page.start_height
    }

    /// Returns the end height that the next older page will cover, if any.
    pub fn next_page_end_height(&self) -> Option<u64> {
        (self.next_page_end_height > 0).then_some(self.next_page_end_height)
    }

    /// Returns the overlap height the next older page must match, if any.
    pub fn next_overlap_candidate_height(&self) -> Option<u64> {
        (self.next_overlap_candidate_height > 0).then_some(self.next_overlap_candidate_height)
    }

    /// Returns the next older exact-overlap page the cursor expects, if any.
    pub fn expected_next_page(&self) -> Result<Option<RecoveredCertifiedBranchPage>, String> {
        let Some(end_height) = self.next_page_end_height() else {
            return Ok(None);
        };

        let fold_span = recovered_segment_fold_span(
            self.window,
            self.overlap,
            self.windows_per_segment,
            self.segments_per_fold,
        )?;
        let start_height = end_height
            .saturating_sub(fold_span.saturating_sub(1))
            .max(1);
        Ok(Some(RecoveredCertifiedBranchPage {
            start_height,
            end_height,
            segments: recovered_segment_ranges(
                start_height,
                end_height,
                self.window,
                self.overlap,
                self.windows_per_segment,
            ),
        }))
    }

    /// Accepts the next older page after validating that it is the exact page
    /// this cursor expects to load.
    pub fn accept_page(&mut self, page: &RecoveredCertifiedBranchPage) -> Result<(), String> {
        let Some(expected) = self.expected_next_page()? else {
            return Err("recovered certified-branch cursor is already exhausted".into());
        };
        if page != &expected {
            return Err(format!(
                "recovered certified-branch cursor expected page {}..={} but received {}..={}",
                expected.start_height, expected.end_height, page.start_height, page.end_height
            ));
        }

        self.loaded_page = page.clone();
        self.next_page_end_height = if page.start_height <= 1 {
            0
        } else {
            page.start_height
                + recovered_segment_fold_overlap(
                    self.window,
                    self.overlap,
                    self.windows_per_segment,
                    self.segments_per_fold,
                )?
                - 1
        };
        self.next_overlap_candidate_height = self.next_page_end_height;
        Ok(())
    }

    /// Returns and consumes the next older exact-overlap page, if any.
    pub fn next_page(&mut self) -> Result<Option<RecoveredCertifiedBranchPage>, String> {
        let Some(page) = self.expected_next_page()? else {
            return Ok(None);
        };
        self.accept_page(&page)?;
        Ok(Some(page))
    }
}

/// Validates that a recovered page covers exactly the heights it claims.
pub fn validate_recovered_page_coverage<T, F>(
    page: &RecoveredCertifiedBranchPage,
    entries: &[T],
    height_of: F,
    label: &str,
) -> Result<(), String>
where
    F: Fn(&T) -> u64,
{
    if page.start_height == 0 || page.end_height == 0 || page.end_height < page.start_height {
        return Err(format!(
            "{label} page has an invalid height range {}..={}",
            page.start_height, page.end_height
        ));
    }
    let expected_len = usize::try_from(page.end_height - page.start_height + 1)
        .map_err(|_| format!("{label} page length overflow"))?;
    if entries.len() != expected_len {
        return Err(format!(
            "{label} page {}..={} expected {} entries but loaded {}",
            page.start_height,
            page.end_height,
            expected_len,
            entries.len()
        ));
    }
    if let Some(first) = entries.first() {
        let first_height = height_of(first);
        if first_height != page.start_height {
            return Err(format!(
                "{label} page {}..={} started at loaded height {}",
                page.start_height, page.end_height, first_height
            ));
        }
    }
    if let Some(last) = entries.last() {
        let last_height = height_of(last);
        if last_height != page.end_height {
            return Err(format!(
                "{label} page {}..={} ended at loaded height {}",
                page.start_height, page.end_height, last_height
            ));
        }
    }
    for pair in entries.windows(2) {
        let previous_height = height_of(&pair[0]);
        let next_height = height_of(&pair[1]);
        if next_height != previous_height + 1 {
            return Err(format!(
                "{label} page {}..={} is not consecutive at heights {} then {}",
                page.start_height, page.end_height, previous_height, next_height
            ));
        }
    }
    Ok(())
}

fn recovered_window_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
) -> Vec<(u64, u64)> {
    if start_height == 0 || end_height == 0 || window == 0 || end_height < start_height {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let mut ranges = Vec::new();
    let step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let mut next_start = start_height;

    loop {
        let next_end = next_start
            .saturating_add(window.saturating_sub(1))
            .min(end_height);
        ranges.push((next_start, next_end));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(step);
    }

    ranges
}

fn recovered_segment_step(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Result<u64, String> {
    if window == 0 || windows_per_segment == 0 {
        return Err("recovered segment step requires non-zero window and segment width".into());
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    Ok(raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1))
}

fn recovered_segment_span(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Result<u64, String> {
    if window == 0 || windows_per_segment == 0 {
        return Err("recovered segment span requires non-zero window and segment width".into());
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    Ok(window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1))))
}

fn recovered_segment_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Vec<Vec<(u64, u64)>> {
    if start_height == 0
        || end_height == 0
        || window == 0
        || windows_per_segment == 0
        || end_height < start_height
    {
        return Vec::new();
    }

    let Ok(segment_span) = recovered_segment_span(window, overlap, windows_per_segment) else {
        return Vec::new();
    };
    let Ok(segment_step) = recovered_segment_step(window, overlap, windows_per_segment) else {
        return Vec::new();
    };

    let mut next_start = start_height;
    let mut segments = Vec::new();

    loop {
        let next_end = next_start
            .saturating_add(segment_span.saturating_sub(1))
            .min(end_height);
        segments.push(recovered_window_ranges(
            next_start, next_end, window, overlap,
        ));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(segment_step);
    }

    segments
}

fn recovered_segment_fold_span(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<u64, String> {
    if segments_per_fold == 0 {
        return Err("recovered segment-fold span requires a non-zero fold width".into());
    }

    let segment_span = recovered_segment_span(window, overlap, windows_per_segment)?;
    let segment_step = recovered_segment_step(window, overlap, windows_per_segment)?;
    Ok(segment_span
        .saturating_add(segment_step.saturating_mul(segments_per_fold.saturating_sub(1))))
}

fn recovered_segment_fold_step(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<u64, String> {
    if segments_per_fold == 0 {
        return Err("recovered segment-fold step requires a non-zero fold width".into());
    }

    let segment_step = recovered_segment_step(window, overlap, windows_per_segment)?;
    Ok(segment_step
        .saturating_mul(segments_per_fold.saturating_sub(1))
        .max(1))
}

fn recovered_segment_fold_overlap(
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<u64, String> {
    let fold_span =
        recovered_segment_fold_span(window, overlap, windows_per_segment, segments_per_fold)?;
    let fold_step =
        recovered_segment_fold_step(window, overlap, windows_per_segment, segments_per_fold)?;
    Ok(fold_span.saturating_sub(fold_step))
}

fn recovered_segment_fold_start_height(
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    fold_count: u64,
) -> u64 {
    if end_height == 0
        || window == 0
        || windows_per_segment == 0
        || segments_per_fold == 0
        || fold_count == 0
    {
        return 0;
    }

    let Ok(fold_span) =
        recovered_segment_fold_span(window, overlap, windows_per_segment, segments_per_fold)
    else {
        return 0;
    };
    let Ok(fold_step) =
        recovered_segment_fold_step(window, overlap, windows_per_segment, segments_per_fold)
    else {
        return 0;
    };
    let covered_span =
        fold_span.saturating_add(fold_step.saturating_mul(fold_count.saturating_sub(1)));
    end_height
        .saturating_sub(covered_span.saturating_sub(1))
        .max(1)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
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

/// Returns the canonical hash of an exploratory witness-coded recovery capsule.
pub fn canonical_recovery_capsule_hash(capsule: &RecoveryCapsule) -> Result<[u8; 32], String> {
    hash_consensus_bytes(capsule)
}

/// Returns the canonical hash of an exploratory recovery witness certificate.
pub fn canonical_recovery_witness_certificate_hash(
    certificate: &RecoveryWitnessCertificate,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(certificate)
}

/// Returns the canonical hash of an exploratory recovery share receipt.
pub fn canonical_recovery_share_receipt_hash(
    receipt: &RecoveryShareReceipt,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(receipt)
}

/// Returns the canonical hash of exploratory recovery share-reveal material.
pub fn canonical_recovery_share_material_hash(
    material: &RecoveryShareMaterial,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(material)
}

/// Returns the canonical hash of a compact recovered-publication bundle object.
pub fn canonical_recovered_publication_bundle_hash(
    recovered_bundle: &RecoveredPublicationBundle,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(recovered_bundle)
}

/// Returns the canonical root hash of the recovered-publication bundles named by one archived segment.
pub fn canonical_archived_recovered_history_segment_root(
    recovered_bundle_hashes: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    if recovered_bundle_hashes.is_empty() {
        return Err("archived recovered-history segment requires at least one bundle hash".into());
    }
    hash_consensus_bytes(&recovered_bundle_hashes.to_vec())
}

/// Returns the canonical hash of an archived recovered-history segment descriptor.
pub fn canonical_archived_recovered_history_segment_hash(
    segment: &ArchivedRecoveredHistorySegment,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(segment)
}

/// Returns the canonical hash of an archived recovered-history profile.
pub fn canonical_archived_recovered_history_profile_hash(
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(profile)
}

/// Returns the canonical hash of an archived recovered-history profile activation.
pub fn canonical_archived_recovered_history_profile_activation_hash(
    activation: &ArchivedRecoveredHistoryProfileActivation,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(activation)
}

/// Returns the canonical hash of an archived recovered restart-page payload.
pub fn canonical_archived_recovered_restart_page_hash(
    page: &ArchivedRecoveredRestartPage,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(page)
}

/// Returns the canonical hash of an archived recovered-history checkpoint.
pub fn canonical_archived_recovered_history_checkpoint_hash(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(checkpoint)
}

/// Returns the canonical hash of an archived recovered-history retention receipt.
pub fn canonical_archived_recovered_history_retention_receipt_hash(
    receipt: &ArchivedRecoveredHistoryRetentionReceipt,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(receipt)
}

/// Returns the canonical hash of a decoded validator-set commitment.
pub fn canonical_validator_sets_hash(sets: &ValidatorSetsV1) -> Result<[u8; 32], String> {
    hash_consensus_bytes(sets)
}

/// Validates one archived recovered-history profile.
pub fn validate_archived_recovered_history_profile(
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    if profile.retention_horizon == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero retention horizon".into(),
        );
    }
    if profile.restart_page_window == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero restart-page window".into(),
        );
    }
    if profile.windows_per_segment == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero windows-per-segment value"
                .into(),
        );
    }
    if profile.segments_per_fold == 0 {
        return Err(
            "archived recovered-history profile requires a non-zero segments-per-fold value".into(),
        );
    }
    let _ = archived_recovered_restart_page_range(
        1,
        profile.restart_page_window,
        profile.restart_page_overlap,
        profile.windows_per_segment,
        profile.segments_per_fold,
    )?;
    match profile.checkpoint_update_rule {
        ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1 => Ok(()),
    }
}

/// Builds an archived recovered-history profile after validating its geometry.
pub fn build_archived_recovered_history_profile(
    retention_horizon: u64,
    restart_page_window: u64,
    restart_page_overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    checkpoint_update_rule: ArchivedRecoveredHistoryCheckpointUpdateRule,
) -> Result<ArchivedRecoveredHistoryProfile, String> {
    let profile = ArchivedRecoveredHistoryProfile {
        retention_horizon,
        restart_page_window,
        restart_page_overlap,
        windows_per_segment,
        segments_per_fold,
        checkpoint_update_rule,
    };
    validate_archived_recovered_history_profile(&profile)?;
    Ok(profile)
}

/// Validates one archived recovered-history profile activation against its referenced profile.
pub fn validate_archived_recovered_history_profile_activation(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if activation.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history profile activation hash {:?} does not match the referenced profile hash {:?}",
            activation.archived_profile_hash, profile_hash
        ));
    }
    if activation.activation_end_height == 0 {
        return Err(
            "archived recovered-history profile activation requires a non-zero activation end height"
                .into(),
        );
    }
    Ok(())
}

/// Verifies that one archived recovered-history profile activation is a valid successor of
/// another.
pub fn validate_archived_recovered_history_profile_activation_successor(
    previous_activation: &ArchivedRecoveredHistoryProfileActivation,
    current_activation: &ArchivedRecoveredHistoryProfileActivation,
) -> Result<(), String> {
    if current_activation.previous_archived_profile_hash
        != previous_activation.archived_profile_hash
    {
        return Err(
            "archived recovered-history profile activation predecessor hash does not match the previously active profile"
                .into(),
        );
    }
    if current_activation.activation_end_height <= previous_activation.activation_end_height {
        return Err(
            "archived recovered-history profile activation must advance to a strictly later archived tip height"
                .into(),
        );
    }
    Ok(())
}

/// Verifies that one archived recovered-history profile activation governs the supplied archived
/// tip height, optionally bounded above by a successor activation.
pub fn validate_archived_recovered_history_profile_activation_covering_tip_height(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    successor_activation: Option<&ArchivedRecoveredHistoryProfileActivation>,
    covered_end_height: u64,
) -> Result<(), String> {
    if covered_end_height < activation.activation_end_height {
        return Err(format!(
            "archived recovered-history object ending at height {} predates the governing profile activation tip {}",
            covered_end_height, activation.activation_end_height
        ));
    }
    if let Some(successor_activation) = successor_activation {
        if covered_end_height >= successor_activation.activation_end_height {
            return Err(format!(
                "archived recovered-history object ending at height {} crosses the successor profile activation tip {}",
                covered_end_height, successor_activation.activation_end_height
            ));
        }
    }
    Ok(())
}

/// Verifies the optional activation checkpoint named by one archived recovered-history profile
/// activation.
pub fn validate_archived_recovered_history_profile_activation_checkpoint(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    activation_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    validate_archived_recovered_history_profile_activation(activation, profile)?;
    let checkpoint_hash = activation.activation_checkpoint_hash;
    if checkpoint_hash == [0u8; 32] {
        return if activation_checkpoint.is_none() {
            Ok(())
        } else {
            Err(
                "archived recovered-history profile activation unexpectedly received a checkpoint despite carrying no activation checkpoint hash"
                    .into(),
            )
        };
    }
    let Some(checkpoint) = activation_checkpoint else {
        return Err(
            "archived recovered-history profile activation references an activation checkpoint that is missing from state"
                .into(),
        );
    };
    let expected_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(checkpoint)?;
    if expected_checkpoint_hash != checkpoint_hash {
        return Err(
            "archived recovered-history profile activation checkpoint hash does not match the published activation checkpoint"
                .into(),
        );
    }
    if checkpoint.archived_profile_hash != activation.archived_profile_hash {
        return Err(
            "archived recovered-history profile activation checkpoint profile hash does not match the activated profile"
                .into(),
        );
    }
    if checkpoint.covered_end_height != activation.activation_end_height {
        return Err(
            "archived recovered-history profile activation checkpoint tip does not match the declared activation end height"
                .into(),
        );
    }
    Ok(())
}

/// Verifies that one archived recovered-history profile activation governs the supplied archived
/// checkpoint without consulting any current activation index.
pub fn validate_archived_recovered_history_profile_activation_against_checkpoint(
    activation: &ArchivedRecoveredHistoryProfileActivation,
    activation_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    validate_archived_recovered_history_profile_activation_checkpoint(
        activation,
        activation_checkpoint,
        profile,
    )?;
    if checkpoint.archived_profile_hash != activation.archived_profile_hash {
        return Err(
            "archived recovered-history checkpoint profile hash does not match the governing activation profile"
                .into(),
        );
    }
    validate_archived_recovered_history_profile_activation_covering_tip_height(
        activation,
        None,
        checkpoint.covered_end_height,
    )
}

/// Builds one archived recovered-history profile activation, chaining it from the previously
/// active profile when present.
pub fn build_archived_recovered_history_profile_activation(
    profile: &ArchivedRecoveredHistoryProfile,
    previous_activation: Option<&ArchivedRecoveredHistoryProfileActivation>,
    activation_end_height: u64,
    activation_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
) -> Result<ArchivedRecoveredHistoryProfileActivation, String> {
    let activation = ArchivedRecoveredHistoryProfileActivation {
        archived_profile_hash: canonical_archived_recovered_history_profile_hash(profile)?,
        previous_archived_profile_hash: previous_activation
            .map(|activation| activation.archived_profile_hash)
            .unwrap_or([0u8; 32]),
        activation_end_height,
        activation_checkpoint_hash: activation_checkpoint
            .map(canonical_archived_recovered_history_checkpoint_hash)
            .transpose()?
            .unwrap_or([0u8; 32]),
    };
    validate_archived_recovered_history_profile_activation(&activation, profile)?;
    if let Some(previous_activation) = previous_activation {
        validate_archived_recovered_history_profile_activation_successor(
            previous_activation,
            &activation,
        )?;
    }
    if let Some(checkpoint) = activation_checkpoint {
        if checkpoint.archived_profile_hash != activation.archived_profile_hash {
            return Err(
                "archived recovered-history profile activation checkpoint profile hash does not match the activated profile"
                    .into(),
            );
        }
        if checkpoint.covered_end_height != activation.activation_end_height {
            return Err(
                "archived recovered-history profile activation checkpoint tip does not match the declared activation end height"
                    .into(),
            );
        }
    }
    Ok(activation)
}

/// Builds a compact archived recovered-history segment descriptor from one contiguous recovered range.
pub fn build_archived_recovered_history_segment(
    recovered_bundles: &[RecoveredPublicationBundle],
    previous_segment: Option<&ArchivedRecoveredHistorySegment>,
    overlap_range: Option<(u64, u64)>,
    profile: &ArchivedRecoveredHistoryProfile,
    activation: &ArchivedRecoveredHistoryProfileActivation,
) -> Result<ArchivedRecoveredHistorySegment, String> {
    validate_archived_recovered_history_profile(profile)?;
    validate_archived_recovered_history_profile_activation(activation, profile)?;
    if recovered_bundles.is_empty() {
        return Err(
            "archived recovered-history segment requires at least one recovered bundle".into(),
        );
    }

    for pair in recovered_bundles.windows(2) {
        if pair[1].height != pair[0].height + 1 {
            return Err(
                "archived recovered-history segment requires contiguous recovered heights".into(),
            );
        }
    }

    let start_height = recovered_bundles
        .first()
        .map(|bundle| bundle.height)
        .ok_or_else(|| {
            "archived recovered-history segment is missing a start height".to_string()
        })?;
    let end_height = recovered_bundles
        .last()
        .map(|bundle| bundle.height)
        .ok_or_else(|| "archived recovered-history segment is missing an end height".to_string())?;

    if let Some(previous) = previous_segment {
        match overlap_range {
            Some((overlap_start_height, overlap_end_height)) => {
                if previous.start_height > overlap_start_height
                    || previous.end_height < overlap_end_height
                {
                    return Err(
                        "archived recovered-history segment predecessor does not cover the declared overlap anchor"
                            .into(),
                    );
                }
                if previous.end_height >= end_height {
                    return Err(
                        "archived recovered-history segment predecessor must end before the current range ends"
                            .into(),
                    );
                }
            }
            None => {
                if previous.end_height >= start_height {
                    return Err(
                        "archived recovered-history segment predecessor must end before the current range starts"
                            .into(),
                    );
                }
            }
        }
    }

    let recovered_bundle_hashes = recovered_bundles
        .iter()
        .map(canonical_recovered_publication_bundle_hash)
        .collect::<Result<Vec<_>, _>>()?;
    let segment_root_hash =
        canonical_archived_recovered_history_segment_root(&recovered_bundle_hashes)?;
    let archived_profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    let archived_profile_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(activation)?;
    validate_archived_recovered_history_profile_activation_covering_tip_height(
        activation, None, end_height,
    )?;

    let previous_archived_segment_hash = previous_segment
        .map(canonical_archived_recovered_history_segment_hash)
        .transpose()?
        .unwrap_or([0u8; 32]);

    let (overlap_start_height, overlap_end_height, overlap_root_hash) = match overlap_range {
        Some((overlap_start_height, overlap_end_height)) => {
            if overlap_start_height == 0
                || overlap_end_height == 0
                || overlap_end_height < overlap_start_height
                || overlap_start_height < start_height
                || overlap_end_height > end_height
            {
                return Err(
                    "archived recovered-history segment overlap range must lie within the covered range"
                        .into(),
                );
            }
            let start_index = usize::try_from(overlap_start_height - start_height)
                .map_err(|_| "archived recovered-history segment overlap start overflow")?;
            let end_index = usize::try_from(overlap_end_height - start_height + 1)
                .map_err(|_| "archived recovered-history segment overlap end overflow")?;
            let overlap_root_hash = canonical_archived_recovered_history_segment_root(
                &recovered_bundle_hashes[start_index..end_index],
            )?;
            (overlap_start_height, overlap_end_height, overlap_root_hash)
        }
        None => (0, 0, [0u8; 32]),
    };

    Ok(ArchivedRecoveredHistorySegment {
        start_height,
        end_height,
        archived_profile_hash,
        archived_profile_activation_hash,
        first_recovered_publication_bundle_hash: recovered_bundle_hashes[0],
        last_recovered_publication_bundle_hash: *recovered_bundle_hashes.last().ok_or_else(
            || "archived recovered-history segment is missing a last bundle hash".to_string(),
        )?,
        previous_archived_segment_hash,
        segment_root_hash,
        overlap_start_height,
        overlap_end_height,
        overlap_root_hash,
    })
}

/// Verifies that one archived recovered-history segment is a structurally valid
/// predecessor of another.
pub fn validate_archived_recovered_history_segment_predecessor(
    previous_segment: &ArchivedRecoveredHistorySegment,
    current_segment: &ArchivedRecoveredHistorySegment,
) -> Result<(), String> {
    let previous_segment_hash =
        canonical_archived_recovered_history_segment_hash(previous_segment)?;
    if current_segment.previous_archived_segment_hash != previous_segment_hash {
        return Err(
            "archived recovered-history segment predecessor hash does not match the referenced predecessor"
                .into(),
        );
    }
    if current_segment.overlap_start_height != 0 || current_segment.overlap_end_height != 0 {
        if previous_segment.start_height > current_segment.overlap_start_height
            || previous_segment.end_height < current_segment.overlap_end_height
        {
            return Err(
                "archived recovered-history segment predecessor does not cover the declared overlap anchor"
                    .into(),
            );
        }
        if previous_segment.end_height >= current_segment.end_height {
            return Err(
                "archived recovered-history segment predecessor must end before the current range ends"
                    .into(),
            );
        }
        if previous_segment.start_height == current_segment.overlap_start_height
            && previous_segment.end_height == current_segment.overlap_end_height
            && previous_segment.segment_root_hash != current_segment.overlap_root_hash
        {
            return Err(
                "archived recovered-history segment full-overlap root does not match the predecessor segment root"
                    .into(),
            );
        }
    } else if previous_segment.end_height >= current_segment.start_height {
        return Err(
            "archived recovered-history segment predecessor must end before the current range starts"
                .into(),
        );
    }
    Ok(())
}

/// Returns the bounded archived restart-page range that mirrors one retained
/// exact-overlap recovered page ending at `end_height`.
pub fn archived_recovered_restart_page_range(
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
) -> Result<(u64, u64), String> {
    if end_height == 0 {
        return Err("archived recovered restart page range requires a non-zero end height".into());
    }
    let start_height = recovered_segment_fold_start_height(
        end_height,
        window,
        overlap,
        windows_per_segment,
        segments_per_fold,
        1,
    );
    if start_height == 0 {
        return Err(
            "archived recovered restart page range could not derive a non-zero start height".into(),
        );
    }
    Ok((start_height, end_height))
}

/// Returns the bounded archived restart-page range implied by one active profile.
pub fn archived_recovered_restart_page_range_for_profile(
    end_height: u64,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(u64, u64), String> {
    validate_archived_recovered_history_profile(profile)?;
    archived_recovered_restart_page_range(
        end_height,
        profile.restart_page_window,
        profile.restart_page_overlap,
        profile.windows_per_segment,
        profile.segments_per_fold,
    )
}

/// Verifies that an archived recovered-history segment follows the active profile geometry.
pub fn validate_archived_recovered_history_segment_against_profile(
    segment: &ArchivedRecoveredHistorySegment,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if segment.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history segment profile hash {:?} does not match the active profile hash {:?}",
            segment.archived_profile_hash,
            profile_hash
        ));
    }
    let (expected_start_height, expected_end_height) =
        archived_recovered_restart_page_range_for_profile(segment.end_height, profile)?;
    if segment.start_height != expected_start_height || segment.end_height != expected_end_height {
        return Err(format!(
            "archived recovered-history segment range {}..={} does not match the active profile range {}..={}",
            segment.start_height, segment.end_height, expected_start_height, expected_end_height
        ));
    }
    Ok(())
}

/// Verifies that an archived recovered restart-page follows the active profile geometry.
pub fn validate_archived_recovered_restart_page_against_profile(
    page: &ArchivedRecoveredRestartPage,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if page.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered restart page profile hash {:?} does not match the active profile hash {:?}",
            page.archived_profile_hash,
            profile_hash
        ));
    }
    let (expected_start_height, expected_end_height) =
        archived_recovered_restart_page_range_for_profile(page.end_height, profile)?;
    if page.start_height != expected_start_height || page.end_height != expected_end_height {
        return Err(format!(
            "archived recovered restart page range {}..={} does not match the active profile range {}..={}",
            page.start_height, page.end_height, expected_start_height, expected_end_height
        ));
    }
    Ok(())
}

/// Builds a content-addressed archived recovered restart-page payload for one
/// archived recovered-history segment.
pub fn build_archived_recovered_restart_page(
    segment: &ArchivedRecoveredHistorySegment,
    restart_headers: &[RecoveredRestartBlockHeaderEntry],
) -> Result<ArchivedRecoveredRestartPage, String> {
    if restart_headers.is_empty() {
        return Err("archived recovered restart page requires at least one restart header".into());
    }
    if restart_headers[0].header.height != segment.start_height
        || restart_headers
            .last()
            .map(|entry| entry.header.height)
            .ok_or_else(|| {
                "archived recovered restart page is missing its end height".to_string()
            })?
            != segment.end_height
    {
        return Err(
            "archived recovered restart page height coverage does not match the archived segment range"
                .into(),
        );
    }
    for pair in restart_headers.windows(2) {
        if pair[1].header.height != pair[0].header.height + 1 {
            return Err(
                "archived recovered restart page requires contiguous restart-header heights".into(),
            );
        }
    }

    Ok(ArchivedRecoveredRestartPage {
        segment_hash: canonical_archived_recovered_history_segment_hash(segment)?,
        archived_profile_hash: segment.archived_profile_hash,
        archived_profile_activation_hash: segment.archived_profile_activation_hash,
        start_height: segment.start_height,
        end_height: segment.end_height,
        restart_headers: restart_headers.to_vec(),
    })
}

/// Builds a compact archived recovered-history checkpoint for one published
/// archived segment/page tip.
pub fn build_archived_recovered_history_checkpoint(
    segment: &ArchivedRecoveredHistorySegment,
    page: &ArchivedRecoveredRestartPage,
    previous_checkpoint: Option<&ArchivedRecoveredHistoryCheckpoint>,
) -> Result<ArchivedRecoveredHistoryCheckpoint, String> {
    let expected_page = build_archived_recovered_restart_page(segment, &page.restart_headers)?;
    if &expected_page != page {
        return Err(
            "archived recovered-history checkpoint page does not match the archived segment range"
                .into(),
        );
    }
    if page.archived_profile_hash != segment.archived_profile_hash {
        return Err(
            "archived recovered-history checkpoint page profile hash does not match the archived segment profile hash"
                .into(),
        );
    }
    if page.archived_profile_activation_hash != segment.archived_profile_activation_hash {
        return Err(
            "archived recovered-history checkpoint page activation hash does not match the archived segment activation hash"
                .into(),
        );
    }

    if let Some(previous) = previous_checkpoint {
        if previous.covered_end_height >= segment.end_height {
            return Err(
                "archived recovered-history checkpoint predecessor must end before the current archived tip end height"
                    .into(),
            );
        }
    }

    Ok(ArchivedRecoveredHistoryCheckpoint {
        covered_start_height: segment.start_height,
        covered_end_height: segment.end_height,
        archived_profile_hash: segment.archived_profile_hash,
        archived_profile_activation_hash: segment.archived_profile_activation_hash,
        latest_archived_segment_hash: canonical_archived_recovered_history_segment_hash(segment)?,
        latest_archived_restart_page_hash: canonical_archived_recovered_restart_page_hash(page)?,
        previous_archived_checkpoint_hash: previous_checkpoint
            .map(canonical_archived_recovered_history_checkpoint_hash)
            .transpose()?
            .unwrap_or([0u8; 32]),
    })
}

/// Builds a compact archived recovered-history retention receipt for one
/// published archived checkpoint under one active validator-set commitment.
pub fn build_archived_recovered_history_retention_receipt(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    validator_set_commitment_hash: [u8; 32],
    retained_through_height: u64,
) -> Result<ArchivedRecoveredHistoryRetentionReceipt, String> {
    if checkpoint.covered_start_height == 0
        || checkpoint.covered_end_height == 0
        || checkpoint.covered_end_height < checkpoint.covered_start_height
    {
        return Err(
            "archived recovered-history retention receipt requires a non-zero covered checkpoint range"
                .into(),
        );
    }
    if validator_set_commitment_hash == [0u8; 32] {
        return Err(
            "archived recovered-history retention receipt requires a non-zero validator-set commitment hash"
                .into(),
        );
    }
    if retained_through_height < checkpoint.covered_end_height {
        return Err(
            "archived recovered-history retention receipt retained-through height must cover the archived checkpoint tip"
                .into(),
        );
    }

    Ok(ArchivedRecoveredHistoryRetentionReceipt {
        covered_start_height: checkpoint.covered_start_height,
        covered_end_height: checkpoint.covered_end_height,
        archived_profile_hash: checkpoint.archived_profile_hash,
        archived_profile_activation_hash: checkpoint.archived_profile_activation_hash,
        archived_checkpoint_hash: canonical_archived_recovered_history_checkpoint_hash(checkpoint)?,
        validator_set_commitment_hash,
        retained_through_height,
    })
}

/// Verifies that an archived recovered-history checkpoint follows one profile.
pub fn validate_archived_recovered_history_checkpoint_against_profile(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if checkpoint.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history checkpoint profile hash {:?} does not match the active profile hash {:?}",
            checkpoint.archived_profile_hash,
            profile_hash
        ));
    }
    Ok(())
}

/// Verifies that an archived recovered-history retention receipt follows one profile.
pub fn validate_archived_recovered_history_retention_receipt_against_profile(
    receipt: &ArchivedRecoveredHistoryRetentionReceipt,
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<(), String> {
    let profile_hash = canonical_archived_recovered_history_profile_hash(profile)?;
    if checkpoint.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history checkpoint profile hash {:?} does not match the active profile hash {:?}",
            checkpoint.archived_profile_hash,
            profile_hash
        ));
    }
    if receipt.archived_profile_hash != profile_hash {
        return Err(format!(
            "archived recovered-history retention receipt profile hash {:?} does not match the active profile hash {:?}",
            receipt.archived_profile_hash,
            profile_hash
        ));
    }
    let expected_retained_through_height =
        archived_recovered_history_retained_through_height(checkpoint, profile)?;
    if receipt.retained_through_height != expected_retained_through_height {
        return Err(format!(
            "archived recovered-history retention receipt retained-through height {} does not match the active profile retained-through height {}",
            receipt.retained_through_height, expected_retained_through_height
        ));
    }
    Ok(())
}

/// Returns the retained-through height implied by one active archive profile.
pub fn archived_recovered_history_retained_through_height(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
) -> Result<u64, String> {
    validate_archived_recovered_history_profile(profile)?;
    Ok(checkpoint
        .covered_end_height
        .saturating_add(profile.retention_horizon))
}

/// Returns the canonical hash of an assigned recovery-share delivery envelope.
pub fn canonical_assigned_recovery_share_envelope_hash(
    envelope: &AssignedRecoveryShareEnvelopeV1,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(envelope)
}

/// Returns the canonical hash of the compact recovery slot payload.
pub fn canonical_recoverable_slot_payload_hash(
    payload: &RecoverableSlotPayloadV1,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the widened recovery slot payload.
pub fn canonical_recoverable_slot_payload_v2_hash(
    payload: &RecoverableSlotPayloadV2,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the publication-oriented recovery slot payload.
pub fn canonical_recoverable_slot_payload_v3_hash(
    payload: &RecoverableSlotPayloadV3,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the close-extraction recovery slot payload.
pub fn canonical_recoverable_slot_payload_v4_hash(
    payload: &RecoverableSlotPayloadV4,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of the explicit bulletin-surface recovery slot payload.
pub fn canonical_recoverable_slot_payload_v5_hash(
    payload: &RecoverableSlotPayloadV5,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(payload)
}

/// Returns the canonical hash of an atomic canonical-order publication bundle.
pub fn canonical_order_publication_bundle_hash(
    bundle: &CanonicalOrderPublicationBundle,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(bundle)
}

/// Returns the canonical hash of an exploratory missing-recovery-share claim.
pub fn canonical_missing_recovery_share_hash(
    missing_share: &MissingRecoveryShare,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(missing_share)
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

/// Returns the canonical hash of a publication availability receipt.
pub fn canonical_publication_availability_receipt_hash(
    receipt: &PublicationAvailabilityReceipt,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(receipt)
}

/// Returns the canonical hash of a compact publication frontier.
pub fn canonical_publication_frontier_hash(
    frontier: &PublicationFrontier,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(frontier)
}

/// Returns the canonical hash of a publication-frontier contradiction witness.
pub fn canonical_publication_frontier_contradiction_hash(
    contradiction: &PublicationFrontierContradiction,
) -> Result<[u8; 32], String> {
    hash_consensus_bytes(contradiction)
}

/// Canonicalizes the witness support set carried by a recovered-publication bundle.
pub fn normalize_recovered_publication_bundle_supporting_witnesses(
    supporting_witness_manifest_hashes: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, String> {
    if supporting_witness_manifest_hashes.is_empty() {
        return Err(
            "recovered publication bundle requires at least one supporting witness manifest".into(),
        );
    }
    if supporting_witness_manifest_hashes
        .iter()
        .any(|manifest_hash| *manifest_hash == [0u8; 32])
    {
        return Err(
            "recovered publication bundle supporting witness manifests must be non-zero".into(),
        );
    }
    let mut normalized = supporting_witness_manifest_hashes.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    if normalized.len() != supporting_witness_manifest_hashes.len() {
        return Err(
            "recovered publication bundle supporting witness manifests must be distinct".into(),
        );
    }
    Ok(normalized)
}

/// Returns the canonical support-set hash for a recovered-publication bundle.
pub fn canonical_recovered_publication_bundle_support_hash(
    supporting_witness_manifest_hashes: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    let normalized = normalize_recovered_publication_bundle_supporting_witnesses(
        supporting_witness_manifest_hashes,
    )?;
    hash_consensus_bytes(&(
        b"aft::recovery::recovered_publication_bundle::support::v1",
        normalized,
    ))
}

fn xor_recovery_share_material_bytes(left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
    if left.len() != right.len() {
        return Err("systematic xor shard operands must have identical lengths".into());
    }
    Ok(left.iter().zip(right.iter()).map(|(a, b)| a ^ b).collect())
}

const GF256_REDUCTION_POLYNOMIAL: u8 = 0x1D;

fn gf256_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0u8;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        let carry = left & 0x80 != 0;
        left <<= 1;
        if carry {
            left ^= GF256_REDUCTION_POLYNOMIAL;
        }
        right >>= 1;
    }
    product
}

fn gf256_inv(value: u8) -> Result<u8, String> {
    if value == 0 {
        return Err("gf256 inverse is undefined for zero".into());
    }
    for candidate in 1..=u8::MAX {
        if gf256_mul(value, candidate) == 1 {
            return Ok(candidate);
        }
    }
    Err("gf256 inverse does not exist for the provided coefficient".into())
}

fn gf256_scale_bytes(coeff: u8, shard: &[u8]) -> Vec<u8> {
    shard.iter().map(|byte| gf256_mul(coeff, *byte)).collect()
}

fn systematic_gf256_geometry(coding: RecoveryCodingDescriptor) -> Option<(usize, usize)> {
    (coding.is_systematic_gf256_k_of_n_family() && coding.validate().is_ok()).then_some((
        usize::from(coding.recovery_threshold),
        usize::from(coding.share_count),
    ))
}

fn decode_recovery_payload_frame(framed: &[u8], scheme: &str) -> Result<Vec<u8>, String> {
    if framed.len() < 4 {
        return Err(format!(
            "{scheme} reconstruction produced an undersized payload frame"
        ));
    }
    let payload_len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
    let frame_len = 4usize
        .checked_add(payload_len)
        .ok_or_else(|| format!("{scheme} reconstruction payload length overflow"))?;
    if frame_len > framed.len() {
        return Err(format!(
            "{scheme} reconstruction produced an invalid payload length"
        ));
    }
    Ok(framed[4..frame_len].to_vec())
}

fn encode_recovery_payload_frame(
    payload_bytes: &[u8],
    data_shard_count: usize,
    scheme: &str,
) -> Result<(Vec<Vec<u8>>, usize), String> {
    if data_shard_count < 2 {
        return Err(format!("{scheme} shards require threshold at least two"));
    }
    let payload_len = u32::try_from(payload_bytes.len())
        .map_err(|_| format!("{scheme} payload exceeds 4 GiB bound"))?;
    let mut framed = Vec::with_capacity(4 + payload_bytes.len());
    framed.extend_from_slice(&payload_len.to_be_bytes());
    framed.extend_from_slice(payload_bytes);
    let shard_len = framed.len().div_ceil(data_shard_count);
    framed.resize(shard_len * data_shard_count, 0);
    Ok((
        framed
            .chunks(shard_len)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>(),
        shard_len,
    ))
}

fn encode_systematic_xor_k_of_k_plus_1_shards(
    payload_bytes: &[u8],
    recovery_threshold: u16,
) -> Result<Vec<Vec<u8>>, String> {
    let scheme = "systematic xor parity";
    let (mut shards, shard_len) =
        encode_recovery_payload_frame(payload_bytes, usize::from(recovery_threshold), scheme)?;
    let mut parity = vec![0u8; shard_len];
    for shard in &shards {
        for (slot, value) in parity.iter_mut().zip(shard.iter()) {
            *slot ^= *value;
        }
    }
    shards.push(parity);
    Ok(shards)
}

fn encode_systematic_gf256_k_of_n_shards(
    payload_bytes: &[u8],
    share_count: u16,
    recovery_threshold: u16,
) -> Result<Vec<Vec<u8>>, String> {
    let scheme = "systematic gf256";
    if recovery_threshold < 2 {
        return Err(format!("{scheme} shards require threshold at least two"));
    }
    if share_count < recovery_threshold.saturating_add(2) {
        return Err(format!(
            "{scheme} shards require at least two parity shares"
        ));
    }
    let parity_shard_count = share_count.saturating_sub(recovery_threshold);
    if parity_shard_count > u16::from(u8::MAX) {
        return Err(format!("{scheme} shards support at most 255 parity shares"));
    }
    if share_count > u16::from(u8::MAX) + 1 {
        return Err(format!("{scheme} shards support at most 256 total shares"));
    }

    let (data_shards, shard_len) =
        encode_recovery_payload_frame(payload_bytes, usize::from(recovery_threshold), scheme)?;
    let mut shards = data_shards.clone();
    for parity_share_index in usize::from(recovery_threshold)..usize::from(share_count) {
        let mut parity = vec![0u8; shard_len];
        for (data_index, shard) in data_shards.iter().enumerate() {
            let coeff = systematic_gf256_parity_coefficient(
                data_index,
                parity_share_index,
                usize::from(recovery_threshold),
                usize::from(share_count),
                scheme,
            )?;
            let scaled = gf256_scale_bytes(coeff, shard);
            for (slot, value) in parity.iter_mut().zip(scaled.iter()) {
                *slot ^= *value;
            }
        }
        shards.push(parity);
    }
    Ok(shards)
}

/// Encodes a recoverable slot payload into deterministic share bytes for the
/// provided recovery coding descriptor.
pub fn encode_coded_recovery_shards(
    coding: RecoveryCodingDescriptor,
    payload_bytes: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    coding
        .family_contract()?
        .encode_payload_shards(payload_bytes)
}

fn is_systematic_xor_parity_coding(coding: RecoveryCodingDescriptor) -> bool {
    coding.is_systematic_xor_parity_family() && coding.validate().is_ok()
}

fn is_systematic_gf256_coding(coding: RecoveryCodingDescriptor) -> bool {
    systematic_gf256_geometry(coding).is_some()
}

fn recover_systematic_xor_k_of_k_plus_1_slot_payload_bytes(
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<u8>, String> {
    let mut unique = materials
        .iter()
        .filter(|material| is_systematic_xor_parity_coding(material.coding))
        .collect::<Vec<_>>();
    unique.sort_by_key(|material| material.share_index);

    let mut deduplicated: Vec<&RecoveryShareMaterial> = Vec::new();
    for material in unique {
        if let Some(previous) = deduplicated.last() {
            if previous.share_index == material.share_index {
                if *previous != material {
                    return Err(
                        "systematic xor reconstruction encountered conflicting reveals for one share index"
                            .into(),
                    );
                }
                continue;
            }
        }
        deduplicated.push(material);
    }

    let Some(first) = deduplicated.first().copied() else {
        return Err(
            "systematic xor parity reconstruction requires at least one share reveal".into(),
        );
    };
    let share_count = usize::from(first.coding.share_count);
    let recovery_threshold = usize::from(first.coding.recovery_threshold);
    if recovery_threshold < 2 {
        return Err("systematic xor parity reconstruction requires threshold at least two".into());
    }
    if share_count != recovery_threshold + 1 {
        return Err(
            "systematic xor parity reconstruction requires share_count = recovery_threshold + 1"
                .into(),
        );
    }
    if deduplicated.len() < recovery_threshold {
        return Err(format!(
            "systematic xor parity reconstruction requires at least {recovery_threshold} distinct share reveals"
        ));
    }
    let shard_len = first.material_bytes.len();
    let parity_index = recovery_threshold;
    let mut shard_by_index = vec![None; share_count];
    for material in &deduplicated {
        if usize::from(material.coding.share_count) != share_count
            || usize::from(material.coding.recovery_threshold) != recovery_threshold
        {
            return Err(
                "systematic xor parity reconstruction requires consistent share geometry".into(),
            );
        }
        if material.height != first.height
            || material.block_commitment_hash != first.block_commitment_hash
        {
            return Err(
                "systematic xor parity reconstruction requires shares from the same slot commitment"
                    .into(),
            );
        }
        if !is_systematic_xor_parity_coding(material.coding) {
            return Err(
                "systematic xor parity reconstruction encountered a non-parity share kind".into(),
            );
        }
        if material.material_bytes.len() != shard_len {
            return Err(
                "systematic xor parity reconstruction requires equal-length shard materials".into(),
            );
        }
        let share_index = usize::from(material.share_index);
        if share_index >= share_count {
            return Err(
                "systematic xor parity reconstruction encountered an out-of-range share index"
                    .into(),
            );
        }
        shard_by_index[share_index] = Some(material.material_bytes.clone());
    }

    let mut data_shards = vec![Vec::new(); recovery_threshold];
    let missing_indices = shard_by_index
        .iter()
        .enumerate()
        .filter_map(|(index, shard)| shard.is_none().then_some(index))
        .collect::<Vec<_>>();
    if missing_indices.len() > 1 {
        return Err(
            "systematic xor parity reconstruction cannot recover more than one missing shard"
                .into(),
        );
    }
    if missing_indices.is_empty() || missing_indices[0] == parity_index {
        for (index, shard) in shard_by_index.iter().take(recovery_threshold).enumerate() {
            data_shards[index] = shard
                .clone()
                .ok_or_else(|| {
                    "systematic xor parity reconstruction requires all data shards when parity is missing"
                        .to_string()
                })?;
        }
    } else {
        let missing_data_index = missing_indices[0];
        let parity = shard_by_index[parity_index].as_ref().ok_or_else(|| {
            "systematic xor parity reconstruction requires the parity shard when one data shard is missing"
                .to_string()
        })?;
        let mut reconstructed = parity.clone();
        for (index, shard) in shard_by_index.iter().take(recovery_threshold).enumerate() {
            if index == missing_data_index {
                continue;
            }
            let shard = shard.as_ref().ok_or_else(|| {
                "systematic xor parity reconstruction requires all other data shards".to_string()
            })?;
            reconstructed = xor_recovery_share_material_bytes(&reconstructed, shard)?;
            data_shards[index] = shard.clone();
        }
        data_shards[missing_data_index] = reconstructed;
    }

    let mut framed = Vec::with_capacity(recovery_threshold * shard_len);
    for shard in data_shards {
        framed.extend_from_slice(&shard);
    }
    decode_recovery_payload_frame(&framed, "systematic xor parity")
}

fn systematic_gf256_parity_coefficient(
    data_index: usize,
    parity_share_index: usize,
    recovery_threshold: usize,
    share_count: usize,
    scheme: &str,
) -> Result<u8, String> {
    if data_index >= recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction encountered an out-of-range data shard index"
        ));
    }
    if parity_share_index < recovery_threshold || parity_share_index >= share_count {
        return Err(format!(
            "{scheme} reconstruction encountered an out-of-range parity share index"
        ));
    }

    let data_point = u8::try_from(data_index)
        .map_err(|_| format!("{scheme} reconstruction data point exceeds u8"))?;
    let parity_point = u8::try_from(parity_share_index)
        .map_err(|_| format!("{scheme} reconstruction parity point exceeds u8"))?;
    let denominator = data_point ^ parity_point;
    if denominator == 0 {
        return Err(format!(
            "{scheme} reconstruction parity coefficient denominator vanished"
        ));
    }
    gf256_inv(denominator)
}

fn systematic_gf256_row(
    share_index: usize,
    recovery_threshold: usize,
    share_count: usize,
    scheme: &str,
) -> Result<Vec<u8>, String> {
    if share_count <= recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction requires at least one parity share"
        ));
    }
    if share_index >= share_count {
        return Err(format!(
            "{scheme} reconstruction encountered an out-of-range share index"
        ));
    }
    if share_index < recovery_threshold {
        let mut row = vec![0u8; recovery_threshold];
        row[share_index] = 1;
        return Ok(row);
    }

    (0..recovery_threshold)
        .map(|data_index| {
            systematic_gf256_parity_coefficient(
                data_index,
                share_index,
                recovery_threshold,
                share_count,
                scheme,
            )
        })
        .collect()
}

fn invert_gf256_matrix(matrix: &[Vec<u8>], scheme: &str) -> Result<Vec<Vec<u8>>, String> {
    let dimension = matrix.len();
    if dimension == 0 {
        return Err(format!(
            "{scheme} reconstruction requires a non-empty matrix"
        ));
    }
    if matrix.iter().any(|row| row.len() != dimension) {
        return Err(format!(
            "{scheme} reconstruction requires a square coefficient matrix"
        ));
    }

    let mut left = matrix.to_vec();
    let mut right = vec![vec![0u8; dimension]; dimension];
    for (index, row) in right.iter_mut().enumerate() {
        row[index] = 1;
    }

    for pivot_index in 0..dimension {
        let pivot_row = (pivot_index..dimension)
            .find(|row_index| left[*row_index][pivot_index] != 0)
            .ok_or_else(|| {
                format!("{scheme} reconstruction requires linearly independent share rows")
            })?;
        if pivot_row != pivot_index {
            left.swap(pivot_index, pivot_row);
            right.swap(pivot_index, pivot_row);
        }

        let inverse_pivot = gf256_inv(left[pivot_index][pivot_index])?;
        for column in 0..dimension {
            left[pivot_index][column] = gf256_mul(left[pivot_index][column], inverse_pivot);
            right[pivot_index][column] = gf256_mul(right[pivot_index][column], inverse_pivot);
        }

        for row_index in 0..dimension {
            if row_index == pivot_index {
                continue;
            }
            let factor = left[row_index][pivot_index];
            if factor == 0 {
                continue;
            }
            for column in 0..dimension {
                left[row_index][column] ^= gf256_mul(factor, left[pivot_index][column]);
                right[row_index][column] ^= gf256_mul(factor, right[pivot_index][column]);
            }
        }
    }

    Ok(right)
}

fn recover_systematic_gf256_k_of_n_slot_payload_bytes(
    materials: &[RecoveryShareMaterial],
) -> Result<Vec<u8>, String> {
    let mut unique = materials
        .iter()
        .filter(|material| is_systematic_gf256_coding(material.coding))
        .collect::<Vec<_>>();
    unique.sort_by_key(|material| material.share_index);

    let mut deduplicated: Vec<&RecoveryShareMaterial> = Vec::new();
    for material in unique {
        if let Some(previous) = deduplicated.last() {
            if previous.share_index == material.share_index {
                if *previous != material {
                    return Err(
                        "systematic gf256 reconstruction encountered conflicting reveals for one share index"
                            .into(),
                    );
                }
                continue;
            }
        }
        deduplicated.push(material);
    }

    let Some(first) = deduplicated.first().copied() else {
        return Err("systematic gf256 reconstruction requires at least one share reveal".into());
    };
    let (recovery_threshold, share_count) =
        systematic_gf256_geometry(first.coding).ok_or_else(|| {
            "systematic gf256 reconstruction requires a supported gf256 materialization kind"
                .to_string()
        })?;
    let scheme = first.coding.label();
    if usize::from(first.coding.share_count) != share_count {
        return Err(format!(
            "{scheme} reconstruction requires share_count = {share_count}"
        ));
    }
    if usize::from(first.coding.recovery_threshold) != recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction requires recovery_threshold = {recovery_threshold}"
        ));
    }
    if deduplicated.len() < recovery_threshold {
        return Err(format!(
            "{scheme} reconstruction requires at least {recovery_threshold} distinct share reveals"
        ));
    }

    let shard_len = first.material_bytes.len();
    for material in &deduplicated {
        if material.coding.share_count != first.coding.share_count
            || material.coding.recovery_threshold != first.coding.recovery_threshold
        {
            return Err(format!(
                "{scheme} reconstruction requires consistent share geometry"
            ));
        }
        if material.height != first.height
            || material.block_commitment_hash != first.block_commitment_hash
        {
            return Err(format!(
                "{scheme} reconstruction requires shares from the same slot commitment"
            ));
        }
        if material.coding != first.coding {
            return Err(format!(
                "{scheme} reconstruction requires a uniform gf256 materialization kind"
            ));
        }
        if material.material_bytes.len() != shard_len {
            return Err(format!(
                "{scheme} reconstruction requires equal-length shard materials"
            ));
        }
        if usize::from(material.share_index) >= share_count {
            return Err(format!(
                "{scheme} reconstruction encountered an out-of-range share index"
            ));
        }
    }

    let selected = deduplicated
        .iter()
        .take(recovery_threshold)
        .copied()
        .collect::<Vec<_>>();
    let coefficient_rows = selected
        .iter()
        .map(|material| {
            systematic_gf256_row(
                usize::from(material.share_index),
                recovery_threshold,
                share_count,
                &scheme,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inverse = invert_gf256_matrix(&coefficient_rows, &scheme)?;
    let selected_shards = selected
        .iter()
        .map(|material| material.material_bytes.as_slice())
        .collect::<Vec<_>>();

    let mut data_shards = Vec::with_capacity(recovery_threshold);
    for row in &inverse {
        let mut shard = vec![0u8; shard_len];
        for (coeff, selected_shard) in row.iter().zip(selected_shards.iter()) {
            if *coeff == 0 {
                continue;
            }
            let scaled = gf256_scale_bytes(*coeff, selected_shard);
            for (byte, scaled_byte) in shard.iter_mut().zip(scaled.iter()) {
                *byte ^= *scaled_byte;
            }
        }
        data_shards.push(shard);
    }

    let mut framed = Vec::with_capacity(recovery_threshold * shard_len);
    for shard in data_shards {
        framed.extend_from_slice(&shard);
    }
    decode_recovery_payload_frame(&framed, &scheme)
}

/// Reconstructs a `RecoverableSlotPayloadV3` from public share reveals.
pub fn recover_recoverable_slot_payload_v3_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<RecoverableSlotPayloadV3, String> {
    let Some(first) = materials.first() else {
        return Err(
            "recoverable slot payload reconstruction requires at least one share reveal".into(),
        );
    };
    let payload_bytes = first
        .coding
        .family_contract()?
        .recover_payload_bytes_from_materials(materials)?;
    codec::from_bytes_canonical(&payload_bytes).map_err(|error| error.to_string())
}

/// Reconstructs and verifies a canonical-order publication bundle from public share reveals.
pub fn recover_canonical_order_publication_bundle_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<(RecoverableSlotPayloadV3, CanonicalOrderPublicationBundle), String> {
    let payload = recover_recoverable_slot_payload_v3_from_share_materials(materials)?;
    let bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&payload.canonical_order_publication_bundle_bytes)
            .map_err(|error| error.to_string())?;
    verify_canonical_order_publication_bundle(&bundle)?;
    Ok((payload, bundle))
}

/// Lifts a recovered `RecoverableSlotPayloadV3` into the explicit positive
/// close-extraction `RecoverableSlotPayloadV4` surface.
pub fn lift_recoverable_slot_payload_v3_to_v4(
    payload: &RecoverableSlotPayloadV3,
) -> Result<
    (
        RecoverableSlotPayloadV4,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
    ),
    String,
> {
    let bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&payload.canonical_order_publication_bundle_bytes)
            .map_err(|error| error.to_string())?;
    let bulletin_close = verify_canonical_order_publication_bundle(&bundle)?;
    let payload_v4 = RecoverableSlotPayloadV4 {
        height: payload.height,
        view: payload.view,
        producer_account_id: payload.producer_account_id,
        block_commitment_hash: payload.block_commitment_hash,
        parent_block_hash: payload.parent_block_hash,
        canonical_order_certificate: payload.canonical_order_certificate.clone(),
        ordered_transaction_bytes: payload.ordered_transaction_bytes.clone(),
        canonical_order_publication_bundle_bytes: payload
            .canonical_order_publication_bundle_bytes
            .clone(),
        canonical_bulletin_close_bytes: codec::to_bytes_canonical(&bulletin_close)
            .map_err(|error| error.to_string())?,
    };
    Ok((payload_v4, bundle, bulletin_close))
}

/// Lifts a recovered `RecoverableSlotPayloadV4` into the explicit extractable
/// bulletin-surface `RecoverableSlotPayloadV5`.
pub fn lift_recoverable_slot_payload_v4_to_v5(
    payload: &RecoverableSlotPayloadV4,
) -> Result<
    (
        RecoverableSlotPayloadV5,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
        Vec<BulletinSurfaceEntry>,
    ),
    String,
> {
    let bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&payload.canonical_order_publication_bundle_bytes)
            .map_err(|error| error.to_string())?;
    let bundle_close = verify_canonical_order_publication_bundle(&bundle)?;
    let bulletin_close: CanonicalBulletinClose =
        codec::from_bytes_canonical(&payload.canonical_bulletin_close_bytes)
            .map_err(|error| error.to_string())?;
    if bulletin_close != bundle_close {
        return Err(
            "recoverable slot payload v5 requires bulletin-close bytes that match the recovered publication bundle"
                .into(),
        );
    }
    let bulletin_surface_entries = extract_canonical_bulletin_surface(
        &bulletin_close,
        &bundle.bulletin_commitment,
        &bundle.bulletin_availability_certificate,
        &bundle.bulletin_entries,
    )?;
    let payload_v5 = RecoverableSlotPayloadV5 {
        height: payload.height,
        view: payload.view,
        producer_account_id: payload.producer_account_id.clone(),
        block_commitment_hash: payload.block_commitment_hash,
        parent_block_hash: payload.parent_block_hash,
        canonical_order_certificate: payload.canonical_order_certificate.clone(),
        ordered_transaction_bytes: payload.ordered_transaction_bytes.clone(),
        canonical_order_publication_bundle_bytes: payload
            .canonical_order_publication_bundle_bytes
            .clone(),
        canonical_bulletin_close_bytes: payload.canonical_bulletin_close_bytes.clone(),
        canonical_bulletin_availability_certificate_bytes: codec::to_bytes_canonical(
            &bundle.bulletin_availability_certificate,
        )
        .map_err(|error| error.to_string())?,
        bulletin_surface_entries: bulletin_surface_entries.clone(),
    };
    Ok((payload_v5, bundle, bulletin_close, bulletin_surface_entries))
}

/// Reconstructs the explicit positive canonical-order close surface from
/// public share reveals.
pub fn recover_canonical_order_artifact_surface_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<
    (
        RecoverableSlotPayloadV4,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
    ),
    String,
> {
    let (payload_v3, _) =
        recover_canonical_order_publication_bundle_from_share_materials(materials)?;
    lift_recoverable_slot_payload_v3_to_v4(&payload_v3)
}

/// Reconstructs the full extractable canonical-order bulletin surface from
/// public share reveals.
pub fn recover_full_canonical_order_surface_from_share_materials(
    materials: &[RecoveryShareMaterial],
) -> Result<
    (
        RecoverableSlotPayloadV5,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
        Vec<BulletinSurfaceEntry>,
    ),
    String,
> {
    let (payload_v4, _, _) =
        recover_canonical_order_artifact_surface_from_share_materials(materials)?;
    lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
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

/// Builds the ordinary AFT historical-continuation anchor when all three bootstrap hashes are
/// present, or `None` when all three are absent.
pub fn aft_historical_continuation_anchor(
    checkpoint_hash: [u8; 32],
    profile_activation_hash: [u8; 32],
    retention_receipt_hash: [u8; 32],
) -> Result<Option<AftHistoricalContinuationAnchor>, String> {
    if checkpoint_hash == [0u8; 32]
        && profile_activation_hash == [0u8; 32]
        && retention_receipt_hash == [0u8; 32]
    {
        Ok(None)
    } else if checkpoint_hash == [0u8; 32]
        || profile_activation_hash == [0u8; 32]
        || retention_receipt_hash == [0u8; 32]
    {
        Err(
            "ordinary AFT historical continuation must carry either all bootstrap hashes or none"
                .into(),
        )
    } else {
        Ok(Some(AftHistoricalContinuationAnchor {
            checkpoint_hash,
            profile_activation_hash,
            retention_receipt_hash,
        }))
    }
}

/// Returns the archived recovered-history anchor named by a canonical collapse object when one is
/// present.
pub fn canonical_collapse_archived_recovered_history_anchor(
    collapse: &CanonicalCollapseObject,
) -> Result<Option<([u8; 32], [u8; 32], [u8; 32])>, String> {
    let checkpoint_hash = collapse.archived_recovered_history_checkpoint_hash;
    let activation_hash = collapse.archived_recovered_history_profile_activation_hash;
    let receipt_hash = collapse.archived_recovered_history_retention_receipt_hash;
    if checkpoint_hash == [0u8; 32] && activation_hash == [0u8; 32] && receipt_hash == [0u8; 32] {
        Ok(None)
    } else if checkpoint_hash == [0u8; 32]
        || activation_hash == [0u8; 32]
        || receipt_hash == [0u8; 32]
    {
        Err(format!(
            "canonical collapse object at height {} must carry either all archived recovered-history anchor hashes or none",
            collapse.height
        ))
    } else {
        Ok(Some((checkpoint_hash, activation_hash, receipt_hash)))
    }
}

/// Returns the ordinary AFT historical-continuation anchor named by a canonical collapse object
/// when one is present.
pub fn canonical_collapse_historical_continuation_anchor(
    collapse: &CanonicalCollapseObject,
) -> Result<Option<AftHistoricalContinuationAnchor>, String> {
    aft_historical_continuation_anchor(
        collapse.archived_recovered_history_checkpoint_hash,
        collapse.archived_recovered_history_profile_activation_hash,
        collapse.archived_recovered_history_retention_receipt_hash,
    )
    .map_err(|error| {
        format!(
            "canonical collapse object at height {} {error}",
            collapse.height
        )
    })
}

/// Attaches or clears the archived recovered-history anchor carried by ordinary canonical history.
pub fn set_canonical_collapse_archived_recovered_history_anchor(
    collapse: &mut CanonicalCollapseObject,
    checkpoint_hash: [u8; 32],
    profile_activation_hash: [u8; 32],
    retention_receipt_hash: [u8; 32],
) -> Result<(), String> {
    let all_zero = checkpoint_hash == [0u8; 32]
        && profile_activation_hash == [0u8; 32]
        && retention_receipt_hash == [0u8; 32];
    let all_non_zero = checkpoint_hash != [0u8; 32]
        && profile_activation_hash != [0u8; 32]
        && retention_receipt_hash != [0u8; 32];
    if !all_zero && !all_non_zero {
        return Err(format!(
            "canonical collapse object at height {} must carry either all archived recovered-history anchor hashes or none",
            collapse.height
        ));
    }
    collapse.archived_recovered_history_checkpoint_hash = checkpoint_hash;
    collapse.archived_recovered_history_profile_activation_hash = profile_activation_hash;
    collapse.archived_recovered_history_retention_receipt_hash = retention_receipt_hash;
    Ok(())
}

/// Returns the ordinary AFT historical-continuation anchor named by a replay-prefix entry when
/// one is present.
pub fn canonical_replay_prefix_historical_continuation_anchor(
    entry: &CanonicalReplayPrefixEntry,
) -> Result<Option<AftHistoricalContinuationAnchor>, String> {
    aft_historical_continuation_anchor(
        entry
            .archived_recovered_history_checkpoint_hash
            .unwrap_or([0u8; 32]),
        entry
            .archived_recovered_history_profile_activation_hash
            .unwrap_or([0u8; 32]),
        entry
            .archived_recovered_history_retention_receipt_hash
            .unwrap_or([0u8; 32]),
    )
    .map_err(|error| {
        format!(
            "canonical replay prefix entry at height {} {error}",
            entry.height
        )
    })
}

/// Compares canonical collapse objects while ignoring only the archival-history anchor fields.
pub fn canonical_collapse_eq_ignoring_archived_recovered_history_anchor(
    left: &CanonicalCollapseObject,
    right: &CanonicalCollapseObject,
) -> bool {
    left.height == right.height
        && left.previous_canonical_collapse_commitment_hash
            == right.previous_canonical_collapse_commitment_hash
        && left.continuity_accumulator_hash == right.continuity_accumulator_hash
        && left.continuity_recursive_proof == right.continuity_recursive_proof
        && left.ordering == right.ordering
        && left.sealing == right.sealing
        && left.transactions_root_hash == right.transactions_root_hash
        && left.resulting_state_root_hash == right.resulting_state_root_hash
}

/// Builds the compact durable prefix entry exposed to replay / checkpoint consumers.
pub fn canonical_replay_prefix_entry(
    collapse: &CanonicalCollapseObject,
    canonical_block_commitment_hash: Option<[u8; 32]>,
    parent_block_commitment_hash: Option<[u8; 32]>,
    ordering_resolution_hash: [u8; 32],
    publication_frontier_hash: Option<[u8; 32]>,
    extracted_bulletin_surface_present: bool,
) -> Result<CanonicalReplayPrefixEntry, String> {
    let archived_recovered_history_anchor =
        canonical_collapse_archived_recovered_history_anchor(collapse)?;
    Ok(CanonicalReplayPrefixEntry {
        height: collapse.height,
        resulting_state_root_hash: collapse.resulting_state_root_hash,
        canonical_block_commitment_hash,
        parent_block_commitment_hash,
        canonical_collapse_commitment_hash: canonical_collapse_commitment_hash_from_object(
            collapse,
        )?,
        previous_canonical_collapse_commitment_hash: collapse
            .previous_canonical_collapse_commitment_hash,
        ordering_kind: collapse.ordering.kind,
        ordering_resolution_hash,
        publication_frontier_hash,
        extracted_bulletin_surface_present,
        archived_recovered_history_checkpoint_hash: archived_recovered_history_anchor
            .map(|(checkpoint_hash, _, _)| checkpoint_hash),
        archived_recovered_history_profile_activation_hash: archived_recovered_history_anchor
            .map(|(_, activation_hash, _)| activation_hash),
        archived_recovered_history_retention_receipt_hash: archived_recovered_history_anchor
            .map(|(_, _, receipt_hash)| receipt_hash),
    })
}

/// Builds the compact recovered header entry exposed to bounded ancestry consumers.
pub fn recovered_canonical_header_entry(
    collapse: &CanonicalCollapseObject,
    full_surface: &RecoverableSlotPayloadV5,
) -> Result<RecoveredCanonicalHeaderEntry, String> {
    if full_surface.height != collapse.height {
        return Err(format!(
            "recovered canonical header entry height mismatch: collapse {}, full surface {}",
            collapse.height, full_surface.height
        ));
    }
    if collapse.transactions_root_hash
        != full_surface
            .canonical_order_certificate
            .ordered_transactions_root_hash
    {
        return Err(format!(
            "recovered canonical header entry transactions-root mismatch at height {}",
            collapse.height
        ));
    }
    if collapse.resulting_state_root_hash
        != full_surface
            .canonical_order_certificate
            .resulting_state_root_hash
    {
        return Err(format!(
            "recovered canonical header entry state-root mismatch at height {}",
            collapse.height
        ));
    }

    Ok(RecoveredCanonicalHeaderEntry {
        height: collapse.height,
        view: full_surface.view,
        canonical_block_commitment_hash: full_surface.block_commitment_hash,
        parent_block_commitment_hash: full_surface.parent_block_hash,
        transactions_root_hash: full_surface
            .canonical_order_certificate
            .ordered_transactions_root_hash,
        resulting_state_root_hash: full_surface
            .canonical_order_certificate
            .resulting_state_root_hash,
        previous_canonical_collapse_commitment_hash: collapse
            .previous_canonical_collapse_commitment_hash,
    })
}

/// Builds the compact recovered certified-header entry exposed to bounded restart consumers.
pub fn recovered_certified_header_entry(
    header: &RecoveredCanonicalHeaderEntry,
    previous: Option<&RecoveredCanonicalHeaderEntry>,
) -> Result<RecoveredCertifiedHeaderEntry, String> {
    if header.height == 0 {
        return Err("recovered certified header entry requires a non-zero height".into());
    }

    let (certified_parent_quorum_certificate, certified_parent_resulting_state_root_hash) =
        if header.height == 1 {
            (QuorumCertificate::default(), [0u8; 32])
        } else {
            let previous = previous.ok_or_else(|| {
                format!(
                    "recovered certified header entry at height {} requires a predecessor header",
                    header.height
                )
            })?;
            if previous.height + 1 != header.height {
                return Err(format!(
                    "recovered certified header entry height mismatch: previous {}, current {}",
                    previous.height, header.height
                ));
            }
            if previous.canonical_block_commitment_hash != header.parent_block_commitment_hash {
                return Err(format!(
                    "recovered certified header entry parent-block hash mismatch at height {}",
                    header.height
                ));
            }
            (
                previous.synthetic_quorum_certificate(),
                previous.resulting_state_root_hash,
            )
        };

    Ok(RecoveredCertifiedHeaderEntry {
        header: header.clone(),
        certified_parent_quorum_certificate,
        certified_parent_resulting_state_root_hash,
    })
}

/// Builds a bounded recovered certified-header prefix from consecutive recovered headers.
pub fn recovered_certified_header_prefix(
    previous: Option<&RecoveredCanonicalHeaderEntry>,
    headers: &[RecoveredCanonicalHeaderEntry],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>, String> {
    let mut certified_entries = Vec::with_capacity(headers.len());
    let mut previous_header = previous.cloned();

    for header in headers {
        let certified = recovered_certified_header_entry(header, previous_header.as_ref())?;
        previous_header = Some(header.clone());
        certified_entries.push(certified);
    }

    Ok(certified_entries)
}

fn stitch_recovered_windows<T, F>(
    windows: &[&[T]],
    height_of: F,
    label: &str,
) -> Result<Vec<T>, String>
where
    T: Clone + PartialEq,
    F: Fn(&T) -> u64,
{
    let mut merged = Vec::new();

    for (window_index, window) in windows.iter().enumerate() {
        if window.is_empty() {
            return Err(format!(
                "{label} window {} must not be empty",
                window_index + 1
            ));
        }

        for pair in window.windows(2) {
            let previous_height = height_of(&pair[0]);
            let next_height = height_of(&pair[1]);
            if next_height != previous_height + 1 {
                return Err(format!(
                    "{label} window {} must be consecutive: saw heights {} then {}",
                    window_index + 1,
                    previous_height,
                    next_height
                ));
            }
        }

        if merged.is_empty() {
            merged.extend(window.iter().cloned());
            continue;
        }

        let merged_start = height_of(&merged[0]);
        let merged_end = height_of(merged.last().expect("merged window tail"));
        let next_start = height_of(&window[0]);
        if next_start > merged_end {
            return Err(format!(
                "{label} window {} must overlap the previous window: previous ends at {}, next starts at {}",
                window_index + 1,
                merged_end,
                next_start
            ));
        }

        for entry in *window {
            let height = height_of(entry);
            if height < merged_start {
                return Err(format!(
                    "{label} window {} starts before the merged prefix at height {}",
                    window_index + 1,
                    merged_start
                ));
            }

            let offset = usize::try_from(height - merged_start)
                .map_err(|_| format!("{label} height offset overflow at {height}"))?;
            if offset < merged.len() {
                if merged[offset] != *entry {
                    return Err(format!(
                        "{label} overlap mismatch at height {} between windows {} and {}",
                        height,
                        window_index,
                        window_index + 1
                    ));
                }
            } else {
                let expected_next_height =
                    height_of(merged.last().expect("merged window tail")) + 1;
                if height != expected_next_height {
                    return Err(format!(
                        "{label} window {} does not continue consecutively after height {}",
                        window_index + 1,
                        height_of(merged.last().expect("merged window tail"))
                    ));
                }
                merged.push(entry.clone());
            }
        }
    }

    Ok(merged)
}

/// Stitches overlapping bounded recovered canonical-header windows into one longer prefix.
pub fn stitch_recovered_canonical_header_windows(
    windows: &[&[RecoveredCanonicalHeaderEntry]],
) -> Result<Vec<RecoveredCanonicalHeaderEntry>, String> {
    stitch_recovered_windows(windows, |entry| entry.height, "recovered canonical header")
}

/// Stitches overlapping bounded recovered canonical-header segments into one
/// longer prefix.
pub fn stitch_recovered_canonical_header_segments(
    segments: &[&[RecoveredCanonicalHeaderEntry]],
) -> Result<Vec<RecoveredCanonicalHeaderEntry>, String> {
    stitch_recovered_canonical_header_windows(segments)
}

/// Stitches overlapping bounded recovered certified-header windows into one longer prefix.
pub fn stitch_recovered_certified_header_windows(
    windows: &[&[RecoveredCertifiedHeaderEntry]],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>, String> {
    stitch_recovered_windows(
        windows,
        |entry| entry.header.height,
        "recovered certified header",
    )
}

/// Stitches overlapping bounded recovered certified-header segments into one
/// longer prefix.
pub fn stitch_recovered_certified_header_segments(
    segments: &[&[RecoveredCertifiedHeaderEntry]],
) -> Result<Vec<RecoveredCertifiedHeaderEntry>, String> {
    stitch_recovered_certified_header_windows(segments)
}

/// Builds the restart-only synthetic block-header cache entry exposed to bounded
/// QC/header restart consumers.
pub fn recovered_restart_block_header_entry(
    full_surface: &RecoverableSlotPayloadV5,
    certified_header: &RecoveredCertifiedHeaderEntry,
) -> Result<RecoveredRestartBlockHeaderEntry, String> {
    if full_surface.height != certified_header.header.height {
        return Err(format!(
            "recovered restart block header height mismatch: payload {}, certified {}",
            full_surface.height, certified_header.header.height
        ));
    }
    if full_surface.view != certified_header.header.view {
        return Err(format!(
            "recovered restart block header view mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface.block_commitment_hash != certified_header.header.canonical_block_commitment_hash
    {
        return Err(format!(
            "recovered restart block header block-commitment mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface.parent_block_hash != certified_header.header.parent_block_commitment_hash {
        return Err(format!(
            "recovered restart block header parent-block mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface.canonical_order_certificate.height != certified_header.header.height {
        return Err(format!(
            "recovered restart block header order-certificate height mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface
        .canonical_order_certificate
        .ordered_transactions_root_hash
        != certified_header.header.transactions_root_hash
    {
        return Err(format!(
            "recovered restart block header transactions-root mismatch at height {}",
            full_surface.height
        ));
    }
    if full_surface
        .canonical_order_certificate
        .resulting_state_root_hash
        != certified_header.header.resulting_state_root_hash
    {
        return Err(format!(
            "recovered restart block header state-root mismatch at height {}",
            full_surface.height
        ));
    }

    let parent_state_root_hash = if certified_header.header.height <= 1 {
        [0u8; 32]
    } else {
        certified_header.certified_parent_resulting_state_root_hash
    };
    let cutoff_timestamp_ms = full_surface
        .canonical_order_certificate
        .bulletin_commitment
        .cutoff_timestamp_ms;

    Ok(RecoveredRestartBlockHeaderEntry {
        certified_header: certified_header.clone(),
        header: BlockHeader {
            height: certified_header.header.height,
            view: certified_header.header.view,
            parent_hash: certified_header.header.parent_block_commitment_hash,
            parent_state_root: StateRoot(parent_state_root_hash.to_vec()),
            state_root: StateRoot(certified_header.header.resulting_state_root_hash.to_vec()),
            transactions_root: certified_header.header.transactions_root_hash.to_vec(),
            timestamp: timestamp_millis_to_legacy_seconds(cutoff_timestamp_ms),
            timestamp_ms: cutoff_timestamp_ms,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: full_surface.producer_account_id.clone(),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0u8; 32],
            producer_pubkey: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: Some(full_surface.canonical_order_certificate.clone()),
            timeout_certificate: None,
            parent_qc: certified_header.certified_parent_quorum_certificate.clone(),
            previous_canonical_collapse_commitment_hash: certified_header
                .header
                .previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: Vec::new(),
        },
    })
}

/// Stitches overlapping bounded recovered restart block-header windows into one longer prefix.
pub fn stitch_recovered_restart_block_header_windows(
    windows: &[&[RecoveredRestartBlockHeaderEntry]],
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, String> {
    stitch_recovered_windows(
        windows,
        |entry| entry.header.height,
        "recovered restart block header",
    )
}

/// Stitches overlapping bounded recovered restart block-header segments into
/// one longer prefix.
pub fn stitch_recovered_restart_block_header_segments(
    segments: &[&[RecoveredRestartBlockHeaderEntry]],
) -> Result<Vec<RecoveredRestartBlockHeaderEntry>, String> {
    stitch_recovered_restart_block_header_windows(segments)
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
    Ok(hash_consensus_bytes(&(
        b"aft::canonical-collapse::succinct-mock-proof::v1",
        public_inputs,
    ))?
    .to_vec())
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
        CanonicalCollapseContinuityProofSystem::HashPcdV1 => Ok(hash_consensus_bytes(&(
            b"aft::canonical-collapse::pcd-proof::v1",
            proof_system as u8,
            statement_hash,
            previous_recursive_proof_hash,
        ))?
        .to_vec()),
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
    let previous_commitment_hash =
        canonical_collapse_commitment_hash(&canonical_collapse_commitment(previous))?;
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

    let predecessor =
        canonical_collapse_extension_predecessor_commitment(header_height, certificate)?;
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
        let expected =
            expected_previous_canonical_collapse_commitment_hash(header.height, Some(previous))?;
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
    // This root intentionally binds only the committed bulletin / order / post-state
    // surface. Exploratory witness-coded recovery layers must refine it with their
    // own witness and coding inputs rather than treating it as a coded-share root.
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

/// Builds the compact publication availability receipt bound to a canonical order certificate.
pub fn build_publication_availability_receipt(
    certificate: &CanonicalOrderCertificate,
) -> Result<PublicationAvailabilityReceipt, String> {
    Ok(PublicationAvailabilityReceipt {
        height: certificate.height,
        bulletin_commitment_hash: canonical_bulletin_commitment_hash(
            &certificate.bulletin_commitment,
        )?,
        ordered_transactions_root_hash: certificate.ordered_transactions_root_hash,
        resulting_state_root_hash: certificate.resulting_state_root_hash,
        receipt_root: certificate
            .bulletin_availability_certificate
            .recoverability_root,
    })
}

/// Verifies a compact publication availability receipt against a canonical order certificate.
pub fn verify_publication_availability_receipt(
    receipt: &PublicationAvailabilityReceipt,
    certificate: &CanonicalOrderCertificate,
) -> Result<(), String> {
    if receipt.height != certificate.height {
        return Err("publication availability receipt height does not match the canonical order certificate".into());
    }
    let expected_commitment_hash =
        canonical_bulletin_commitment_hash(&certificate.bulletin_commitment)?;
    if receipt.bulletin_commitment_hash != expected_commitment_hash {
        return Err(
            "publication availability receipt does not match the bulletin commitment hash".into(),
        );
    }
    if receipt.ordered_transactions_root_hash != certificate.ordered_transactions_root_hash {
        return Err(
            "publication availability receipt does not match the ordered transactions root".into(),
        );
    }
    if receipt.resulting_state_root_hash != certificate.resulting_state_root_hash {
        return Err(
            "publication availability receipt does not match the resulting state root".into(),
        );
    }
    if receipt.receipt_root
        != certificate
            .bulletin_availability_certificate
            .recoverability_root
    {
        return Err(
            "publication availability receipt does not match the recoverability root".into(),
        );
    }
    Ok(())
}

/// Verifies a bulletin availability certificate against its public binding inputs.
pub fn verify_bulletin_availability_binding(
    certificate: &BulletinAvailabilityCertificate,
    bulletin_commitment: &BulletinCommitment,
) -> Result<(), String> {
    if certificate.height != bulletin_commitment.height {
        return Err(
            "bulletin availability certificate height does not match bulletin commitment".into(),
        );
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
        return Err(
            "canonical bulletin close cutoff does not match the bulletin commitment".into(),
        );
    }
    if close.entry_count != bulletin_commitment.entry_count {
        return Err(
            "canonical bulletin close entry count does not match the bulletin commitment".into(),
        );
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

/// Builds the compact publication frontier carried on the live consensus path.
pub fn build_publication_frontier(
    header: &BlockHeader,
    previous: Option<&PublicationFrontier>,
) -> Result<PublicationFrontier, String> {
    let certificate = header
        .canonical_order_certificate
        .as_ref()
        .ok_or_else(|| "publication frontier requires a canonical-order certificate".to_string())?;
    let receipt = build_publication_availability_receipt(certificate)?;
    let parent_frontier_hash = previous
        .map(canonical_publication_frontier_hash)
        .transpose()?
        .unwrap_or([0u8; 32]);
    Ok(PublicationFrontier {
        height: header.height,
        view: header.view,
        counter: header.height,
        parent_frontier_hash,
        bulletin_commitment_hash: receipt.bulletin_commitment_hash,
        ordered_transactions_root_hash: receipt.ordered_transactions_root_hash,
        availability_receipt_hash: canonical_publication_availability_receipt_hash(&receipt)?,
    })
}

/// Verifies the same-slot binding between a compact publication frontier and a block header.
pub fn verify_publication_frontier_binding(
    header: &BlockHeader,
    frontier: &PublicationFrontier,
) -> Result<(), String> {
    let certificate = header.canonical_order_certificate.as_ref().ok_or_else(|| {
        "publication frontier verification requires a canonical-order certificate".to_string()
    })?;
    if frontier.height != header.height {
        return Err("publication frontier height does not match the block height".into());
    }
    if frontier.view != header.view {
        return Err("publication frontier view does not match the block view".into());
    }
    if frontier.counter != header.height {
        return Err("publication frontier counter does not match the slot height".into());
    }
    let receipt = build_publication_availability_receipt(certificate)?;
    verify_publication_availability_receipt(&receipt, certificate)?;
    if frontier.bulletin_commitment_hash != receipt.bulletin_commitment_hash {
        return Err("publication frontier does not match the bulletin commitment hash".into());
    }
    if frontier.ordered_transactions_root_hash != receipt.ordered_transactions_root_hash {
        return Err("publication frontier does not match the ordered transactions root".into());
    }
    let expected_receipt_hash = canonical_publication_availability_receipt_hash(&receipt)?;
    if frontier.availability_receipt_hash != expected_receipt_hash {
        return Err(
            "publication frontier does not match the publication availability receipt hash".into(),
        );
    }
    Ok(())
}

/// Verifies the predecessor link of a compact publication frontier.
pub fn verify_publication_frontier_chain(
    frontier: &PublicationFrontier,
    previous: &PublicationFrontier,
) -> Result<(), String> {
    if frontier.height != previous.height.saturating_add(1) {
        return Err("publication frontier height does not extend the previous frontier".into());
    }
    if frontier.counter != previous.counter.saturating_add(1) {
        return Err("publication frontier counter does not extend the previous frontier".into());
    }
    let expected_parent_hash = canonical_publication_frontier_hash(previous)?;
    if frontier.parent_frontier_hash != expected_parent_hash {
        return Err("publication frontier parent hash does not match the previous frontier".into());
    }
    Ok(())
}

/// Verifies a compact publication frontier against a block header and optional predecessor frontier.
pub fn verify_publication_frontier(
    header: &BlockHeader,
    frontier: &PublicationFrontier,
    previous: Option<&PublicationFrontier>,
) -> Result<(), String> {
    verify_publication_frontier_binding(header, frontier)?;
    match previous {
        Some(previous) => verify_publication_frontier_chain(frontier, previous),
        None if header.height <= 1 => {
            if frontier.parent_frontier_hash != [0u8; 32] {
                return Err("genesis publication frontier must have a zero parent hash".into());
            }
            Ok(())
        }
        None => Err(format!(
            "publication frontier for height {} requires a predecessor frontier",
            header.height
        )),
    }
}

/// Verifies an objective contradiction witness over compact publication frontiers.
pub fn verify_publication_frontier_contradiction(
    contradiction: &PublicationFrontierContradiction,
) -> Result<(), String> {
    if contradiction.candidate_frontier.height != contradiction.height {
        return Err("publication frontier contradiction candidate height does not match".into());
    }
    match contradiction.kind {
        PublicationFrontierContradictionKind::ConflictingFrontier => {
            if contradiction.reference_frontier.height != contradiction.height {
                return Err(
                    "publication frontier contradiction reference height does not match".into(),
                );
            }
            if contradiction.candidate_frontier.counter != contradiction.reference_frontier.counter
            {
                return Err(
                    "conflicting publication frontiers must target the same counter".into(),
                );
            }
            let candidate_hash =
                canonical_publication_frontier_hash(&contradiction.candidate_frontier)?;
            let reference_hash =
                canonical_publication_frontier_hash(&contradiction.reference_frontier)?;
            if candidate_hash == reference_hash {
                return Err(
                    "conflicting publication frontier witness must carry distinct frontiers".into(),
                );
            }
            Ok(())
        }
        PublicationFrontierContradictionKind::StaleParentLink => {
            let previous = &contradiction.reference_frontier;
            if previous.height.saturating_add(1) != contradiction.height {
                return Err(
                    "stale publication frontier witness must reference the immediately preceding frontier"
                        .into(),
                );
            }
            if contradiction.candidate_frontier.counter != contradiction.height {
                return Err(
                    "stale publication frontier witness carries an invalid slot counter".into(),
                );
            }
            let expected_parent_hash = canonical_publication_frontier_hash(previous)?;
            if contradiction.candidate_frontier.parent_frontier_hash == expected_parent_hash
                && contradiction.candidate_frontier.counter == previous.counter.saturating_add(1)
            {
                return Err(
                    "stale publication frontier witness does not contradict the predecessor link"
                        .into(),
                );
            }
            Ok(())
        }
    }
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
            let availability_certificate_hash = canonical_bulletin_availability_certificate_hash(
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
    if entry_height != height || entries.iter().any(|entry| entry.height != height) {
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
    verify_bulletin_surface_entries(
        certificate.height,
        &certificate.bulletin_commitment,
        entries,
    )
}

/// Deterministically extracts the canonical closed bulletin surface from published artifacts.
pub fn extract_canonical_bulletin_surface(
    close: &CanonicalBulletinClose,
    bulletin_commitment: &BulletinCommitment,
    bulletin_availability_certificate: &BulletinAvailabilityCertificate,
    entries: &[BulletinSurfaceEntry],
) -> Result<Vec<BulletinSurfaceEntry>, String> {
    verify_canonical_bulletin_close(
        close,
        bulletin_commitment,
        bulletin_availability_certificate,
    )?;
    let mut canonical_entries = entries.to_vec();
    canonical_entries.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
    verify_bulletin_surface_entries(close.height, bulletin_commitment, &canonical_entries)?;
    let expected_entry_count = usize::try_from(close.entry_count)
        .map_err(|_| "canonical bulletin close entry count does not fit into usize".to_string())?;
    if canonical_entries.len() != expected_entry_count {
        return Err(
            "canonical bulletin close entry count does not match the published bulletin surface"
                .into(),
        );
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
    if bundle
        .canonical_order_certificate
        .bulletin_availability_certificate
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
        .and_then(|candidate| {
            canonical_bulletin_commitment_hash(&candidate.bulletin_commitment).ok()
        })
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
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)?;
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
            let close = proof.observer_canonical_close.as_ref().ok_or_else(|| {
                "sealed finality proof is missing a canonical observer close".to_string()
            })?;
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
                return Err(
                    "sealed finality proof abort path must carry the BaseFinal tier".into(),
                );
            }
            let abort = proof.observer_canonical_abort.as_ref().ok_or_else(|| {
                "sealed finality proof is missing a canonical observer abort".to_string()
            })?;
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
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    bind_canonical_collapse_continuity(&mut collapse, previous)?;
    Ok(collapse)
}

/// Derives the protocol-wide canonical collapse object from a recovered full extractable
/// slot surface while binding the previous slot's continuity surface.
pub fn derive_canonical_collapse_object_from_recovered_surface(
    full_surface: &RecoverableSlotPayloadV5,
    bulletin_close: &CanonicalBulletinClose,
    previous: Option<&CanonicalCollapseObject>,
) -> Result<CanonicalCollapseObject, String> {
    let certificate = &full_surface.canonical_order_certificate;
    let expected_bulletin_close = build_canonical_bulletin_close(
        &certificate.bulletin_commitment,
        &certificate.bulletin_availability_certificate,
    )?;
    if &expected_bulletin_close != bulletin_close {
        return Err(
            "recovered full extractable slot surface carries a bulletin close that does not match the recovered canonical order certificate".into(),
        );
    }

    let mut collapse = CanonicalCollapseObject {
        height: full_surface.height,
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        continuity_accumulator_hash: [0u8; 32],
        continuity_recursive_proof: Default::default(),
        ordering: CanonicalOrderingCollapse {
            height: full_surface.height,
            kind: if certificate.omission_proofs.is_empty() {
                CanonicalCollapseKind::Close
            } else {
                CanonicalCollapseKind::Abort
            },
            bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                &certificate.bulletin_commitment,
            )?,
            bulletin_availability_certificate_hash:
                canonical_bulletin_availability_certificate_hash(
                    &certificate.bulletin_availability_certificate,
                )?,
            bulletin_close_hash: canonical_bulletin_close_hash(bulletin_close)?,
            canonical_order_certificate_hash: canonical_order_certificate_hash(certificate)?,
        },
        sealing: None,
        transactions_root_hash: certificate.ordered_transactions_root_hash,
        resulting_state_root_hash: certificate.resulting_state_root_hash,
        archived_recovered_history_checkpoint_hash: [0u8; 32],
        archived_recovered_history_profile_activation_hash: [0u8; 32],
        archived_recovered_history_retention_receipt_hash: [0u8; 32],
    };
    bind_canonical_collapse_continuity(&mut collapse, previous)?;
    Ok(collapse)
}

#[cfg(test)]
mod tests {
    use super::{
        archived_recovered_restart_page_range, bind_canonical_collapse_continuity,
        build_archived_recovered_history_checkpoint,
        build_archived_recovered_history_profile_activation,
        build_archived_recovered_history_retention_receipt,
        build_archived_recovered_history_segment, build_archived_recovered_restart_page,
        build_canonical_bulletin_close, build_committed_surface_canonical_order_certificate,
        build_publication_frontier, build_reference_canonical_order_certificate,
        canonical_archived_recovered_history_checkpoint_hash,
        canonical_archived_recovered_history_profile_activation_hash,
        canonical_archived_recovered_history_segment_hash,
        canonical_archived_recovered_history_segment_root,
        canonical_archived_recovered_restart_page_hash,
        canonical_collapse_commitment_hash_from_object, canonical_collapse_extension_certificate,
        canonical_collapse_historical_continuation_anchor, canonical_collapse_object_hash,
        canonical_collapse_recursive_proof_hash, canonical_missing_recovery_share_hash,
        canonical_order_certificate_hash, canonical_order_publication_bundle_hash,
        canonical_recoverable_slot_payload_hash, canonical_recoverable_slot_payload_v2_hash,
        canonical_recoverable_slot_payload_v3_hash, canonical_recoverable_slot_payload_v4_hash,
        canonical_recoverable_slot_payload_v5_hash, canonical_recovered_publication_bundle_hash,
        canonical_recovery_capsule_hash, canonical_recovery_share_material_hash,
        canonical_recovery_share_receipt_hash, canonical_recovery_witness_certificate_hash,
        canonical_replay_prefix_historical_continuation_anchor,
        canonical_transaction_root_from_hashes, canonicalize_transactions_for_header,
        derive_canonical_collapse_object, derive_canonical_collapse_object_from_recovered_surface,
        derive_canonical_collapse_object_with_previous, derive_canonical_order_execution_object,
        derive_canonical_order_public_obstruction, encode_coded_recovery_shards,
        expected_previous_canonical_collapse_commitment_hash, extract_canonical_bulletin_surface,
        lift_recoverable_slot_payload_v3_to_v4, lift_recoverable_slot_payload_v4_to_v5,
        normalize_recovered_publication_bundle_supporting_witnesses,
        recover_canonical_order_publication_bundle_from_share_materials,
        recover_recoverable_slot_payload_v3_from_share_materials,
        validate_archived_recovered_history_segment_predecessor,
        verify_block_header_canonical_collapse_evidence, verify_bulletin_surface_publication,
        verify_canonical_collapse_continuity, verify_canonical_collapse_recursive_proof,
        verify_canonical_collapse_recursive_proof_matches_collapse,
        verify_canonical_order_certificate, verify_canonical_order_publication_bundle,
        verify_publication_frontier, verify_publication_frontier_contradiction,
        CanonicalCollapseContinuityProofSystem, CanonicalCollapseKind, CanonicalOrderAbortReason,
        PublicationFrontierContradiction, PublicationFrontierContradictionKind,
    };
    use crate::app::{
        build_archived_recovered_history_profile,
        canonical_archived_recovered_history_profile_hash,
        canonical_archived_recovered_history_retention_receipt_hash,
        canonical_assigned_recovery_share_envelope_hash,
        canonical_asymptote_observer_canonical_close_hash,
        canonical_asymptote_observer_challenges_hash,
        canonical_asymptote_observer_transcripts_hash, canonical_validator_sets_hash, to_root_hash,
        AccountId, ArchivedRecoveredHistoryCheckpoint,
        ArchivedRecoveredHistoryCheckpointUpdateRule, ArchivedRecoveredHistorySegment,
        ArchivedRecoveredRestartPage, AssignedRecoveryShareEnvelopeV1,
        AsymptoteObserverCanonicalClose, BlockHeader, BulletinAvailabilityCertificate,
        BulletinCommitment, BulletinSurfaceEntry, CanonicalBulletinClose,
        CanonicalCollapseExtensionCertificate, CanonicalCollapseObject, CanonicalOrderCertificate,
        CanonicalOrderPublicationBundle, CanonicalOrderingCollapse, CanonicalReplayPrefixEntry,
        ChainId, ChainTransaction, CollapseState, FinalityTier, GuardianWitnessRecoveryBinding,
        MissingRecoveryShare, OmissionProof, QuorumCertificate, RecoverableSlotPayloadV1,
        RecoverableSlotPayloadV2, RecoverableSlotPayloadV3, RecoverableSlotPayloadV4,
        RecoverableSlotPayloadV5, RecoveredCanonicalHeaderEntry, RecoveredCertifiedHeaderEntry,
        RecoveredPublicationBundle, RecoveredRestartBlockHeaderEntry, RecoveryCapsule,
        RecoveryCodingDescriptor, RecoveryCodingFamily, RecoveryShareMaterial,
        RecoveryShareReceipt, RecoveryWitnessCertificate, SealedFinalityProof, SignHeader,
        SignatureProof, SignatureSuite, StateRoot, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    };
    use crate::codec;
    use std::sync::{Mutex, OnceLock};

    fn sample_archived_recovered_history_profile_for_tests(
    ) -> crate::app::ArchivedRecoveredHistoryProfile {
        build_archived_recovered_history_profile(
            1024,
            5,
            2,
            5,
            4,
            ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
        )
        .expect("archived recovered-history profile")
    }

    fn sample_archived_recovered_history_profile_hash_for_tests() -> [u8; 32] {
        canonical_archived_recovered_history_profile_hash(
            &sample_archived_recovered_history_profile_for_tests(),
        )
        .expect("archived recovered-history profile hash")
    }

    fn sample_archived_recovered_history_profile_activation_for_tests(
    ) -> crate::app::ArchivedRecoveredHistoryProfileActivation {
        build_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile_for_tests(),
            None,
            1,
            None,
        )
        .expect("archived recovered-history profile activation")
    }

    fn sample_archived_recovered_history_profile_activation_hash_for_tests() -> [u8; 32] {
        canonical_archived_recovered_history_profile_activation_hash(
            &sample_archived_recovered_history_profile_activation_for_tests(),
        )
        .expect("archived recovered-history profile activation hash")
    }

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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            publication_frontier: None,
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
    ) -> (
        BlockHeader,
        Vec<ChainTransaction>,
        CanonicalOrderCertificate,
    ) {
        let mut header = sample_ordering_header(height, view, seed);
        let transactions =
            canonicalize_transactions_for_header(&header, &sample_ordering_transactions(seed))
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

    fn build_sample_recoverable_slot_payload_v3(
        height: u64,
        view: u64,
        seed: u8,
    ) -> (RecoverableSlotPayloadV3, CanonicalOrderPublicationBundle) {
        let (mut header, ordered_transactions, certificate) =
            sample_committed_surface_ordering_fixture(height, view, seed);
        header.canonical_order_certificate = Some(certificate.clone());
        let execution_object =
            derive_canonical_order_execution_object(&header, &ordered_transactions)
                .expect("derive canonical order execution object");
        let bundle = CanonicalOrderPublicationBundle {
            bulletin_commitment: execution_object.bulletin_commitment.clone(),
            bulletin_entries: execution_object.bulletin_entries.clone(),
            bulletin_availability_certificate: execution_object
                .bulletin_availability_certificate
                .clone(),
            canonical_order_certificate: execution_object.canonical_order_certificate.clone(),
        };
        let payload = RecoverableSlotPayloadV3 {
            height: header.height,
            view: header.view,
            producer_account_id: header.producer_account_id,
            block_commitment_hash: header
                .hash()
                .expect("header hash")
                .as_slice()
                .try_into()
                .expect("32-byte block hash"),
            parent_block_hash: header.parent_hash,
            canonical_order_certificate: certificate,
            ordered_transaction_bytes: ordered_transactions
                .iter()
                .map(|transaction| {
                    codec::to_bytes_canonical(transaction).expect("encode ordered transaction")
                })
                .collect(),
            canonical_order_publication_bundle_bytes: codec::to_bytes_canonical(&bundle)
                .expect("encode publication bundle"),
        };
        (payload, bundle)
    }

    fn build_sample_recoverable_slot_payload_v4(
        height: u64,
        view: u64,
        seed: u8,
    ) -> (
        RecoverableSlotPayloadV4,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
    ) {
        let (payload_v3, bundle) = build_sample_recoverable_slot_payload_v3(height, view, seed);
        let (payload_v4, lifted_bundle, bulletin_close) =
            lift_recoverable_slot_payload_v3_to_v4(&payload_v3)
                .expect("lift recoverable payload v4");
        assert_eq!(lifted_bundle, bundle);
        (payload_v4, bundle, bulletin_close)
    }

    fn build_sample_recoverable_slot_payload_v5(
        height: u64,
        view: u64,
        seed: u8,
    ) -> (
        RecoverableSlotPayloadV5,
        CanonicalOrderPublicationBundle,
        CanonicalBulletinClose,
        Vec<BulletinSurfaceEntry>,
    ) {
        let (payload_v4, bundle, bulletin_close) =
            build_sample_recoverable_slot_payload_v4(height, view, seed);
        let (payload_v5, lifted_bundle, lifted_close, surface) =
            lift_recoverable_slot_payload_v4_to_v5(&payload_v4)
                .expect("lift recoverable payload v5");
        assert_eq!(lifted_bundle, bundle);
        assert_eq!(lifted_close, bulletin_close);
        (payload_v5, bundle, bulletin_close, surface)
    }

    fn encode_systematic_xor_k_of_k_plus_1_shards(
        payload: &RecoverableSlotPayloadV3,
        recovery_threshold: u16,
    ) -> Vec<Vec<u8>> {
        encode_coded_recovery_shards(
            xor_recovery_coding(recovery_threshold + 1, recovery_threshold),
            &codec::to_bytes_canonical(payload).expect("encode payload"),
        )
        .expect("encode xor shards")
    }

    fn encode_systematic_gf256_k_of_n_shards(
        payload: &RecoverableSlotPayloadV3,
        share_count: usize,
        recovery_threshold: usize,
    ) -> Vec<Vec<u8>> {
        encode_coded_recovery_shards(
            gf256_recovery_coding(
                u16::try_from(share_count).expect("share count"),
                u16::try_from(recovery_threshold).expect("recovery threshold"),
            ),
            &codec::to_bytes_canonical(payload).expect("encode payload"),
        )
        .expect("encode gf256 shards")
    }

    fn encode_systematic_gf256_2_of_4_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
        encode_systematic_gf256_k_of_n_shards(payload, 4, 2)
    }

    fn encode_systematic_gf256_3_of_5_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
        encode_systematic_gf256_k_of_n_shards(payload, 5, 3)
    }

    fn encode_systematic_gf256_3_of_7_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
        encode_systematic_gf256_k_of_n_shards(payload, 7, 3)
    }

    fn encode_systematic_gf256_4_of_6_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
        encode_systematic_gf256_k_of_n_shards(payload, 6, 4)
    }

    fn encode_systematic_gf256_4_of_7_shards(payload: &RecoverableSlotPayloadV3) -> Vec<Vec<u8>> {
        encode_systematic_gf256_k_of_n_shards(payload, 7, 4)
    }

    fn transparent_recovery_coding(
        share_count: u16,
        recovery_threshold: u16,
    ) -> RecoveryCodingDescriptor {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::TransparentCommittedSurfaceV1,
            share_count,
            recovery_threshold,
        }
    }

    fn xor_recovery_coding(share_count: u16, recovery_threshold: u16) -> RecoveryCodingDescriptor {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicXorKOfKPlus1V1,
            share_count,
            recovery_threshold,
        }
    }

    fn gf256_recovery_coding(
        share_count: u16,
        recovery_threshold: u16,
    ) -> RecoveryCodingDescriptor {
        RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicGf256KOfNV1,
            share_count,
            recovery_threshold,
        }
    }

    fn continuity_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn collect_index_combinations(total: usize, choose: usize) -> Vec<Vec<usize>> {
        fn recurse(
            total: usize,
            choose: usize,
            start: usize,
            current: &mut Vec<usize>,
            all: &mut Vec<Vec<usize>>,
        ) {
            if current.len() == choose {
                all.push(current.clone());
                return;
            }
            let remaining = choose.saturating_sub(current.len());
            for index in start..=total.saturating_sub(remaining) {
                current.push(index);
                recurse(total, choose, index + 1, current, all);
                current.pop();
            }
        }

        if choose == 0 {
            return vec![Vec::new()];
        }
        let mut all = Vec::new();
        let mut current = Vec::new();
        recurse(total, choose, 0, &mut current, &mut all);
        all
    }

    fn select_recovery_share_materials(
        materials: &[RecoveryShareMaterial],
        indices: &[usize],
    ) -> Vec<RecoveryShareMaterial> {
        indices
            .iter()
            .map(|index| materials[*index].clone())
            .collect()
    }

    fn build_coded_recovery_materials_for_contract(
        payload: &RecoverableSlotPayloadV3,
        coding: RecoveryCodingDescriptor,
        seed: u8,
    ) -> Vec<RecoveryShareMaterial> {
        let payload_bytes = codec::to_bytes_canonical(payload).expect("encode payload");
        let shards = coding
            .family_contract()
            .expect("coded recovery-family contract")
            .encode_payload_shards(&payload_bytes)
            .expect("encode payload shards");
        shards
            .into_iter()
            .enumerate()
            .map(|(share_index, material_bytes)| RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [seed.wrapping_add(share_index as u8 + 1); 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding,
                share_index: u16::try_from(share_index).expect("share index"),
                share_commitment_hash: [seed.wrapping_add(share_index as u8 + 41); 32],
                material_bytes,
            })
            .collect()
    }

    fn assert_coded_recovery_family_contract_conformance_case(
        height: u64,
        view: u64,
        seed: u8,
        coding: RecoveryCodingDescriptor,
    ) {
        let contract = coding
            .family_contract()
            .expect("coded recovery-family contract");
        assert!(
            contract.supports_coded_payload_reconstruction(),
            "test harness requires a coded recovery-family contract"
        );
        let (payload, expected_bundle) =
            build_sample_recoverable_slot_payload_v3(height, view, seed);
        let materials =
            build_coded_recovery_materials_for_contract(&payload, coding, seed.wrapping_add(60));

        for indices in
            collect_index_combinations(materials.len(), usize::from(coding.recovery_threshold))
        {
            let subset = select_recovery_share_materials(&materials, &indices);
            let recovered_payload_bytes = contract
                .recover_payload_bytes_from_materials(&subset)
                .unwrap_or_else(|error| {
                    panic!(
                        "threshold subset {indices:?} should reconstruct under {}: {error}",
                        coding.label()
                    )
                });
            let recovered_payload: RecoverableSlotPayloadV3 =
                codec::from_bytes_canonical(&recovered_payload_bytes)
                    .expect("decode reconstructed payload");
            let recovered_top_level = recover_recoverable_slot_payload_v3_from_share_materials(
                &subset,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "top-level threshold subset {indices:?} should reconstruct under {}: {error}",
                    coding.label()
                )
            });
            let (recovered_bundle_payload, recovered_bundle) =
                recover_canonical_order_publication_bundle_from_share_materials(&subset)
                    .unwrap_or_else(|error| {
                        panic!(
                            "publication bundle threshold subset {indices:?} should reconstruct under {}: {error}",
                            coding.label()
                        )
                    });
            assert_eq!(recovered_payload, payload);
            assert_eq!(recovered_top_level, payload);
            assert_eq!(recovered_bundle_payload, payload);
            assert_eq!(recovered_bundle, expected_bundle);
        }

        for indices in collect_index_combinations(
            materials.len(),
            usize::from(coding.recovery_threshold.saturating_sub(1)),
        ) {
            let subset = select_recovery_share_materials(&materials, &indices);
            let error = contract
                .recover_payload_bytes_from_materials(&subset)
                .expect_err("below-threshold subset should fail under the contract");
            assert!(
                error.contains(&format!(
                    "requires at least {} distinct share reveals",
                    coding.recovery_threshold
                )),
                "unexpected below-threshold error for {} subset {indices:?}: {error}",
                coding.label()
            );
        }
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
            publication_frontier: None,
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
            publication_frontier: None,
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
        let rebuilt_close =
            verify_canonical_order_publication_bundle(&super::CanonicalOrderPublicationBundle {
                bulletin_commitment: certificate.bulletin_commitment.clone(),
                bulletin_entries: entries.clone(),
                bulletin_availability_certificate: certificate
                    .bulletin_availability_certificate
                    .clone(),
                canonical_order_certificate: certificate.clone(),
            })
            .expect("verify publication bundle");
        assert_eq!(rebuilt_close, bulletin_close);

        header.canonical_order_certificate = Some(certificate.clone());
        let execution_object =
            derive_canonical_order_execution_object(&header, &ordered_transactions)
                .expect("derive canonical order execution object");
        assert_eq!(
            execution_object.bulletin_commitment,
            certificate.bulletin_commitment
        );
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
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let abort = derive_canonical_order_execution_object(&header, &[])
            .expect_err("missing canonical-order certificate must derive abort");
        assert_eq!(abort.height, header.height);
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::MissingOrderCertificate
        );
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
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::BulletinSurfaceMismatch
        );
        assert_ne!(abort.canonical_order_certificate_hash, [0u8; 32]);
        assert!(abort
            .details
            .contains("proof-carried bulletin surface is invalid"));
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_surface_reconstruction_failure() {
        let (header, ordered_transactions, _) =
            sample_committed_surface_ordering_fixture(29, 3, 24);
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
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::InvalidBulletinClose
        );
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
        assert_eq!(
            abort.reason,
            CanonicalOrderAbortReason::InvalidPublicInputsHash
        );
    }

    #[test]
    fn derive_canonical_order_public_obstruction_reports_invalid_availability_certificate() {
        let (mut header, ordered_transactions, mut certificate) =
            sample_committed_surface_ordering_fixture(45, 11, 65);
        certificate
            .bulletin_availability_certificate
            .recoverability_root[0] ^= 0xFF;
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
    fn publication_frontier_verifies_against_header_and_predecessor() {
        let (previous_header, _, _) = sample_committed_surface_ordering_fixture(1, 1, 71);
        let previous_frontier =
            build_publication_frontier(&previous_header, None).expect("previous frontier");
        verify_publication_frontier(&previous_header, &previous_frontier, None)
            .expect("genesis frontier should verify");

        let (header, _, _) = sample_committed_surface_ordering_fixture(2, 2, 72);
        let frontier =
            build_publication_frontier(&header, Some(&previous_frontier)).expect("frontier");
        verify_publication_frontier(&header, &frontier, Some(&previous_frontier))
            .expect("frontier should verify against predecessor");
    }

    #[test]
    fn publication_frontier_conflict_contradiction_verifies() {
        let (previous_header, _, _) = sample_committed_surface_ordering_fixture(1, 1, 73);
        let previous_frontier =
            build_publication_frontier(&previous_header, None).expect("previous frontier");
        let (header, _, _) = sample_committed_surface_ordering_fixture(2, 2, 74);
        let reference_frontier =
            build_publication_frontier(&header, Some(&previous_frontier)).expect("reference");
        let mut candidate_frontier = reference_frontier.clone();
        candidate_frontier.view += 1;
        candidate_frontier.bulletin_commitment_hash[0] ^= 0xFF;

        verify_publication_frontier_contradiction(&PublicationFrontierContradiction {
            height: header.height,
            kind: PublicationFrontierContradictionKind::ConflictingFrontier,
            candidate_frontier,
            reference_frontier,
        })
        .expect("conflicting frontier contradiction should verify");
    }

    #[test]
    fn publication_frontier_stale_parent_link_contradiction_verifies() {
        let (previous_header, _, _) = sample_committed_surface_ordering_fixture(4, 1, 75);
        let previous_frontier =
            build_publication_frontier(&previous_header, None).expect("previous frontier");
        let (header, _, _) = sample_committed_surface_ordering_fixture(5, 2, 76);
        let mut candidate_frontier =
            build_publication_frontier(&header, Some(&previous_frontier)).expect("frontier");
        candidate_frontier.parent_frontier_hash[0] ^= 0xAA;

        verify_publication_frontier_contradiction(&PublicationFrontierContradiction {
            height: header.height,
            kind: PublicationFrontierContradictionKind::StaleParentLink,
            candidate_frontier,
            reference_frontier: previous_frontier,
        })
        .expect("stale frontier contradiction should verify");
    }

    #[test]
    fn recovery_capsule_hash_changes_with_payload_commitment() {
        let mut capsule = RecoveryCapsule {
            height: 9,
            coding: RecoveryCodingDescriptor::deterministic_scaffold(),
            recovery_committee_root_hash: [1u8; 32],
            payload_commitment_hash: [2u8; 32],
            coding_root_hash: [3u8; 32],
            recovery_window_close_ms: 1_750_000_999_000,
        };
        let original = canonical_recovery_capsule_hash(&capsule).expect("capsule hash");
        capsule.payload_commitment_hash[0] ^= 0xFF;
        let updated = canonical_recovery_capsule_hash(&capsule).expect("updated capsule hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recovery_witness_and_missing_share_hashes_bind_distinct_evidence() {
        let certificate = RecoveryWitnessCertificate {
            height: 10,
            epoch: 4,
            witness_manifest_hash: [5u8; 32],
            recovery_capsule_hash: [6u8; 32],
            share_commitment_hash: [7u8; 32],
        };
        let receipt = RecoveryShareReceipt {
            height: 10,
            witness_manifest_hash: certificate.witness_manifest_hash,
            block_commitment_hash: [8u8; 32],
            share_commitment_hash: certificate.share_commitment_hash,
        };
        let material = RecoveryShareMaterial {
            height: 10,
            witness_manifest_hash: certificate.witness_manifest_hash,
            block_commitment_hash: receipt.block_commitment_hash,
            coding: transparent_recovery_coding(3, 2),
            share_index: 0,
            share_commitment_hash: certificate.share_commitment_hash,
            material_bytes: vec![1, 2, 3, 4],
        };
        let envelope = AssignedRecoveryShareEnvelopeV1 {
            recovery_capsule_hash: certificate.recovery_capsule_hash,
            expected_share_commitment_hash: certificate.share_commitment_hash,
            share_material: material.clone(),
        };
        let mut missing = MissingRecoveryShare {
            height: 10,
            witness_manifest_hash: certificate.witness_manifest_hash,
            recovery_capsule_hash: certificate.recovery_capsule_hash,
            recovery_window_close_ms: 1_750_001_111_000,
        };

        let certificate_hash = canonical_recovery_witness_certificate_hash(&certificate)
            .expect("recovery witness certificate hash");
        let receipt_hash =
            canonical_recovery_share_receipt_hash(&receipt).expect("recovery share receipt hash");
        let material_hash = canonical_recovery_share_material_hash(&material)
            .expect("recovery share material hash");
        let envelope_hash = canonical_assigned_recovery_share_envelope_hash(&envelope)
            .expect("assigned recovery share envelope hash");
        let missing_hash =
            canonical_missing_recovery_share_hash(&missing).expect("missing share hash");
        assert_ne!(certificate_hash, receipt_hash);
        assert_ne!(certificate_hash, material_hash);
        assert_ne!(certificate_hash, envelope_hash);
        assert_ne!(certificate_hash, missing_hash);
        assert_ne!(receipt_hash, material_hash);
        assert_ne!(receipt_hash, envelope_hash);
        assert_ne!(receipt_hash, missing_hash);
        assert_ne!(material_hash, envelope_hash);
        assert_ne!(material_hash, missing_hash);
        assert_ne!(envelope_hash, missing_hash);

        assert_eq!(material.to_recovery_share_receipt(), receipt);
        assert_eq!(
            envelope.recovery_binding(),
            GuardianWitnessRecoveryBinding {
                recovery_capsule_hash: certificate.recovery_capsule_hash,
                share_commitment_hash: certificate.share_commitment_hash,
            }
        );
        envelope
            .validate_for_witness(certificate.witness_manifest_hash, certificate.height)
            .expect("assigned recovery share envelope should validate");

        missing.recovery_window_close_ms += 1_000;
        let updated_missing_hash =
            canonical_missing_recovery_share_hash(&missing).expect("updated missing share hash");
        assert_ne!(missing_hash, updated_missing_hash);
    }

    #[test]
    fn recoverable_slot_payload_hash_changes_with_transaction_hashes() {
        let certificate = CanonicalOrderCertificate {
            height: 11,
            bulletin_commitment: BulletinCommitment {
                height: 11,
                cutoff_timestamp_ms: 1_750_002_222_000,
                bulletin_root: [31u8; 32],
                entry_count: 2,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 11,
                bulletin_commitment_hash: [32u8; 32],
                recoverability_root: [33u8; 32],
            },
            randomness_beacon: [34u8; 32],
            ordered_transactions_root_hash: [35u8; 32],
            resulting_state_root_hash: [36u8; 32],
            proof: Default::default(),
            omission_proofs: Vec::new(),
        };
        let mut payload = RecoverableSlotPayloadV1 {
            height: 11,
            view: 4,
            producer_account_id: AccountId([37u8; 32]),
            block_commitment_hash: [38u8; 32],
            canonical_order_certificate: certificate,
            ordered_transaction_hashes: vec![[39u8; 32], [40u8; 32]],
        };

        let original = canonical_recoverable_slot_payload_hash(&payload).expect("payload hash");
        payload.ordered_transaction_hashes[1][0] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_hash(&payload).expect("updated payload hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v2_hash_changes_with_transaction_bytes() {
        let certificate = CanonicalOrderCertificate {
            height: 12,
            bulletin_commitment: BulletinCommitment {
                height: 12,
                cutoff_timestamp_ms: 1_750_003_333_000,
                bulletin_root: [41u8; 32],
                entry_count: 2,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 12,
                bulletin_commitment_hash: [42u8; 32],
                recoverability_root: [43u8; 32],
            },
            randomness_beacon: [44u8; 32],
            ordered_transactions_root_hash: [45u8; 32],
            resulting_state_root_hash: [46u8; 32],
            proof: Default::default(),
            omission_proofs: Vec::new(),
        };
        let mut payload = RecoverableSlotPayloadV2 {
            height: 12,
            view: 5,
            producer_account_id: AccountId([47u8; 32]),
            block_commitment_hash: [48u8; 32],
            canonical_order_certificate: certificate,
            ordered_transaction_bytes: vec![vec![49u8, 50u8], vec![51u8, 52u8]],
        };

        let original =
            canonical_recoverable_slot_payload_v2_hash(&payload).expect("payload v2 hash");
        payload.ordered_transaction_bytes[1][1] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v2_hash(&payload).expect("updated payload v2 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v3_hash_changes_with_publication_bundle_bytes() {
        let certificate = CanonicalOrderCertificate {
            height: 13,
            bulletin_commitment: BulletinCommitment {
                height: 13,
                cutoff_timestamp_ms: 1_750_004_444_000,
                bulletin_root: [51u8; 32],
                entry_count: 2,
            },
            bulletin_availability_certificate: BulletinAvailabilityCertificate {
                height: 13,
                bulletin_commitment_hash: [52u8; 32],
                recoverability_root: [53u8; 32],
            },
            randomness_beacon: [54u8; 32],
            ordered_transactions_root_hash: [55u8; 32],
            resulting_state_root_hash: [56u8; 32],
            proof: Default::default(),
            omission_proofs: Vec::new(),
        };
        let mut payload = RecoverableSlotPayloadV3 {
            height: 13,
            view: 6,
            producer_account_id: AccountId([57u8; 32]),
            block_commitment_hash: [58u8; 32],
            parent_block_hash: [57u8; 32],
            canonical_order_certificate: certificate,
            ordered_transaction_bytes: vec![vec![59u8, 60u8], vec![61u8, 62u8]],
            canonical_order_publication_bundle_bytes: vec![63u8, 64u8, 65u8],
        };

        let original =
            canonical_recoverable_slot_payload_v3_hash(&payload).expect("payload v3 hash");
        payload.canonical_order_publication_bundle_bytes[2] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v3_hash(&payload).expect("updated payload v3 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v4_hash_changes_with_bulletin_close_bytes() {
        let (mut payload, _, _) = build_sample_recoverable_slot_payload_v4(13, 6, 57);
        let original =
            canonical_recoverable_slot_payload_v4_hash(&payload).expect("payload v4 hash");
        payload.canonical_bulletin_close_bytes[0] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v4_hash(&payload).expect("updated payload v4 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recoverable_slot_payload_v5_hash_changes_with_bulletin_surface_entries() {
        let (mut payload, _, _, _) = build_sample_recoverable_slot_payload_v5(14, 7, 63);
        let original =
            canonical_recoverable_slot_payload_v5_hash(&payload).expect("payload v5 hash");
        payload.bulletin_surface_entries[0].tx_hash[0] ^= 0xFF;
        let updated =
            canonical_recoverable_slot_payload_v5_hash(&payload).expect("updated payload v5 hash");
        assert_ne!(original, updated);
    }

    #[test]
    fn recovered_publication_bundle_hash_changes_with_supporting_witnesses() {
        let recovered = RecoveredPublicationBundle {
            height: 14,
            block_commitment_hash: [66u8; 32],
            parent_block_commitment_hash: [65u8; 32],
            coding: xor_recovery_coding(3, 2),
            supporting_witness_manifest_hashes: vec![[67u8; 32], [68u8; 32]],
            recoverable_slot_payload_hash: [69u8; 32],
            recoverable_full_surface_hash: [70u8; 32],
            canonical_order_publication_bundle_hash: [71u8; 32],
            canonical_bulletin_close_hash: [72u8; 32],
        };
        let original =
            canonical_recovered_publication_bundle_hash(&recovered).expect("recovered hash");
        let mut updated = recovered.clone();
        updated.supporting_witness_manifest_hashes.swap(0, 1);
        let reordered =
            canonical_recovered_publication_bundle_hash(&updated).expect("reordered hash");
        assert_ne!(original, reordered);

        let normalized = normalize_recovered_publication_bundle_supporting_witnesses(
            &updated.supporting_witness_manifest_hashes,
        )
        .expect("normalize supporting witnesses");
        assert_eq!(normalized, vec![[67u8; 32], [68u8; 32]]);
    }

    #[test]
    fn archived_recovered_history_segment_builder_chains_previous_hash_deterministically() {
        let recovered_a = RecoveredPublicationBundle {
            height: 21,
            block_commitment_hash: [80u8; 32],
            parent_block_commitment_hash: [79u8; 32],
            coding: xor_recovery_coding(3, 2),
            supporting_witness_manifest_hashes: vec![[81u8; 32], [82u8; 32]],
            recoverable_slot_payload_hash: [83u8; 32],
            recoverable_full_surface_hash: [84u8; 32],
            canonical_order_publication_bundle_hash: [85u8; 32],
            canonical_bulletin_close_hash: [86u8; 32],
        };
        let recovered_b = RecoveredPublicationBundle {
            height: 22,
            block_commitment_hash: [87u8; 32],
            parent_block_commitment_hash: [80u8; 32],
            coding: xor_recovery_coding(3, 2),
            supporting_witness_manifest_hashes: vec![[88u8; 32], [89u8; 32]],
            recoverable_slot_payload_hash: [90u8; 32],
            recoverable_full_surface_hash: [91u8; 32],
            canonical_order_publication_bundle_hash: [92u8; 32],
            canonical_bulletin_close_hash: [93u8; 32],
        };

        let previous_segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_a),
            None,
            None,
            &sample_archived_recovered_history_profile_for_tests(),
            &sample_archived_recovered_history_profile_activation_for_tests(),
        )
        .expect("previous segment");
        let current_segment = build_archived_recovered_history_segment(
            std::slice::from_ref(&recovered_b),
            Some(&previous_segment),
            None,
            &sample_archived_recovered_history_profile_for_tests(),
            &sample_archived_recovered_history_profile_activation_for_tests(),
        )
        .expect("current segment");

        assert_eq!(current_segment.start_height, 22);
        assert_eq!(current_segment.end_height, 22);
        assert_eq!(
            current_segment.previous_archived_segment_hash,
            canonical_archived_recovered_history_segment_hash(&previous_segment)
                .expect("previous segment hash")
        );
    }

    #[test]
    fn archived_recovered_history_segment_builder_derives_overlap_root_from_range() {
        let recovered_a = RecoveredPublicationBundle {
            height: 31,
            block_commitment_hash: [94u8; 32],
            parent_block_commitment_hash: [93u8; 32],
            coding: gf256_recovery_coding(4, 2),
            supporting_witness_manifest_hashes: vec![[95u8; 32], [96u8; 32]],
            recoverable_slot_payload_hash: [97u8; 32],
            recoverable_full_surface_hash: [98u8; 32],
            canonical_order_publication_bundle_hash: [99u8; 32],
            canonical_bulletin_close_hash: [100u8; 32],
        };
        let recovered_b = RecoveredPublicationBundle {
            height: 32,
            block_commitment_hash: [101u8; 32],
            parent_block_commitment_hash: [94u8; 32],
            coding: gf256_recovery_coding(4, 2),
            supporting_witness_manifest_hashes: vec![[102u8; 32], [103u8; 32]],
            recoverable_slot_payload_hash: [104u8; 32],
            recoverable_full_surface_hash: [105u8; 32],
            canonical_order_publication_bundle_hash: [106u8; 32],
            canonical_bulletin_close_hash: [107u8; 32],
        };
        let recovered_c = RecoveredPublicationBundle {
            height: 33,
            block_commitment_hash: [108u8; 32],
            parent_block_commitment_hash: [101u8; 32],
            coding: gf256_recovery_coding(4, 2),
            supporting_witness_manifest_hashes: vec![[109u8; 32], [110u8; 32]],
            recoverable_slot_payload_hash: [111u8; 32],
            recoverable_full_surface_hash: [112u8; 32],
            canonical_order_publication_bundle_hash: [113u8; 32],
            canonical_bulletin_close_hash: [114u8; 32],
        };
        let segment = build_archived_recovered_history_segment(
            &[
                recovered_a.clone(),
                recovered_b.clone(),
                recovered_c.clone(),
            ],
            None,
            Some((32, 33)),
            &sample_archived_recovered_history_profile_for_tests(),
            &sample_archived_recovered_history_profile_activation_for_tests(),
        )
        .expect("segment");

        let overlap_hashes = vec![
            canonical_recovered_publication_bundle_hash(&recovered_b).expect("recovered b hash"),
            canonical_recovered_publication_bundle_hash(&recovered_c).expect("recovered c hash"),
        ];
        assert_eq!(segment.overlap_start_height, 32);
        assert_eq!(segment.overlap_end_height, 33);
        assert_eq!(
            segment.overlap_root_hash,
            canonical_archived_recovered_history_segment_root(&overlap_hashes)
                .expect("overlap root hash")
        );
    }

    #[test]
    fn archived_recovered_history_segment_predecessor_validation_rejects_out_of_range_overlap() {
        let previous = ArchivedRecoveredHistorySegment {
            start_height: 40,
            end_height: 40,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [115u8; 32],
            last_recovered_publication_bundle_hash: [115u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [116u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let mut current = ArchivedRecoveredHistorySegment {
            start_height: 41,
            end_height: 41,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [117u8; 32],
            last_recovered_publication_bundle_hash: [117u8; 32],
            previous_archived_segment_hash: canonical_archived_recovered_history_segment_hash(
                &previous,
            )
            .expect("previous archived segment hash"),
            segment_root_hash: [118u8; 32],
            overlap_start_height: 41,
            overlap_end_height: 41,
            overlap_root_hash: [119u8; 32],
        };

        let error = validate_archived_recovered_history_segment_predecessor(&previous, &current)
            .expect_err("overlap outside predecessor coverage should fail");
        assert!(error.contains("does not cover the declared overlap anchor"));

        current.overlap_start_height = 0;
        current.overlap_end_height = 0;
        current.overlap_root_hash = [0u8; 32];
        validate_archived_recovered_history_segment_predecessor(&previous, &current)
            .expect("non-overlap predecessor should remain valid");
    }

    #[test]
    fn archived_recovered_history_segment_predecessor_validation_accepts_exact_overlap_page() {
        let previous = ArchivedRecoveredHistorySegment {
            start_height: 28,
            end_height: 30,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [132u8; 32],
            last_recovered_publication_bundle_hash: [133u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [134u8; 32],
            overlap_start_height: 29,
            overlap_end_height: 30,
            overlap_root_hash: [135u8; 32],
        };
        let current = ArchivedRecoveredHistorySegment {
            start_height: 29,
            end_height: 31,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [136u8; 32],
            last_recovered_publication_bundle_hash: [137u8; 32],
            previous_archived_segment_hash: canonical_archived_recovered_history_segment_hash(
                &previous,
            )
            .expect("previous archived segment hash"),
            segment_root_hash: [138u8; 32],
            overlap_start_height: 29,
            overlap_end_height: 30,
            overlap_root_hash: [139u8; 32],
        };

        validate_archived_recovered_history_segment_predecessor(&previous, &current)
            .expect("exact-overlap archived predecessor should remain valid");
    }

    #[test]
    fn archived_recovered_restart_page_range_matches_bounded_fold_page_geometry() {
        assert_eq!(
            archived_recovered_restart_page_range(30, 5, 2, 5, 4)
                .expect("archived recovered restart page range"),
            (1, 30)
        );
        assert_eq!(
            archived_recovered_restart_page_range(54, 5, 2, 5, 4)
                .expect("archived recovered restart page range"),
            (2, 54)
        );
    }

    #[test]
    fn archived_recovered_restart_page_builder_matches_segment_range() {
        let previous = ArchivedRecoveredHistorySegment {
            start_height: 50,
            end_height: 50,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [120u8; 32],
            last_recovered_publication_bundle_hash: [120u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [121u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let segment = ArchivedRecoveredHistorySegment {
            start_height: 51,
            end_height: 51,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [122u8; 32],
            last_recovered_publication_bundle_hash: [122u8; 32],
            previous_archived_segment_hash: canonical_archived_recovered_history_segment_hash(
                &previous,
            )
            .expect("previous archived segment hash"),
            segment_root_hash: [123u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let restart_entry = RecoveredRestartBlockHeaderEntry {
            certified_header: RecoveredCertifiedHeaderEntry {
                header: RecoveredCanonicalHeaderEntry {
                    height: 51,
                    view: 7,
                    canonical_block_commitment_hash: [124u8; 32],
                    parent_block_commitment_hash: [125u8; 32],
                    transactions_root_hash: [126u8; 32],
                    resulting_state_root_hash: [127u8; 32],
                    previous_canonical_collapse_commitment_hash: [128u8; 32],
                },
                certified_parent_quorum_certificate: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [125u8; 32],
                    ..Default::default()
                },
                certified_parent_resulting_state_root_hash: [129u8; 32],
            },
            header: BlockHeader {
                height: 51,
                view: 7,
                parent_hash: [125u8; 32],
                parent_state_root: StateRoot(vec![129u8; 32]),
                state_root: StateRoot(vec![127u8; 32]),
                transactions_root: vec![126u8; 32],
                timestamp: 1,
                timestamp_ms: 1_000,
                gas_used: 0,
                validator_set: Vec::new(),
                producer_account_id: AccountId([130u8; 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [131u8; 32],
                producer_pubkey: Vec::new(),
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
                parent_qc: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [125u8; 32],
                    ..Default::default()
                },
                previous_canonical_collapse_commitment_hash: [128u8; 32],
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                signature: Vec::new(),
            },
        };

        let page =
            build_archived_recovered_restart_page(&segment, std::slice::from_ref(&restart_entry))
                .expect("archived recovered restart page");
        assert_eq!(page.start_height, 51);
        assert_eq!(page.end_height, 51);
        assert_eq!(
            page.segment_hash,
            canonical_archived_recovered_history_segment_hash(&segment).expect("segment hash")
        );
        assert_eq!(page.restart_headers, vec![restart_entry]);
    }

    #[test]
    fn canonical_collapse_historical_continuation_anchor_requires_all_hashes_or_none() {
        let mut collapse = CanonicalCollapseObject {
            height: 77,
            ..Default::default()
        };
        assert_eq!(
            canonical_collapse_historical_continuation_anchor(&collapse).expect("no anchor"),
            None
        );

        collapse.archived_recovered_history_checkpoint_hash = [0x11; 32];
        let error = canonical_collapse_historical_continuation_anchor(&collapse)
            .expect_err("partial anchor must fail");
        assert!(error.contains("all bootstrap hashes or none"));

        collapse.archived_recovered_history_profile_activation_hash = [0x22; 32];
        collapse.archived_recovered_history_retention_receipt_hash = [0x33; 32];
        let anchor = canonical_collapse_historical_continuation_anchor(&collapse)
            .expect("full anchor")
            .expect("present anchor");
        assert_eq!(anchor.checkpoint_hash, [0x11; 32]);
        assert_eq!(anchor.profile_activation_hash, [0x22; 32]);
        assert_eq!(anchor.retention_receipt_hash, [0x33; 32]);
    }

    #[test]
    fn canonical_replay_prefix_historical_continuation_anchor_matches_optional_triplet() {
        let mut entry = CanonicalReplayPrefixEntry {
            height: 91,
            ..Default::default()
        };
        assert_eq!(
            canonical_replay_prefix_historical_continuation_anchor(&entry).expect("no anchor"),
            None
        );

        entry.archived_recovered_history_checkpoint_hash = Some([0x41; 32]);
        entry.archived_recovered_history_profile_activation_hash = Some([0x42; 32]);
        entry.archived_recovered_history_retention_receipt_hash = Some([0x43; 32]);

        let anchor = canonical_replay_prefix_historical_continuation_anchor(&entry)
            .expect("full replay anchor")
            .expect("present replay anchor");
        assert_eq!(anchor.checkpoint_hash, [0x41; 32]);
        assert_eq!(anchor.profile_activation_hash, [0x42; 32]);
        assert_eq!(anchor.retention_receipt_hash, [0x43; 32]);
    }

    #[test]
    fn archived_recovered_history_checkpoint_builder_commits_segment_and_page_hashes() {
        let segment = ArchivedRecoveredHistorySegment {
            start_height: 51,
            end_height: 51,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [140u8; 32],
            last_recovered_publication_bundle_hash: [140u8; 32],
            previous_archived_segment_hash: [0u8; 32],
            segment_root_hash: [141u8; 32],
            overlap_start_height: 0,
            overlap_end_height: 0,
            overlap_root_hash: [0u8; 32],
        };
        let restart_entry = RecoveredRestartBlockHeaderEntry {
            certified_header: RecoveredCertifiedHeaderEntry {
                header: RecoveredCanonicalHeaderEntry {
                    height: 51,
                    view: 7,
                    canonical_block_commitment_hash: [142u8; 32],
                    parent_block_commitment_hash: [143u8; 32],
                    transactions_root_hash: [144u8; 32],
                    resulting_state_root_hash: [145u8; 32],
                    previous_canonical_collapse_commitment_hash: [146u8; 32],
                },
                certified_parent_quorum_certificate: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [143u8; 32],
                    ..Default::default()
                },
                certified_parent_resulting_state_root_hash: [147u8; 32],
            },
            header: BlockHeader {
                height: 51,
                view: 7,
                parent_hash: [143u8; 32],
                parent_state_root: StateRoot(vec![147u8; 32]),
                state_root: StateRoot(vec![145u8; 32]),
                transactions_root: vec![144u8; 32],
                timestamp: 1,
                timestamp_ms: 1_000,
                gas_used: 0,
                validator_set: Vec::new(),
                producer_account_id: AccountId([148u8; 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [149u8; 32],
                producer_pubkey: Vec::new(),
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
                parent_qc: QuorumCertificate {
                    height: 50,
                    view: 6,
                    block_hash: [143u8; 32],
                    ..Default::default()
                },
                previous_canonical_collapse_commitment_hash: [146u8; 32],
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                signature: Vec::new(),
            },
        };
        let page =
            build_archived_recovered_restart_page(&segment, std::slice::from_ref(&restart_entry))
                .expect("archived recovered restart page");

        let checkpoint = build_archived_recovered_history_checkpoint(&segment, &page, None)
            .expect("archived recovered history checkpoint");
        assert_eq!(checkpoint.covered_start_height, segment.start_height);
        assert_eq!(checkpoint.covered_end_height, segment.end_height);
        assert_eq!(
            checkpoint.latest_archived_segment_hash,
            canonical_archived_recovered_history_segment_hash(&segment).expect("segment hash")
        );
        assert_eq!(
            checkpoint.latest_archived_restart_page_hash,
            canonical_archived_recovered_restart_page_hash(&page).expect("page hash")
        );
        assert_eq!(checkpoint.previous_archived_checkpoint_hash, [0u8; 32]);
    }

    #[test]
    fn archived_recovered_history_checkpoint_builder_chains_previous_hash() {
        let previous_checkpoint = ArchivedRecoveredHistoryCheckpoint {
            covered_start_height: 28,
            covered_end_height: 50,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            latest_archived_segment_hash: [150u8; 32],
            latest_archived_restart_page_hash: [151u8; 32],
            previous_archived_checkpoint_hash: [0u8; 32],
        };
        let segment = ArchivedRecoveredHistorySegment {
            start_height: 29,
            end_height: 51,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            first_recovered_publication_bundle_hash: [152u8; 32],
            last_recovered_publication_bundle_hash: [153u8; 32],
            previous_archived_segment_hash: [154u8; 32],
            segment_root_hash: [155u8; 32],
            overlap_start_height: 29,
            overlap_end_height: 50,
            overlap_root_hash: [156u8; 32],
        };
        let page = ArchivedRecoveredRestartPage {
            segment_hash: canonical_archived_recovered_history_segment_hash(&segment)
                .expect("segment hash"),
            archived_profile_hash: segment.archived_profile_hash,
            archived_profile_activation_hash: segment.archived_profile_activation_hash,
            start_height: 29,
            end_height: 51,
            restart_headers: (29..=51)
                .map(|height| RecoveredRestartBlockHeaderEntry {
                    certified_header: RecoveredCertifiedHeaderEntry {
                        header: RecoveredCanonicalHeaderEntry {
                            height,
                            view: 7,
                            canonical_block_commitment_hash: [157u8; 32],
                            parent_block_commitment_hash: [158u8; 32],
                            transactions_root_hash: [159u8; 32],
                            resulting_state_root_hash: [160u8; 32],
                            previous_canonical_collapse_commitment_hash: [161u8; 32],
                        },
                        certified_parent_quorum_certificate: QuorumCertificate {
                            height: height.saturating_sub(1),
                            view: 6,
                            block_hash: [158u8; 32],
                            ..Default::default()
                        },
                        certified_parent_resulting_state_root_hash: [162u8; 32],
                    },
                    header: BlockHeader {
                        height,
                        view: 7,
                        parent_hash: [158u8; 32],
                        parent_state_root: StateRoot(vec![162u8; 32]),
                        state_root: StateRoot(vec![160u8; 32]),
                        transactions_root: vec![159u8; 32],
                        timestamp: 1,
                        timestamp_ms: 1_000,
                        gas_used: 0,
                        validator_set: Vec::new(),
                        producer_account_id: AccountId([163u8; 32]),
                        producer_key_suite: SignatureSuite::ED25519,
                        producer_pubkey_hash: [164u8; 32],
                        producer_pubkey: Vec::new(),
                        oracle_counter: 0,
                        oracle_trace_hash: [0u8; 32],
                        parent_qc: QuorumCertificate {
                            height: height.saturating_sub(1),
                            view: 6,
                            block_hash: [158u8; 32],
                            ..Default::default()
                        },
                        previous_canonical_collapse_commitment_hash: [161u8; 32],
                        canonical_collapse_extension_certificate: None,
                        publication_frontier: None,
                        guardian_certificate: None,
                        sealed_finality_proof: None,
                        canonical_order_certificate: None,
                        timeout_certificate: None,
                        signature: Vec::new(),
                    },
                })
                .collect(),
        };

        let checkpoint = build_archived_recovered_history_checkpoint(
            &segment,
            &page,
            Some(&previous_checkpoint),
        )
        .expect("chained archived recovered history checkpoint");
        assert_eq!(
            checkpoint.previous_archived_checkpoint_hash,
            canonical_archived_recovered_history_checkpoint_hash(&previous_checkpoint)
                .expect("previous checkpoint hash")
        );
    }

    #[test]
    fn archived_recovered_history_retention_receipt_builder_commits_checkpoint_and_validator_set() {
        let checkpoint = ArchivedRecoveredHistoryCheckpoint {
            covered_start_height: 41,
            covered_end_height: 63,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            latest_archived_segment_hash: [170u8; 32],
            latest_archived_restart_page_hash: [171u8; 32],
            previous_archived_checkpoint_hash: [169u8; 32],
        };
        let validator_sets = ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 3,
                validators: vec![
                    ValidatorV1 {
                        account_id: AccountId([0x11; 32]),
                        weight: 1,
                        consensus_key: Default::default(),
                    },
                    ValidatorV1 {
                        account_id: AccountId([0x22; 32]),
                        weight: 2,
                        consensus_key: Default::default(),
                    },
                ],
            },
            next: None,
        };
        let validator_set_commitment_hash =
            canonical_validator_sets_hash(&validator_sets).expect("validator set commitment hash");

        let receipt = build_archived_recovered_history_retention_receipt(
            &checkpoint,
            validator_set_commitment_hash,
            96,
        )
        .expect("archived recovered-history retention receipt");

        assert_eq!(
            receipt.covered_start_height,
            checkpoint.covered_start_height
        );
        assert_eq!(receipt.covered_end_height, checkpoint.covered_end_height);
        assert_eq!(
            receipt.archived_checkpoint_hash,
            canonical_archived_recovered_history_checkpoint_hash(&checkpoint)
                .expect("checkpoint hash")
        );
        assert_eq!(
            receipt.validator_set_commitment_hash,
            validator_set_commitment_hash
        );
        assert_eq!(receipt.retained_through_height, 96);
        assert_ne!(
            canonical_archived_recovered_history_retention_receipt_hash(&receipt)
                .expect("receipt hash"),
            [0u8; 32]
        );
    }

    #[test]
    fn archived_recovered_history_retention_receipt_builder_rejects_short_horizon() {
        let checkpoint = ArchivedRecoveredHistoryCheckpoint {
            covered_start_height: 71,
            covered_end_height: 93,
            archived_profile_hash: sample_archived_recovered_history_profile_hash_for_tests(),
            archived_profile_activation_hash:
                sample_archived_recovered_history_profile_activation_hash_for_tests(),
            latest_archived_segment_hash: [180u8; 32],
            latest_archived_restart_page_hash: [181u8; 32],
            previous_archived_checkpoint_hash: [179u8; 32],
        };

        let error =
            build_archived_recovered_history_retention_receipt(&checkpoint, [182u8; 32], 92)
                .expect_err("short retention horizon must fail");
        assert!(error.contains("retained-through height"));
    }

    #[test]
    fn archived_recovered_history_profile_builder_commits_archive_geometry() {
        let profile = build_archived_recovered_history_profile(
            1024,
            5,
            2,
            5,
            4,
            ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
        )
        .expect("archived recovered-history profile");
        assert_eq!(profile.retention_horizon, 1024);
        assert_eq!(profile.restart_page_window, 5);
        assert_eq!(profile.restart_page_overlap, 2);
        assert_eq!(profile.windows_per_segment, 5);
        assert_eq!(profile.segments_per_fold, 4);
        assert_eq!(
            canonical_archived_recovered_history_profile_hash(&profile)
                .expect("archived recovered-history profile hash"),
            canonical_archived_recovered_history_profile_hash(&profile)
                .expect("deterministic archived recovered-history profile hash")
        );
    }

    #[test]
    fn archived_recovered_history_profile_builder_rejects_zero_retention_horizon() {
        let error = build_archived_recovered_history_profile(
            0,
            5,
            2,
            5,
            4,
            ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
        )
        .expect_err("zero archived retention horizon must fail");
        assert!(error.contains("non-zero retention horizon"));
    }

    #[test]
    fn recoverable_slot_payload_v4_lifts_from_v3_and_preserves_bundle() {
        let (payload_v3, bundle) = build_sample_recoverable_slot_payload_v3(21, 9, 44);
        let (payload_v4, lifted_bundle, bulletin_close) =
            lift_recoverable_slot_payload_v3_to_v4(&payload_v3).expect("lift payload v4");

        assert_eq!(lifted_bundle, bundle);
        assert_eq!(payload_v4.height, payload_v3.height);
        assert_eq!(payload_v4.view, payload_v3.view);
        assert_eq!(
            payload_v4.producer_account_id,
            payload_v3.producer_account_id
        );
        assert_eq!(
            payload_v4.block_commitment_hash,
            payload_v3.block_commitment_hash
        );
        assert_eq!(
            payload_v4.canonical_order_certificate,
            payload_v3.canonical_order_certificate
        );
        assert_eq!(
            payload_v4.ordered_transaction_bytes,
            payload_v3.ordered_transaction_bytes
        );
        assert_eq!(
            payload_v4.canonical_order_publication_bundle_bytes,
            payload_v3.canonical_order_publication_bundle_bytes
        );
        let decoded_close: CanonicalBulletinClose =
            codec::from_bytes_canonical(&payload_v4.canonical_bulletin_close_bytes)
                .expect("decode bulletin close");
        assert_eq!(decoded_close, bulletin_close);
    }

    #[test]
    fn recoverable_slot_payload_v5_lifts_from_v4_and_extracts_surface() {
        let (payload_v4, bundle, bulletin_close) =
            build_sample_recoverable_slot_payload_v4(22, 10, 47);
        let (payload_v5, lifted_bundle, lifted_close, surface) =
            lift_recoverable_slot_payload_v4_to_v5(&payload_v4).expect("lift payload v5");

        assert_eq!(lifted_bundle, bundle);
        assert_eq!(lifted_close, bulletin_close);
        assert_eq!(payload_v5.height, payload_v4.height);
        assert_eq!(payload_v5.view, payload_v4.view);
        assert_eq!(
            payload_v5.producer_account_id,
            payload_v4.producer_account_id
        );
        assert_eq!(
            payload_v5.block_commitment_hash,
            payload_v4.block_commitment_hash
        );
        assert_eq!(
            payload_v5.canonical_order_certificate,
            payload_v4.canonical_order_certificate
        );
        assert_eq!(
            payload_v5.ordered_transaction_bytes,
            payload_v4.ordered_transaction_bytes
        );
        assert_eq!(
            payload_v5.canonical_order_publication_bundle_bytes,
            payload_v4.canonical_order_publication_bundle_bytes
        );
        assert_eq!(
            payload_v5.canonical_bulletin_close_bytes,
            payload_v4.canonical_bulletin_close_bytes
        );
        let decoded_availability: BulletinAvailabilityCertificate = codec::from_bytes_canonical(
            &payload_v5.canonical_bulletin_availability_certificate_bytes,
        )
        .expect("decode bulletin availability");
        assert_eq!(
            decoded_availability,
            bundle.bulletin_availability_certificate
        );
        assert_eq!(payload_v5.bulletin_surface_entries, surface);
        assert_eq!(surface, bundle.bulletin_entries);
    }

    #[test]
    fn recovered_surface_derives_close_valued_canonical_collapse_object() {
        let (payload_v5, _, bulletin_close, _) =
            build_sample_recoverable_slot_payload_v5(2, 10, 47);
        let previous = sample_canonical_collapse_object(1, None, 91);

        let collapse = derive_canonical_collapse_object_from_recovered_surface(
            &payload_v5,
            &bulletin_close,
            Some(&previous),
        )
        .expect("derive recovered collapse");

        assert_eq!(collapse.height, payload_v5.height);
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Close);
        assert_eq!(
            collapse.transactions_root_hash,
            payload_v5
                .canonical_order_certificate
                .ordered_transactions_root_hash
        );
        assert_eq!(
            collapse.resulting_state_root_hash,
            payload_v5
                .canonical_order_certificate
                .resulting_state_root_hash
        );
        verify_canonical_collapse_continuity(&collapse, Some(&previous))
            .expect("recovered close continuity should verify");
    }

    #[test]
    fn recovered_surface_derives_abort_valued_canonical_collapse_object_for_omissions() {
        let (mut payload_v5, _, bulletin_close, _) =
            build_sample_recoverable_slot_payload_v5(3, 11, 48);
        payload_v5
            .canonical_order_certificate
            .omission_proofs
            .push(OmissionProof {
                height: payload_v5.height,
                tx_hash: [0xA7u8; 32],
                offender_account_id: AccountId([0x91u8; 32]),
                bulletin_root: [0xB3u8; 32],
                details: "recovered omission proof".into(),
            });
        let grandparent = sample_canonical_collapse_object(1, None, 92);
        let previous = sample_canonical_collapse_object(2, Some(&grandparent), 93);

        let collapse = derive_canonical_collapse_object_from_recovered_surface(
            &payload_v5,
            &bulletin_close,
            Some(&previous),
        )
        .expect("derive recovered omission collapse");

        assert_eq!(collapse.height, payload_v5.height);
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Abort);
        verify_canonical_collapse_continuity(&collapse, Some(&previous))
            .expect("recovered abort continuity should verify");
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_two_systematic_xor_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(15, 7, 71);
        let shards = encode_systematic_xor_k_of_k_plus_1_shards(&payload, 2);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [72u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(3, 2),
                share_index: 0,
                share_commitment_hash: [73u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [74u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(3, 2),
                share_index: 2,
                share_commitment_hash: [75u8; 32],
                material_bytes: shards[2].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from two systematic xor shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
        assert_eq!(
            canonical_order_publication_bundle_hash(&recovered_bundle)
                .expect("publication bundle hash"),
            canonical_order_publication_bundle_hash(&bundle).expect("expected bundle hash")
        );
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_three_of_four_systematic_xor_parity_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(16, 8, 76);
        let shards = encode_systematic_xor_k_of_k_plus_1_shards(&payload, 3);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [77u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(4, 3),
                share_index: 0,
                share_commitment_hash: [78u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [79u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(4, 3),
                share_index: 2,
                share_commitment_hash: [80u8; 32],
                material_bytes: shards[2].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [81u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: xor_recovery_coding(4, 3),
                share_index: 3,
                share_commitment_hash: [82u8; 32],
                material_bytes: shards[3].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect(
            "recoverable slot payload should reconstruct from three of four parity-family shares",
        );
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_two_of_four_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(17, 9, 83);
        let shards = encode_systematic_gf256_2_of_4_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [84u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(4, 2),
                share_index: 1,
                share_commitment_hash: [85u8; 32],
                material_bytes: shards[1].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [86u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(4, 2),
                share_index: 3,
                share_commitment_hash: [87u8; 32],
                material_bytes: shards[3].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from two of four gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_three_of_five_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(18, 10, 88);
        let shards = encode_systematic_gf256_3_of_5_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [89u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(5, 3),
                share_index: 0,
                share_commitment_hash: [90u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [91u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(5, 3),
                share_index: 3,
                share_commitment_hash: [92u8; 32],
                material_bytes: shards[3].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [93u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(5, 3),
                share_index: 4,
                share_commitment_hash: [94u8; 32],
                material_bytes: shards[4].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from three of five gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_three_of_seven_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(19, 11, 95);
        let shards = encode_systematic_gf256_3_of_7_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [96u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 3),
                share_index: 0,
                share_commitment_hash: [97u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [98u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 3),
                share_index: 3,
                share_commitment_hash: [99u8; 32],
                material_bytes: shards[3].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [100u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 3),
                share_index: 6,
                share_commitment_hash: [101u8; 32],
                material_bytes: shards[6].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from three of seven gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_four_of_six_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(20, 12, 102);
        let shards = encode_systematic_gf256_4_of_6_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [103u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 0,
                share_commitment_hash: [104u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [105u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 2,
                share_commitment_hash: [106u8; 32],
                material_bytes: shards[2].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [107u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 4,
                share_commitment_hash: [108u8; 32],
                material_bytes: shards[4].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [109u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(6, 4),
                share_index: 5,
                share_commitment_hash: [110u8; 32],
                material_bytes: shards[5].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from four of six gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn recoverable_slot_payload_v3_reconstructs_from_four_of_seven_systematic_gf256_shares() {
        let (payload, bundle) = build_sample_recoverable_slot_payload_v3(21, 13, 111);
        let shards = encode_systematic_gf256_4_of_7_shards(&payload);
        let materials = vec![
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [112u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 0,
                share_commitment_hash: [113u8; 32],
                material_bytes: shards[0].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [114u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 2,
                share_commitment_hash: [115u8; 32],
                material_bytes: shards[2].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [116u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 4,
                share_commitment_hash: [117u8; 32],
                material_bytes: shards[4].clone(),
            },
            RecoveryShareMaterial {
                height: payload.height,
                witness_manifest_hash: [118u8; 32],
                block_commitment_hash: payload.block_commitment_hash,
                coding: gf256_recovery_coding(7, 4),
                share_index: 6,
                share_commitment_hash: [119u8; 32],
                material_bytes: shards[6].clone(),
            },
        ];

        let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
            .expect("recoverable slot payload should reconstruct from four of seven gf256 shares");
        assert_eq!(reconstructed, payload);

        let (recovered_payload, recovered_bundle) =
            recover_canonical_order_publication_bundle_from_share_materials(&materials)
                .expect("publication bundle should reconstruct");
        assert_eq!(recovered_payload, payload);
        assert_eq!(recovered_bundle, bundle);
    }

    #[test]
    fn coded_recovery_family_contract_conformance_holds_across_supported_families() {
        for (height, view, seed, coding) in [
            (30, 14, 0x41, xor_recovery_coding(3, 2)),
            (31, 15, 0x47, xor_recovery_coding(4, 3)),
            (32, 16, 0x53, gf256_recovery_coding(4, 2)),
            (33, 17, 0x59, gf256_recovery_coding(5, 3)),
            (34, 18, 0x61, gf256_recovery_coding(7, 3)),
            (35, 19, 0x67, gf256_recovery_coding(7, 4)),
        ] {
            assert_coded_recovery_family_contract_conformance_case(height, view, seed, coding);
        }
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
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let collapse =
            derive_canonical_collapse_object(&header, &[]).expect("derive collapse object");
        assert_eq!(collapse.height, header.height);
        assert_eq!(
            collapse.previous_canonical_collapse_commitment_hash,
            [0u8; 32]
        );
        assert_eq!(collapse.ordering.kind, CanonicalCollapseKind::Abort);
        assert!(collapse.sealing.is_none());
        assert_eq!(
            collapse.transactions_root_hash,
            to_root_hash(&header.transactions_root).unwrap()
        );
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
            publication_frontier: None,
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

        let collapse = derive_canonical_collapse_object(&header, &ordered_transactions)
            .expect("derive collapse object");
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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
            signature: vec![],
        };
        let collapse =
            derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous))
                .expect("derive continuity-bound collapse");
        let previous_hash =
            canonical_collapse_commitment_hash_from_object(&previous).expect("previous hash");
        assert_eq!(
            collapse.previous_canonical_collapse_commitment_hash,
            previous_hash
        );
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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            publication_frontier: None,
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err());
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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err());
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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            canonical_collapse_extension_certificate: Some(certificate_from_predecessor(&previous)),
            publication_frontier: None,
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

        assert!(verify_canonical_collapse_recursive_proof_matches_collapse(
            &mismatched,
            &proof,
            Some(&previous),
        )
        .is_err());
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
        let tampered_hash = canonical_collapse_recursive_proof_hash(&carried)
            .expect("tampered recursive proof hash");

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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
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
            publication_frontier: None,
            signature: vec![],
        };

        assert!(verify_block_header_canonical_collapse_evidence(&header, Some(&previous)).is_err());
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
