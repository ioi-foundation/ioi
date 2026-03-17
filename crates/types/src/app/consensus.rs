// Path: crates/types/src/app/consensus.rs

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
/// State key prefix for published AFT canonical-order certificates by height.
pub const AFT_ORDER_CERTIFICATE_PREFIX: &[u8] = b"aft::ordering::certificate::";
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

/// Builds the canonical state key for a published AFT canonical-order certificate.
pub fn aft_order_certificate_key(height: u64) -> Vec<u8> {
    [AFT_ORDER_CERTIFICATE_PREFIX, &height.to_be_bytes()].concat()
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

/// Succinct witness payload for the committed-surface canonical-order verifier.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct CommittedSurfaceCanonicalOrderProof {
    /// Canonical recoverability root over the published bulletin surface.
    #[serde(default)]
    pub recoverability_root: [u8; 32],
    /// Canonical commitment over the omission set for the slot.
    #[serde(default)]
    pub omission_commitment_root: [u8; 32],
}

/// Objective proof that a candidate canonical order omitted an eligible transaction.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct OmissionProof {
    /// Slot / height the omission applies to.
    pub height: u64,
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

    let mut certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment,
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
    let proof = CommittedSurfaceCanonicalOrderProof {
        recoverability_root: canonical_recoverability_root(
            &bulletin_commitment,
            &randomness_beacon,
            &ordered_transactions_root_hash,
            &resulting_state_root_hash,
        )?,
        omission_commitment_root: canonical_omission_commitment_root(&omission_proofs)?,
    };

    let mut certificate = CanonicalOrderCertificate {
        height: header.height,
        bulletin_commitment,
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
) -> Result<(), String> {
    if certificate.height != header.height
        || certificate.bulletin_commitment.height != header.height
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
            let recoverability_root = canonical_recoverability_root(
                &certificate.bulletin_commitment,
                &certificate.randomness_beacon,
                &certificate.ordered_transactions_root_hash,
                &certificate.resulting_state_root_hash,
            )?;
            if recoverability_root != proof.recoverability_root {
                return Err(
                    "committed-surface canonical order proof does not match the recoverability root"
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

#[cfg(test)]
mod tests {
    use super::{
        build_committed_surface_canonical_order_certificate,
        build_reference_canonical_order_certificate, canonical_transaction_root_from_hashes,
        canonicalize_transactions_for_header, verify_canonical_order_certificate,
    };
    use crate::app::{
        AccountId, BlockHeader, ChainId, ChainTransaction, QuorumCertificate, SignHeader,
        SignatureProof, SignatureSuite, StateRoot, SystemPayload, SystemTransaction,
    };

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
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let certificate =
            build_reference_canonical_order_certificate(&header, &[]).expect("build certificate");
        assert!(certificate.omission_proofs.is_empty());
        assert_ne!(certificate.bulletin_commitment.bulletin_root, [0u8; 32]);
        verify_canonical_order_certificate(
            &header,
            &certificate,
            Some(&certificate.bulletin_commitment),
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
                method: "publish_aft_order_certificate@v1".into(),
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
        verify_canonical_order_certificate(
            &header,
            &certificate,
            Some(&certificate.bulletin_commitment),
        )
        .expect("verify committed-surface certificate");
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
