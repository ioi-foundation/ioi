// Path: crates/types/src/app/identity.rs

//! Defines the canonical `AccountId` and the single, deterministic function
//! used to derive it from a cryptographic public key.
//!
//! This module serves as the foundational source of truth for on-chain identity,
//! ensuring consistency across all services, transaction models, and state transitions.

use crate::error::TransactionError;
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use dcrypt::algorithms::ByteSerializable;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// A unique identifier for a blockchain, used for replay protection.
#[derive(
    Encode,
    Decode,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Default,
    Hash,
)]
#[serde(transparent)] // Ensures JSON/TOML is just the raw u32
pub struct ChainId(pub u32);

impl From<u32> for ChainId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}
impl From<ChainId> for u32 {
    fn from(c: ChainId) -> Self {
        c.0
    }
}

/// A unique, stable identifier for an on-chain account, derived from the hash of a public key.
///
/// This `AccountId` remains constant even if the underlying cryptographic keys are rotated,
/// providing a persistent address for accounts. It is represented as a 32-byte array.
#[derive(
    Encode,
    Decode,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Default,
    Hash,
)]
pub struct AccountId(pub [u8; 32]);

impl AsRef<[u8]> for AccountId {
    /// Allows treating the `AccountId` as a byte slice.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for AccountId {
    /// Allows creating an `AccountId` directly from a 32-byte array.
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl core::fmt::Display for ChainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Defines the cryptographic algorithm suite used for a key or signature.
///
/// Instead of a closed enum, this uses an `i32` identifier compatible with the
/// IANA COSE Algorithms Registry. This provides cryptographic agility, allowing
/// the chain to support new algorithms (e.g., ML-DSA, SLH-DSA) without breaking changes.
#[derive(
    Encode,
    Decode,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
)]
#[serde(transparent)]
pub struct SignatureSuite(pub i32);

impl SignatureSuite {
    /// Ed25519 (Pure). IANA COSE ID: -8.
    pub const ED25519: Self = Self(-8);

    /// ML-DSA-44 (formerly Dilithium2).
    /// Using tentative IANA assignment or private range for now (e.g., -17 based on drafts).
    pub const ML_DSA_44: Self = Self(-17);

    /// Falcon-512 (Round 3).
    /// Private range ID for now.
    pub const FALCON_512: Self = Self(-100);

    /// Hybrid Scheme: Ed25519 + ML-DSA-44.
    /// Concatenated Public Keys and Signatures.
    /// Private range ID.
    pub const HYBRID_ED25519_ML_DSA_44: Self = Self(-200);

    /// Returns true if the algorithm is considered post-quantum secure.
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            *self,
            Self::ML_DSA_44 | Self::FALCON_512 | Self::HYBRID_ED25519_ML_DSA_44
        )
    }
}

/// The minimal record of an active consensus key, stored in the core state map.
#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode, Default)]
pub struct ActiveKeyRecord {
    /// The algorithm used by this credential.
    pub suite: SignatureSuite,
    /// The hash of the public key.
    pub public_key_hash: [u8; 32],
    /// The first block height at which this key is valid for signing.
    pub since_height: u64,
}

/// A cryptographic credential defining an account's active key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Credential {
    /// The algorithm used by this credential.
    pub suite: SignatureSuite,
    /// The SHA-256 hash of the public key.
    pub public_key_hash: [u8; 32],
    /// The block height at which this credential becomes active.
    pub activation_height: u64,
    /// Optional location of the full public key on a Layer 2 or DA layer.
    pub l2_location: Option<String>,
    /// The voting weight associated with this credential.
    /// Used for multisig threshold calculations. Defaults to 1 for standard accounts.
    #[serde(default = "default_weight")]
    pub weight: u64,
}

fn default_weight() -> u64 {
    1
}

/// Derives a canonical, deterministic `AccountId` from a public key's raw material.
///
/// This is the **SINGLE SOURCE OF TRUTH** for account ID generation across the entire system.
/// It uses a domain-separated `sha256` hash and includes a suite tag to ensure that the
/// output cannot collide with other hashes or between different key types. It correctly
/// handles both raw and libp2p-encoded Ed25519 keys by reducing them to a canonical form before hashing.
pub fn account_id_from_key_material(
    suite: SignatureSuite,
    public_key: &[u8],
) -> Result<[u8; 32], TransactionError> {
    // Concatenate all parts to be hashed into a single buffer.
    let mut data_to_hash = Vec::new();
    // Domain separate the hash to prevent collisions with other parts of the system.
    data_to_hash.extend_from_slice(b"IOI-ACCOUNT-ID::V1");

    // [CHANGED] Include the I32 suite ID in the hash preimage to bind ID to algorithm.
    // We use Big Endian to ensure consistency across architectures.
    data_to_hash.extend_from_slice(&suite.0.to_be_bytes());

    // Reduce different key encodings to a single canonical representation before hashing.
    if suite == SignatureSuite::ED25519 {
        // --- FIX: Unambiguously reduce to raw 32-byte key ---
        let raw_key = if let Ok(pk) = libp2p::identity::PublicKey::try_decode_protobuf(public_key) {
            // If it's a libp2p key, convert it to its raw 32-byte form.
            pk.try_into_ed25519()
                .map_err(|_| TransactionError::Invalid("Not an Ed25519 libp2p key".to_string()))?
                .to_bytes()
                .to_vec()
        } else if public_key.len() == 32 {
            // If it's already a raw 32-byte key, use it directly.
            public_key.to_vec()
        } else {
            return Err(TransactionError::Invalid(
                "Malformed Ed25519 public key".to_string(),
            ));
        };
        data_to_hash.extend_from_slice(&raw_key);
    } else {
        // For ML-DSA (Dilithium), Falcon, and Hybrids, the key representation is fixed/raw,
        // so we hash the bytes directly.
        data_to_hash.extend_from_slice(public_key);
    }

    let hash_bytes = DcryptSha256::digest(&data_to_hash)
        .map_err(|e| TransactionError::Invalid(format!("Hashing failed: {}", e)))?
        .to_bytes();

    hash_bytes
        .try_into()
        .map_err(|_| TransactionError::Invalid("SHA256 digest was not 32 bytes".into()))
}

// -----------------------------------------------------------------------------
// Binary Integrity & Boot Attestation Types
// -----------------------------------------------------------------------------

/// A domain tag to prevent hash collisions for different signature purposes.
#[derive(Encode, Decode)]
pub enum SigDomain {
    /// The domain for version 1 of the block header signing preimage.
    BlockHeaderV1,
}

/// Represents a cryptographic measurement of a specific binary file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BinaryMeasurement {
    /// The filename (e.g., "orchestration", "workload").
    pub name: String,
    /// The SHA-256 hash of the binary file.
    pub sha256: [u8; 32],
    /// The size of the binary in bytes.
    pub size: u64,
}

/// A signed attestation from a Guardian proving the integrity of the node's boot process.
/// This structure is serialized, signed, and stored on-chain to provide an immutable
/// audit trail of the software running on the network.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BootAttestation {
    /// The AccountId of the validator issuing this attestation.
    pub validator_account_id: AccountId,
    /// The UNIX timestamp (seconds) when the measurement was taken.
    pub timestamp: u64,
    /// Measurement of the Guardian binary itself.
    pub guardian: BinaryMeasurement,
    /// Measurement of the Orchestrator binary.
    pub orchestration: BinaryMeasurement,
    /// Measurement of the Workload binary.
    pub workload: BinaryMeasurement,
    /// Optional metadata string (e.g., git commit hash, version tag).
    pub build_metadata: String,
    /// The cryptographic signature over the canonical encoding of the fields above.
    /// This signature DOES NOT cover itself; it covers the serialized struct with this field empty.
    pub signature: Vec<u8>,
}

impl BootAttestation {
    /// Creates the canonical byte buffer for signing (excluding the signature field).
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, crate::error::CoreError> {
        let mut temp = self.clone();
        temp.signature = Vec::new();
        crate::codec::to_bytes_canonical(&temp).map_err(crate::error::CoreError::Custom)
    }
}

/// The payload sent from Guardian to Orchestrator via the secure IPC channel.
/// It aggregates the agentic model hash (for logic integrity) and the boot
/// attestation (for binary integrity).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GuardianReport {
    /// The hash of the agentic model (for model integrity checks).
    pub agentic_hash: Vec<u8>,
    /// The signed boot attestation (for binary integrity checks).
    pub binary_attestation: BootAttestation,
}
