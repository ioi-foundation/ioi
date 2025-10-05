// Path: crates/types/src/app/identity.rs

//! Defines the canonical `AccountId` and the single, deterministic function
//! used to derive it from a cryptographic public key.
//!
//! This module serves as the foundational source of truth for on-chain identity,
//! ensuring consistency across all services, transaction models, and state transitions.

use crate::app::SignatureSuite;
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
    data_to_hash.extend_from_slice(b"DEP-SDK-ACCOUNT-ID::V1");
    // Include the suite tag to prevent cross-algorithm collisions.
    data_to_hash.push(match suite {
        SignatureSuite::Ed25519 => 0x01,
        SignatureSuite::Dilithium2 => 0x02,
    });

    // Reduce different key encodings to a single canonical representation before hashing.
    match suite {
        SignatureSuite::Ed25519 => {
            // --- FIX: Unambiguously reduce to raw 32-byte key ---
            let raw_key =
                if let Ok(pk) = libp2p::identity::PublicKey::try_decode_protobuf(public_key) {
                    // If it's a libp2p key, convert it to its raw 32-byte form.
                    pk.try_into_ed25519()
                        .map_err(|_| {
                            TransactionError::Invalid("Not an Ed25519 libp2p key".to_string())
                        })?
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
        }
        SignatureSuite::Dilithium2 => {
            // Dilithium keys have a single representation, so just hash the bytes.
            data_to_hash.extend_from_slice(public_key);
        }
    }

    let hash_bytes = DcryptSha256::digest(&data_to_hash)
        .map_err(|e| TransactionError::Invalid(format!("Hashing failed: {}", e)))?
        .to_bytes();

    hash_bytes
        .try_into()
        .map_err(|_| TransactionError::Invalid("SHA256 digest was not 32 bytes".into()))
}
