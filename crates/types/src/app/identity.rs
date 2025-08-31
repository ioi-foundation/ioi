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

/// The minimal record of an active consensus key, stored in the core state map.
#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct ActiveKeyRecord {
    /// The algorithm used by this credential.
    pub suite: SignatureSuite,
    /// The hash of the public key.
    pub pubkey_hash: [u8; 32],
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
            if let Ok(pk) = libp2p::identity::PublicKey::try_decode_protobuf(public_key) {
                // It's a libp2p key, use its protobuf encoding as the canonical form.
                data_to_hash.extend_from_slice(&pk.encode_protobuf());
            } else if public_key.len() == 32 {
                // It's a raw 32-byte key, use it directly.
                data_to_hash.extend_from_slice(public_key);
            } else {
                return Err(TransactionError::Invalid(
                    "Malformed Ed25519 public key".to_string(),
                ));
            }
        }
        SignatureSuite::Dilithium2 => {
            // Dilithium keys have a single representation, so just hash the bytes.
            data_to_hash.extend_from_slice(public_key);
        }
    }

    let hash_bytes = DcryptSha256::digest(&data_to_hash)
        .map_err(|e| TransactionError::Invalid(format!("Hashing failed: {}", e)))?
        .to_bytes();

    Ok(hash_bytes
        .try_into()
        .expect("SHA256 digest should be 32 bytes"))
}