// crates/types/src/app/identity.rs

//! Defines the canonical `AccountId` and the single, deterministic function
//! used to derive it from a cryptographic public key.
//!
//! This module serves as the foundational source of truth for on-chain identity,
//! ensuring consistency across all services, transaction models, and state transitions.

use dcrypt::algorithms::xof::{Blake3Xof, ExtendableOutputFunction};
use libp2p::identity::PublicKey;
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

/// An enum to tag the raw key bytes, ensuring future algorithm additions are non-breaking.
/// This prevents cross-algorithm collisions if different key types were to produce the
/// same raw byte representation.
pub enum KeyAlgo {
    /// Represents an Ed25519 public key.
    Ed25519 = 0x01,
}

/// Derives a canonical, deterministic `AccountId` from a `libp2p::identity::PublicKey`.
///
/// This is the **SINGLE SOURCE OF TRUTH** for account ID generation across the entire system.
/// It uses a domain-separated `blake3` hash to ensure that the output cannot collide with
/// hashes generated for other purposes within the SDK.
///
/// # Arguments
///
/// * `pk` - A reference to the `libp2p::identity::PublicKey` to derive the ID from.
///
/// # Returns
///
/// A canonical 32-byte `AccountId`.
///
/// # Panics
///
/// This function will panic if it encounters a `PublicKey` variant that is not yet supported
/// for `AccountId` derivation (e.g., Secp256k1, if not implemented).
pub fn account_id_from_pubkey(pk: &PublicKey) -> AccountId {
    // The libp2p::identity::PublicKey is an opaque struct in some versions,
    // requiring `try_into_*` methods to access the underlying key data. We use
    // an `if let` chain to handle this correctly.
    let (algo_tag, raw_key_bytes): (u8, Vec<u8>) =
        if let Ok(ed25519_pk) = pk.clone().try_into_ed25519() {
            // --- MODIFICATION START ---
            // Do not rely on external crates implementing traits like `Encode`.
            // Instead, extract the canonical raw bytes, which are stable.
            (KeyAlgo::Ed25519 as u8, ed25519_pk.to_bytes().to_vec())
            // --- MODIFICATION END ---
        }
        // Add other key types here using `else if let Ok(...)`
        else {
            unimplemented!("Unsupported public key algorithm for AccountId derivation");
        };

    // Use the streaming API of Blake3Xof for domain separation.
    let mut xof = Blake3Xof::new();
    // Use a domain separator to prevent hash collisions with other parts of the system.
    xof.update(b"DEP-SDK-ACCOUNT-ID::V1").unwrap();
    // Include the algorithm tag in the hash to prevent cross-algorithm collisions.
    xof.update(&[algo_tag]).unwrap();
    // Hash the raw key bytes.
    xof.update(&raw_key_bytes).unwrap();

    let hash_vec = xof.squeeze_into_vec(32).unwrap();
    let hash_array: [u8; 32] = hash_vec
        .try_into()
        .expect("Blake3Xof output should be 32 bytes");

    AccountId(hash_array)
}
