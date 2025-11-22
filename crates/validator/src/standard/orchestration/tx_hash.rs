// Path: crates/validator/src/standard/orchestration/tx_hash.rs
use anyhow::{anyhow, Error};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::{app::ChainTransaction, codec};

/// A fixed-size transaction hash.
pub type TxHash = [u8; 32];

/// Computes the SHA-256 hash of a transaction's canonical serialization.
pub fn hash_transaction(tx: &ChainTransaction) -> Result<TxHash, Error> {
    let serialized = codec::to_bytes_canonical(tx).map_err(|e| anyhow!(e))?;
    hash_transaction_bytes(&serialized)
}

/// Computes the SHA-256 hash of a raw byte slice (e.g., serialized transaction).
pub fn hash_transaction_bytes(bytes: &[u8]) -> Result<TxHash, Error> {
    sha256(bytes).map_err(|e| anyhow!(e))
}