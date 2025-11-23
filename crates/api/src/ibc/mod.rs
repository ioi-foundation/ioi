// Path: crates/api/src/ibc/mod.rs
use crate::error::CoreError;
use async_trait::async_trait;
use ioi_types::ibc::{Finality, Header, InclusionProof};
use std::collections::HashMap;

pub mod zk;
pub use zk::IbcZkVerifier;

/// A cache to amortize expensive deserialization across multiple verifications in a single block.
#[derive(Default, Debug)]
pub struct VerifyCtx {
    /// Example: Cache deserialized Tendermint validator sets by hash.
    pub tm_valsets: HashMap<[u8; 32], Vec<u8>>,
    /// Example: Cache deserialized Ethereum sync committees by period.
    pub eth_sync_committees: HashMap<u64, Vec<u8>>,
    // Room for Solana vote-sets, etc.
}

/// A generic verifier for an external blockchain's state and consensus.
#[async_trait]
pub trait LightClient: Send + Sync {
    /// The unique identifier for the chain this verifier targets (e.g., "eth-mainnet").
    fn chain_id(&self) -> &str;

    /// Verifies that a header is valid and follows a previously verified header.
    /// A mutable context is passed to cache deserialized data for the duration of a block.
    async fn verify_header(
        &self,
        header: &Header,
        finality: &Finality,
        ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError>;

    /// Verifies that the given inclusion proof is valid for the given header.
    /// For ICS-23, the proof must include `path` (ICS-24 key, usually without the store prefix)
    /// and the committed `value` in addition to `proof_bytes`.
    async fn verify_inclusion(
        &self,
        proof: &InclusionProof,
        header: &Header,
        ctx: &mut VerifyCtx,
    ) -> Result<(), CoreError>;

    /// Returns the latest block height that has been successfully verified and stored.
    async fn latest_verified_height(&self) -> u64;
}