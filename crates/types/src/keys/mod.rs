// Path: crates/types/src/keys.rs
//! Defines constants for well-known state keys.

/// The state key for the map of validator stakes.
pub const STAKES_KEY: &[u8] = b"system::stakes";
/// The state key for the persisted chain status.
pub const STATUS_KEY: &[u8] = b"chain::status";
/// The state key for the active validator set (for consensus).
pub const VALIDATOR_SET_KEY: &[u8] = b"system::validators";
/// The state key for the Proof-of-Authority authority set.
pub const AUTHORITY_SET_KEY: &[u8] = b"system::authorities";
/// The state key for the governance public key.
pub const GOVERNANCE_KEY: &[u8] = b"system::governance_key";
