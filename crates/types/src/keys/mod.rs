// Path: crates/types/src/keys.rs
//! Defines constants for well-known state keys.

/// The state key for the map of validator stakes active for the CURRENT block height.
pub const STAKES_KEY_CURRENT: &[u8] = b"system::stakes::current";
/// The state key for the map of validator stakes that will become active at the NEXT block height.
pub const STAKES_KEY_NEXT: &[u8] = b"system::stakes::next";
/// The state key for the persisted chain status.
pub const STATUS_KEY: &[u8] = b"chain::status";
/// The state key for the active validator set (for consensus).
pub const VALIDATOR_SET_KEY: &[u8] = b"system::validators";
/// The state key for the Proof-of-Authority authority set.
pub const AUTHORITY_SET_KEY: &[u8] = b"system::authorities";
/// The state key for the governance public key.
pub const GOVERNANCE_KEY: &[u8] = b"system::governance_key";
/// The state key for the governance-approved semantic AI model hash.
pub const STATE_KEY_SEMANTIC_MODEL_HASH: &[u8] = b"system::semantic_model_hash";

/// The state key prefix for user account data.
pub const ACCOUNT_KEY_PREFIX: &[u8] = b"account::";
/// The state key prefix for gas escrow entries.
pub const GAS_ESCROW_KEY_PREFIX: &[u8] = b"escrow::gas::";

/// The state key for the next available proposal ID.
pub const GOVERNANCE_NEXT_PROPOSAL_ID_KEY: &[u8] = b"gov::next_id";
/// The state key prefix for storing proposals by ID.
pub const GOVERNANCE_PROPOSAL_KEY_PREFIX: &[u8] = b"gov::proposal::";
/// The state key prefix for storing votes.
pub const GOVERNANCE_VOTE_KEY_PREFIX: &[u8] = b"gov::vote::";