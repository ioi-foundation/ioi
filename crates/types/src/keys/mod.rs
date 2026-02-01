// Path: crates/types/src/keys/mod.rs
//! Defines constants for well-known state keys.
//!
//! These constants provide a single source of truth for the keys used to store
//! critical system data in the state manager. Using these constants prevents
//! typos and ensures consistency across different modules that need to access
//! the same state entries.

/// The state key for the single, canonical `ValidatorSetBlob` structure.
pub const VALIDATOR_SET_KEY: &[u8] = b"system::validators::current";

/// The state key for the persisted chain status.
pub const STATUS_KEY: &[u8] = b"chain::status";

/// The state key for the Proof-of-Authority authority set.
#[deprecated(note = "Use VALIDATOR_SET_KEY with a PoA-configured ValidatorSetBlob")]
pub const AUTHORITY_SET_KEY: &[u8] = b"system::authorities";
/// The state key for the governance public key.
pub const GOVERNANCE_KEY: &[u8] = b"system::governance_key";
/// The state key for the governance-approved agentic AI model hash.
pub const STATE_KEY_SEMANTIC_MODEL_HASH: &[u8] = b"system::agentic_model_hash";

/// The state key for the current PoS stake distribution (effective this epoch).
pub const STAKES_KEY_CURRENT: &[u8] = b"system::stakes::current";
/// The state key for the next PoS stake distribution (effective next epoch).
pub const STAKES_KEY_NEXT: &[u8] = b"system::stakes::next";

/// The state key prefix for user account data.
pub const ACCOUNT_KEY_PREFIX: &[u8] = b"account::";
/// The state key prefix for a user's transaction nonce.
pub const ACCOUNT_NONCE_PREFIX: &[u8] = b"account::nonce::";
/// The state key prefix for gas escrow entries.
pub const GAS_ESCROW_KEY_PREFIX: &[u8] = b"escrow::gas::";

/// The state key for the next available proposal ID.
pub const GOVERNANCE_NEXT_PROPOSAL_ID_KEY: &[u8] = b"gov::next_id";
/// The state key prefix for storing proposals by ID.
pub const GOVERNANCE_PROPOSAL_KEY_PREFIX: &[u8] = b"gov::proposal::";
/// The state key prefix for storing votes.
pub const GOVERNANCE_VOTE_KEY_PREFIX: &[u8] = b"gov::vote::";

/// The state key prefix for pending oracle requests, keyed by request_id.
pub const ORACLE_PENDING_REQUEST_PREFIX: &[u8] = b"oracle::pending::";
/// The state key prefix for finalized oracle data, keyed by request_id.
pub const ORACLE_DATA_PREFIX: &[u8] = b"oracle::data::";

/// The state key prefix for storing processed foreign receipt IDs to prevent replays.
pub const IBC_PROCESSED_RECEIPT_PREFIX: &[u8] = b"ibc::receipt::";

/// State key prefix for pending module upgrades, keyed by activation height.
pub const UPGRADE_PENDING_PREFIX: &[u8] = b"upgrade::pending::";

/// State key prefix for the canonical registry of active services.
pub const UPGRADE_ACTIVE_SERVICE_PREFIX: &[u8] = b"upgrade::active::";

/// State key prefix for storing service manifests, keyed by their SHA-256 hash.
pub const UPGRADE_MANIFEST_PREFIX: &[u8] = b"upgrade::manifest::";

/// State key prefix for storing service artifacts, keyed by their SHA-256 hash.
pub const UPGRADE_ARTIFACT_PREFIX: &[u8] = b"upgrade::artifact::";

/// Creates the canonical, queryable key for an active service.
/// The service type name is always converted to lowercase to ensure determinism.
///
/// # Example
/// `active_service_key("IdentityHub")` -> `b"upgrade::active::identityhub"`
pub fn active_service_key<S: AsRef<str>>(service_type: S) -> Vec<u8> {
    let name = service_type.as_ref().to_ascii_lowercase();
    [UPGRADE_ACTIVE_SERVICE_PREFIX, name.as_bytes()].concat()
}

/// The state key for the set of all evidence that has already been processed.
/// Stores a `BTreeSet<[u8; 32]>` of evidence IDs, providing replay protection.
pub const EVIDENCE_REGISTRY_KEY: &[u8] = b"system::penalties::evidence";

/// The state key for the set of quarantined PoA validators.
/// Stores a `BTreeSet<AccountId>`, representing authorities that are temporarily
/// barred from consensus participation.
pub const QUARANTINED_VALIDATORS_KEY: &[u8] = b"system::penalties::quarantined_poa";

// --- Block Timing Keys ---
/// State key for the governance-controlled BlockTimingParams.
pub const BLOCK_TIMING_PARAMS_KEY: &[u8] = b"system::timing::params";
/// State key for the dynamically updated BlockTimingRuntime.
pub const BLOCK_TIMING_RUNTIME_KEY: &[u8] = b"system::timing::runtime";

// --- Identity Hub Keys ---
/// State key prefix for an account's credentials array.
pub const IDENTITY_CREDENTIALS_PREFIX: &[u8] = b"identity::creds::";
/// State key prefix for an account's rotation nonce.
pub const IDENTITY_ROTATION_NONCE_PREFIX: &[u8] = b"identity::nonce::rotation::";
/// State key prefix for indexing credential promotions by block height.
pub const IDENTITY_PROMOTION_INDEX_PREFIX: &[u8] = b"identity::index::promotion::";
/// State key prefix for the AccountId -> libp2p PublicKey mapping.
pub const ACCOUNT_ID_TO_PUBKEY_PREFIX: &[u8] = b"identity::pubkey::";

// --- Protocol Apex Keys ---
/// The state key for the current security epoch (Lazarus Protocol).
/// Used to coordinate the transition back from A-PMFT to A-DMFT.
pub const CURRENT_EPOCH_KEY: &[u8] = b"system::epoch";