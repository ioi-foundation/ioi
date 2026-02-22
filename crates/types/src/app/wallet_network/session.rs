// Path: crates/types/src/app/wallet_network/session.rs

use crate::app::action::ActionTarget;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bounded delegation scope for an issued session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionScope {
    /// Expiration timestamp for the session.
    pub expires_at_ms: u64,
    /// Optional max number of actions allowed in this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u32>,
    /// Optional spend cap in micro-USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_spend_usd_micros: Option<u64>,
    /// Allowed action targets for this session.
    #[serde(default)]
    pub action_allowlist: Vec<ActionTarget>,
    /// Optional allowed domains for net/web actions.
    #[serde(default)]
    pub domain_allowlist: Vec<String>,
}

/// Issued delegated authority for a specific agent runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionGrant {
    /// Deterministic session id.
    pub session_id: [u8; 32],
    /// Owning vault identity id.
    pub vault_id: [u8; 32],
    /// Logical agent identifier.
    pub agent_id: String,
    /// User/developer reason text.
    pub purpose: String,
    /// Scope constraints.
    pub scope: SessionScope,
    /// Guardian/runtime encryption key for secure bundle handoff.
    pub guardian_ephemeral_public_key: Vec<u8>,
    /// Created timestamp.
    pub issued_at_ms: u64,
}

/// Lease mode for authorization lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SessionLeaseMode {
    /// One-shot authorization for a single action.
    OneShot,
    /// Multi-action lease with bounded TTL.
    Lease,
}

/// Temporary revocable authorization minted for a session channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionLease {
    /// Lease identifier.
    pub lease_id: [u8; 32],
    /// Parent channel identifier.
    pub channel_id: [u8; 32],
    /// Issuer identity fingerprint.
    pub issuer_id: [u8; 32],
    /// Subject identity fingerprint.
    pub subject_id: [u8; 32],
    /// Policy commitment hash for this lease.
    pub policy_hash: [u8; 32],
    /// Parent grant identifier.
    pub grant_id: [u8; 32],
    /// Capability subset authorized by this lease.
    #[serde(default)]
    pub capability_subset: Vec<String>,
    /// Constraint subset authorized by this lease.
    #[serde(default)]
    pub constraints_subset: BTreeMap<String, String>,
    /// Lease usage mode.
    pub mode: SessionLeaseMode,
    /// Lease expiry timestamp.
    pub expires_at_ms: u64,
    /// Minimum valid revocation epoch.
    pub revocation_epoch: u64,
    /// Intended audience identity fingerprint.
    pub audience: [u8; 32],
    /// Lease nonce for replay protection.
    pub nonce: [u8; 32],
    /// Monotonic issuance counter.
    pub counter: u64,
    /// Issuance timestamp.
    pub issued_at_ms: u64,
    /// Hybrid signature over lease payload.
    pub sig_hybrid_lc: Vec<u8>,
}

/// Direction of a receipt commitment batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SessionReceiptCommitDirection {
    /// Receipts committed from local control plane toward remote executor.
    LocalToRemote,
    /// Receipts committed from remote executor toward local control plane.
    RemoteToLocal,
}

/// Batched receipt commitment checkpoint for a channel sequence range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionReceiptCommit {
    /// Commitment identifier.
    pub commit_id: [u8; 32],
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Batch flow direction.
    pub direction: SessionReceiptCommitDirection,
    /// First sequence number in the committed batch.
    pub start_seq: u64,
    /// Last sequence number in the committed batch.
    pub end_seq: u64,
    /// Merkle root over canonical receipt leaves.
    pub merkle_root: [u8; 32],
    /// Commit timestamp.
    pub committed_at_ms: u64,
    /// Signer identity fingerprint.
    pub signer_id: [u8; 32],
    /// Hybrid signature over commit payload.
    pub sig_hybrid_sender: Vec<u8>,
}
