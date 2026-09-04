//! Wire objects for online Query-Unanimity Verification (`aft_quv_v0`).
//!
//! These bytes are transport and audit material. They are not a portable
//! finality receipt and cannot authorize a later offline executor.

use super::AccountId;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Stable profile identifier.
pub const QUV_PROFILE_V0: &str = "aft_quv_v0";
/// Canonical SHA-256 commitment.
pub type QuvHash = [u8; 32];
/// Fresh verifier session nonce.
pub type QuvNonce = [u8; 32];

/// Rooted authority rule for one slot.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum QuvAuthorityModeV0 {
    /// Exactly one rooted owner may authorize candidates.
    Owned,
    /// Independently valid candidates race for each member's first winner.
    Unowned,
}

/// Exact rooted slot identity. Every field is load-bearing replay protection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct QuvSlotV0 {
    /// Commitment to the exact configured membership and keys.
    pub configuration_root: QuvHash,
    /// Commitment to the independently provisioned domain authority and
    /// complete known-synchrony/continuation bounds.
    pub policy_root: QuvHash,
    /// Rooted network identity.
    pub network_id: QuvHash,
    /// Commitment to the effect conflict domain.
    pub domain_id: QuvHash,
    /// One-based position in that domain.
    pub slot: u64,
    /// Exact prior accepted candidate or rooted initial predecessor.
    pub predecessor: QuvHash,
    /// Authority rule used by member and executor verification.
    pub authority_mode: QuvAuthorityModeV0,
}

/// Complete rooted candidate pushed to every configured member.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct QuvCandidateV0 {
    /// Exact slot context.
    pub slot: QuvSlotV0,
    /// Commitment to the effect manifest or ordered payload.
    pub payload_hash: QuvHash,
    /// Rooted authority signing this candidate.
    pub authorizer: AccountId,
    /// Domain-separated authority signature.
    pub authority_signature: Vec<u8>,
}

/// Fresh online write-back/query request.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct QuvPushQueryV0 {
    /// Fresh nonce binding this executor operation.
    pub verifier_nonce: QuvNonce,
    /// Candidate written before any member reply is exposed.
    pub candidate: QuvCandidateV0,
}

/// Signed complete snapshot returned after durable write-back.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct QuvReplyV0 {
    /// Nonce of the requesting executor operation.
    pub verifier_nonce: QuvNonce,
    /// Rooted member producing the reply.
    pub member: AccountId,
    /// Exact rooted slot context.
    pub slot: QuvSlotV0,
    /// Hash of the candidate pushed by this operation.
    pub candidate_hash: QuvHash,
    /// Commitment to the complete ordered snapshot.
    pub snapshot_hash: QuvHash,
    /// Complete grow-only candidate sequence for the slot.
    pub complete_snapshot: Vec<QuvCandidateV0>,
    /// Member signature produced only after durable write-back.
    pub signature: Vec<u8>,
}
