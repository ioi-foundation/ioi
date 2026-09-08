//! Wire objects for online Query-Unanimity Verification (`aft_quv_v0`).
//!
//! These bytes are transport and audit material. They are not a portable
//! finality receipt and cannot authorize a later offline executor.

use super::{AccountId, QuorumCertificate, ValidatorSetV1};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Stable profile identifier.
pub const QUV_PROFILE_V0: &str = "aft_quv_v0";
/// Production v0 admission bound. The isolated runtime lane reserves two
/// events per configured member: one request and one reply.
pub const QUV_MAX_CONFIGURED_MEMBERS_V0: usize = 1_024;
/// Absolute syntax ceiling for a rooted finite Fixed-domain slot horizon.
pub const QUV_MAX_AUTHORITY_SLOTS_V0: u32 = 1_000_000;
/// Normal pending-record count in the rooted shared-outbox profile.
pub const QUV_OUTBOX_NORMAL_RECORDS_PER_RECIPIENT_V0: usize = 1_024;
/// One request lane and one reply lane are reserved per rooted recipient.
pub const QUV_OUTBOX_RESERVED_RECORDS_PER_RECIPIENT_V0: usize = 2;
/// Rooted shared-outbox profile: normal traffic cannot spend the QUV reserve.
/// These are encoded-payload budgets, not physical allocation guarantees.
pub const QUV_OUTBOX_NORMAL_BYTES_PER_RECIPIENT_V0: u64 = 16 * 1024 * 1024;
/// Maximum encoded QUV transport payload under the rooted profile.
pub const QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0: u64 = 16 * 1024;
/// Separate encoded capacity for one outgoing request and one reply per account.
pub const QUV_OUTBOX_RESERVED_BYTES_PER_RECIPIENT_V0: u64 = 2 * QUV_OUTBOX_MAX_PAYLOAD_BYTES_V0;
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

/// Independently provisioned starting rule, committed by the domain policy.
/// This describes bootstrap; it is not evidence that any candidate was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuvDomainBootstrapV0 {
    /// Exact initial slot and predecessor for a fixed domain history.
    Fixed {
        /// First slot permitted by the provisioned domain history.
        initial_slot: u64,
        /// Independently provisioned predecessor of that first slot.
        predecessor: QuvHash,
    },
    /// The handoff slot is its activation height. Its predecessor must be
    /// derived from the independently verified old-root boundary, never from
    /// an incoming candidate alone. This does not bootstrap effect domains.
    HandoffBoundary {
        /// Successor activation height and exact handoff slot.
        activation_height: u64,
    },
}

impl QuvDomainBootstrapV0 {
    /// A finite rooted horizon must fit the slot number space without wrapping.
    pub fn is_valid_authority_slots(self, slots: u32) -> bool {
        slots > 0
            && slots <= QUV_MAX_AUTHORITY_SLOTS_V0
            && match self {
                Self::Fixed { initial_slot, .. } => {
                    initial_slot.checked_add(u64::from(slots) - 1).is_some()
                }
                Self::HandoffBoundary { .. } => true,
            }
    }

    /// Check bootstrap syntax and its compatibility with the authority rule.
    pub fn is_valid_for(self, mode: QuvAuthorityModeV0) -> bool {
        match self {
            Self::Fixed {
                initial_slot,
                predecessor,
            } => initial_slot > 0 && predecessor != [0; 32],
            Self::HandoffBoundary { activation_height } => {
                activation_height > 1 && mode == QuvAuthorityModeV0::Owned
            }
        }
    }
}

/// Rooted preparation budget. These limits are a service contract to qualify,
/// not evidence that a worker meets them or that any peer has advanced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuvPreparationPolicyV0 {
    /// Each member performs its own live preparation query for Fixed histories.
    Independent {
        /// Finite per-slot attempt budget, to be durably reserved before query.
        max_attempts_per_slot: u16,
        /// Active attempt service from exclusive operation admission through
        /// reservation, live query and head commit. Readiness must also cover
        /// selection and queue waiting; this limit alone does not bound them.
        service_millis: u64,
        /// Local child-readiness delay; complete scheduling costs must fit here.
        readiness_millis: u64,
    },
    /// One-shot handoff domains use their dedicated live install coordinator.
    OneShot,
}

impl QuvPreparationPolicyV0 {
    /// Durable reservations permitted in one slot; handoff uses no worker.
    pub fn max_attempts_per_slot(self) -> u16 {
        match self {
            Self::Independent {
                max_attempts_per_slot,
                ..
            } => max_attempts_per_slot,
            Self::OneShot => 0,
        }
    }

    /// All-operation active budget, independently rooted and never inferred.
    /// A preparation attempt may use a tighter cap, but not a wider one.
    pub fn is_valid_operation_service(
        self,
        operation_service_millis: u64,
        delta_rt_millis: u64,
        continuation_millis: u64,
    ) -> bool {
        operation_service_millis > delta_rt_millis
            && delta_rt_millis
                .checked_add(continuation_millis)
                .is_some_and(|limit| operation_service_millis <= limit)
            && match self {
                Self::Independent { service_millis, .. } => {
                    service_millis <= operation_service_millis
                }
                Self::OneShot => true,
            }
    }

    /// Validate local syntax and bootstrap compatibility. This does not qualify
    /// queue fairness, network/storage costs, or a cross-domain service bound.
    pub fn is_valid_for(
        self,
        bootstrap: QuvDomainBootstrapV0,
        delta_rt_millis: u64,
        continuation_millis: u64,
    ) -> bool {
        match (self, bootstrap) {
            (
                Self::Independent {
                    max_attempts_per_slot,
                    service_millis,
                    readiness_millis,
                },
                QuvDomainBootstrapV0::Fixed { .. },
            ) => {
                max_attempts_per_slot > 0
                    && service_millis > delta_rt_millis
                    && delta_rt_millis
                        .checked_add(continuation_millis)
                        .is_some_and(|limit| service_millis <= limit)
                    && service_millis
                        .checked_mul(u64::from(max_attempts_per_slot))
                        .is_some_and(|minimum| readiness_millis >= minimum)
            }
            (Self::OneShot, QuvDomainBootstrapV0::HandoffBoundary { .. }) => true,
            _ => false,
        }
    }
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

/// Signed complete retained conflict summary after durable write-back.
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
    /// First two distinct candidates in durable linearization order. The field
    /// name is retained on the wire; v4 policy roots bind summary semantics.
    /// Saturation preserves owned conflict and the unowned first winner.
    pub complete_snapshot: Vec<QuvCandidateV0>,
    /// Member signature produced only after durable write-back.
    pub signature: Vec<u8>,
}

/// Raw evidence retained for audit after an online acceptance. The elapsed
/// time is an executor claim and cannot be authenticated for an offline
/// verifier, so this object is deliberately non-authorizing.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct QuvAcceptedAuditEvidenceV0 {
    /// Exact request executed by the relying process.
    pub request: QuvPushQueryV0,
    /// Exact rooted membership the process says it contacted.
    pub configured_members: Vec<AccountId>,
    /// All structurally and cryptographically valid replies used at decision.
    pub valid_replies: Vec<QuvReplyV0>,
    /// Monotonic milliseconds from operation admission to each corresponding
    /// entry in `valid_replies`. These executor-local observations are useful
    /// for qualification, but remain non-authorizing and non-portable.
    pub valid_reply_elapsed_millis: Vec<u64>,
    /// Provisioned wait interval.
    pub decision_interval_millis: u64,
    /// Monotonic elapsed time observed by the executor.
    pub observed_elapsed_millis: u64,
}

/// Complete state transferred by a live Q-EA7 old-root authorization. The
/// successor set is embedded so activation cannot substitute membership after
/// the online operation. These bytes remain non-authorizing without the
/// process-local QUV continuation that installed them.
#[derive(Debug, Clone, Encode, Decode)]
pub struct QuvConfigurationHandoffV0 {
    /// Rooted network identity shared by both configurations.
    pub network_id: QuvHash,
    /// Exact old configuration queried by every correct successor.
    pub old_configuration_root: QuvHash,
    /// Complete canonical successor membership and keys.
    pub successor_set: ValidatorSetV1,
    /// First height at which the successor may act.
    pub activation_height: u64,
    /// Last height at which the old QUV authority is live.
    pub old_authority_expiry_height: u64,
    /// Canonical rooted initial predecessor derived from the exact final
    /// old-root state. A candidate source cannot nominate this value.
    pub predecessor_candidate_hash: QuvHash,
    /// Final old-root state height installed by the successor.
    pub state_height: u64,
    /// Block identity carrying the installed state.
    pub state_block_hash: QuvHash,
    /// Complete application state-root bytes for that block.
    pub state_root: Vec<u8>,
    /// Old-root quorum certificate for the exact installed boundary. This is
    /// ordering evidence needed to extend the chain after activation; it does
    /// not replace the fresh online QUV authorization of successor authority.
    pub boundary_qc: QuorumCertificate,
}

/// Independently provisioned Q-EA7 source object. The candidate carries the
/// old-member authority signature; the payload supplies the exact successor
/// and state bytes committed by that signature. Loading this object grants no
/// authority until a local online QUV operation accepts and installs it.
#[derive(Debug, Clone, Encode, Decode)]
pub struct QuvConfigurationHandoffEnvelopeV0 {
    /// Exact successor/state payload committed by `candidate.payload_hash`.
    pub handoff: QuvConfigurationHandoffV0,
    /// Old-root owner-signed candidate that must be pushed online.
    pub candidate: QuvCandidateV0,
}
