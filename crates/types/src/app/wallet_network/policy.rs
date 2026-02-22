// Path: crates/types/src/app/wallet_network/policy.rs

use super::vault::VaultSurface;
use crate::app::action::{ActionTarget, ApprovalToken};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Policy interception context surfaced to wallet.network for HITL decisioning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletInterceptionContext {
    /// Optional session id associated with intercepted action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<[u8; 32]>,
    /// Hash of blocked action request.
    pub request_hash: [u8; 32],
    /// Action target being evaluated.
    pub target: ActionTarget,
    /// Optional value estimate in micro-USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_usd_micros: Option<u64>,
    /// Interception reason text.
    pub reason: String,
    /// Intercepted timestamp.
    pub intercepted_at_ms: u64,
}

/// Decision outcome category for wallet-network gate handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum WalletApprovalDecisionKind {
    /// Approved automatically by active policy.
    AutoApproved,
    /// Approved via explicit human step-up.
    ApprovedByHuman,
    /// Explicitly denied by a human.
    DeniedByHuman,
    /// Deferred until a human decision is provided.
    RequiresHumanReview,
}

/// Approval decision emitted by the wallet.network policy surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct WalletApprovalDecision {
    /// Interception context reviewed.
    pub interception: WalletInterceptionContext,
    /// Decision result.
    pub decision: WalletApprovalDecisionKind,
    /// Optional approval token when action is approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<ApprovalToken>,
    /// Surface that produced this decision.
    pub surface: VaultSurface,
    /// Decision timestamp.
    pub decided_at_ms: u64,
}

/// Canonical audit event types for wallet.network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum VaultAuditEventKind {
    /// A new vault identity was created.
    IdentityCreated,
    /// An owner wallet anchor was linked/updated.
    OwnerLinked,
    /// A secret record was created.
    SecretStored,
    /// A secret record was rotated or replaced.
    SecretRotated,
    /// A policy rule was inserted or updated.
    PolicyUpserted,
    /// A session grant was issued.
    SessionIssued,
    /// A secret injection grant was issued.
    SecretInjectionGranted,
    /// A secret injection request and attestation were recorded.
    SecretInjectionRequested,
    /// A channel open-init payload was accepted.
    ChannelOpenInitAccepted,
    /// A channel open-try payload was accepted.
    ChannelOpenTryAccepted,
    /// A channel completed handshake and became active.
    ChannelOpened,
    /// A channel was closed.
    ChannelClosed,
    /// A session lease was issued.
    LeaseIssued,
    /// A channel receipt batch commitment was recorded.
    ReceiptCommitted,
    /// A firewall interception was recorded.
    InterceptionObserved,
    /// A policy approval decision was recorded.
    ApprovalDecided,
    /// An emergency stop/revocation event occurred.
    EmergencyStop,
    /// A connector operation executed under lease authority.
    ConnectorOperationExecuted,
}

/// Immutable audit record emitted by the wallet vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct VaultAuditEvent {
    /// Stable audit event id.
    pub event_id: [u8; 32],
    /// Audit category.
    pub kind: VaultAuditEventKind,
    /// Event timestamp.
    pub timestamp_ms: u64,
    /// Event hash commitment.
    pub event_hash: [u8; 32],
    /// String metadata for UI/reporting.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}
