// Path: crates/types/src/app/wallet_network/session_channel.rs

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Packet ordering mode for a wallet-network session channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SessionChannelOrdering {
    /// Enforce strict in-order packet processing by sequence number.
    Ordered,
    /// Allow out-of-order packet processing with replay protection.
    Unordered,
}

/// Execution mode negotiated for a session channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SessionChannelMode {
    /// Remote instance requests operations; local vault/guardian executes with local secrets.
    RemoteRequestLocalExecution,
    /// Local vault authorizes bounded operations for attested remote execution.
    AttestedRemoteExecution,
}

/// Lifecycle state for a session channel handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SessionChannelState {
    /// Open-init was accepted and persisted.
    OpenInit,
    /// Open-try was accepted and attestation response captured.
    OpenTry,
    /// Open-ack was accepted and awaiting final confirm.
    OpenAck,
    /// Channel handshake completed and channel is active.
    Open,
    /// Channel is closed and no new leases/packets are allowed.
    Closed,
}

/// Reason code for channel closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SessionChannelCloseReason {
    /// Channel naturally expired by TTL.
    Expired,
    /// Channel was revoked by policy or security action.
    Revoked,
    /// Global panic-stop closed the channel.
    Panic,
    /// Policy changed incompatibly and required channel replacement.
    PolicyChange,
    /// Manual operator/user initiated close.
    Manual,
}

/// Delegation constraints negotiated at channel open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelDelegationRules {
    /// Maximum allowed sub-grant delegation depth.
    pub max_depth: u8,
    /// Whether re-delegation is permitted at all.
    pub can_redelegate: bool,
    /// Optional issuance budget for downstream grants/leases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_budget: Option<u32>,
}

/// Immutable channel envelope binding policy, capability, and expiry constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelEnvelope {
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Local control-plane identity fingerprint.
    pub lc_id: [u8; 32],
    /// Remote kernel identity fingerprint.
    pub rc_id: [u8; 32],
    /// Packet ordering contract for this channel.
    pub ordering: SessionChannelOrdering,
    /// Execution mode for this channel.
    pub mode: SessionChannelMode,
    /// Policy commitment hash bound to this channel.
    pub policy_hash: [u8; 32],
    /// Monotonic policy version.
    pub policy_version: u64,
    /// Parent root-grant/session authority identifier.
    pub root_grant_id: [u8; 32],
    /// Capability allowlist negotiated for this channel.
    #[serde(default)]
    pub capability_set: Vec<String>,
    /// Canonical constraint key-value map for capability arguments.
    #[serde(default)]
    pub constraints: BTreeMap<String, String>,
    /// Delegation rules for sub-grant issuance on this channel.
    pub delegation_rules: SessionChannelDelegationRules,
    /// Minimum valid revocation epoch for artifacts used on this channel.
    pub revocation_epoch: u64,
    /// Absolute expiry of this channel.
    pub expires_at_ms: u64,
}

/// Open-init message persisted by wallet.network before remote acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelOpenInit {
    /// Proposed immutable channel envelope.
    pub envelope: SessionChannelEnvelope,
    /// Local classical KEM ephemeral public key bytes.
    pub lc_kem_ephemeral_pub_classical: Vec<u8>,
    /// Local PQ KEM ephemeral public key bytes.
    pub lc_kem_ephemeral_pub_pq: Vec<u8>,
    /// Local handshake nonce.
    pub nonce_lc: [u8; 32],
    /// Hybrid signature over the canonical open-init payload.
    pub sig_hybrid_lc: Vec<u8>,
}

/// Open-try response persisted after attestation check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelOpenTry {
    /// Channel identifier being negotiated.
    pub channel_id: [u8; 32],
    /// Hash commitment of the immutable channel envelope.
    pub envelope_hash: [u8; 32],
    /// Remote attestation evidence blob.
    pub rc_attestation_evidence: Vec<u8>,
    /// Remote attestation bound public identity material.
    pub rc_attestation_pub: Vec<u8>,
    /// Remote classical KEM ephemeral public key bytes.
    pub rc_kem_ephemeral_pub_classical: Vec<u8>,
    /// Remote PQ KEM encapsulation ciphertext.
    pub rc_kem_ciphertext_pq: Vec<u8>,
    /// Remote handshake nonce.
    pub nonce_rc: [u8; 32],
    /// Hybrid signature over the canonical open-try payload.
    pub sig_hybrid_rc: Vec<u8>,
}

/// Open-ack message proving local side accepted the remote try state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelOpenAck {
    /// Channel identifier being acknowledged.
    pub channel_id: [u8; 32],
    /// Hash commitment of the immutable channel envelope.
    pub envelope_hash: [u8; 32],
    /// Second local handshake nonce.
    pub nonce_lc2: [u8; 32],
    /// Hybrid signature over the canonical open-ack payload.
    pub sig_hybrid_lc: Vec<u8>,
}

/// Open-confirm message marking a channel as active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelOpenConfirm {
    /// Channel identifier being confirmed.
    pub channel_id: [u8; 32],
    /// Hash commitment of the immutable channel envelope.
    pub envelope_hash: [u8; 32],
    /// Second remote handshake nonce.
    pub nonce_rc2: [u8; 32],
    /// Hybrid signature over the canonical open-confirm payload.
    pub sig_hybrid_rc: Vec<u8>,
}

/// Authenticated channel close request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelClose {
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Closure reason code.
    pub reason: SessionChannelCloseReason,
    /// Final sequence observed/committed at close.
    pub final_seq: u64,
    /// Closure timestamp.
    pub closed_at_ms: u64,
    /// Hybrid signature over the canonical close payload.
    pub sig_hybrid_sender: Vec<u8>,
}

/// Persisted aggregate state for a session channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelRecord {
    /// Immutable channel envelope.
    pub envelope: SessionChannelEnvelope,
    /// Current channel lifecycle state.
    pub state: SessionChannelState,
    /// Hash commitment of `envelope`.
    pub envelope_hash: [u8; 32],
    /// Timestamp when channel reached `Open`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_at_ms: Option<u64>,
    /// Timestamp when channel reached `Closed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at_ms: Option<u64>,
    /// Last committed packet/receipt sequence for this channel.
    pub last_seq: u64,
    /// Optional final close reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<SessionChannelCloseReason>,
}

/// Persisted KEM/key-derivation state for a session channel handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SessionChannelKeyState {
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Hash commitment of the immutable channel envelope.
    pub envelope_hash: [u8; 32],
    /// Transcript construction version for deterministic derivation.
    pub transcript_version: u16,
    /// Rolling transcript hash over open_init/open_try/open_ack/open_confirm KEM material.
    pub kem_transcript_hash: [u8; 32],
    /// Hash of local classical KEM ephemeral public key.
    pub lc_kem_ephemeral_pub_classical_hash: [u8; 32],
    /// Hash of local PQ KEM ephemeral public key.
    pub lc_kem_ephemeral_pub_pq_hash: [u8; 32],
    /// Hash of remote classical KEM ephemeral public key (set at open_try).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rc_kem_ephemeral_pub_classical_hash: Option<[u8; 32]>,
    /// Hash of remote PQ KEM ciphertext (set at open_try).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rc_kem_ciphertext_pq_hash: Option<[u8; 32]>,
    /// Local handshake nonce from open_init.
    pub nonce_lc: [u8; 32],
    /// Remote handshake nonce from open_try.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_rc: Option<[u8; 32]>,
    /// Local second handshake nonce from open_ack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_lc2: Option<[u8; 32]>,
    /// Remote second handshake nonce from open_confirm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_rc2: Option<[u8; 32]>,
    /// Derived channel secret identifier hash (set at open_confirm).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_channel_secret_hash: Option<[u8; 32]>,
    /// Key epoch for future rotations/rekeys.
    pub key_epoch: u64,
    /// True when channel key derivation completed.
    pub ready: bool,
    /// Last state update timestamp.
    pub updated_at_ms: u64,
}
