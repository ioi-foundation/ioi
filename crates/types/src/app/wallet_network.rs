// Path: crates/types/src/app/wallet_network.rs

use crate::app::action::{ActionTarget, ApprovalToken};
use crate::app::SignatureSuite;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Product surface where a wallet.network action was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum VaultSurface {
    /// Desktop control-plane surface.
    Desktop,
    /// Browser extension bridge surface.
    Extension,
    /// Mobile notifier/approver surface.
    Mobile,
}

/// Legacy wallet curve used for owner anchoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWalletCurve {
    /// Legacy ECDSA curve used by Ethereum-style EOAs.
    Secp256k1,
    /// EdDSA curve used by modern wallets/keys.
    Ed25519,
}

/// Post-quantum suite used by the manager layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum VaultPqSuite {
    /// ML-DSA-44 (Dilithium class) signature suite.
    MlDsa44,
    /// ML-KEM-768 (Kyber class) key encapsulation suite.
    Kyber768,
}

/// External owner wallet anchor linked to a local Vault identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct OwnerAnchor {
    /// Network namespace (for example: "ethereum:mainnet").
    pub network: String,
    /// Owner address/public account identifier.
    pub address: String,
    /// Owner key curve.
    pub curve: OwnerWalletCurve,
    /// Signed message proving ownership linkage.
    pub link_signature: Vec<u8>,
    /// Signature suite used for the linkage proof.
    pub signature_suite: SignatureSuite,
    /// UNIX timestamp (ms) when linked.
    pub linked_at_ms: u64,
}

/// Hybrid identity representing the agency manager layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct VaultIdentity {
    /// Stable vault identity id.
    pub vault_id: [u8; 32],
    /// Anchored owner wallets.
    #[serde(default)]
    pub owner_anchors: Vec<OwnerAnchor>,
    /// PQ signature suite used for manager control messages.
    pub pq_signing_suite: VaultPqSuite,
    /// PQ KEM suite used for envelope encryption to trusted runtimes.
    pub pq_kem_suite: VaultPqSuite,
    /// PQ signing public key bytes.
    pub pq_signing_public_key: Vec<u8>,
    /// PQ KEM public key bytes.
    pub pq_kem_public_key: Vec<u8>,
    /// Created timestamp.
    pub created_at_ms: u64,
    /// Last updated timestamp.
    pub updated_at_ms: u64,
}

/// Secret category managed by the local vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// API key style bearer credential.
    ApiKey,
    /// User password credential.
    Password,
    /// Short-lived or refresh token credential.
    AccessToken,
    /// X.509 or similar certificate material.
    Certificate,
    /// Custom provider-specific secret category.
    Custom(String),
}

/// Encrypted secret record persisted by the Vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct VaultSecretRecord {
    /// Stable id for the secret.
    pub secret_id: String,
    /// Human-readable alias (for example: "openai", "twitter").
    pub alias: String,
    /// Secret class.
    pub kind: SecretKind,
    /// Ciphertext payload encrypted at rest.
    pub ciphertext: Vec<u8>,
    /// Optional metadata (region/owner/provider labels).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Created timestamp.
    pub created_at_ms: u64,
    /// Optional rotated timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at_ms: Option<u64>,
}

/// Scoped policy rule authored by a human for autonomous execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct VaultPolicyRule {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Human label for UI.
    pub label: String,
    /// Target capability affected by this rule.
    pub target: ActionTarget,
    /// Auto-approve if rule constraints are satisfied.
    pub auto_approve: bool,
    /// Optional value ceiling in micro-USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value_usd_micros: Option<u64>,
    /// Optional TTL for approval/session context in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    /// Optional allowlisted domains for network-capable actions.
    #[serde(default)]
    pub domain_allowlist: Vec<String>,
}

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

/// Guardian attestation evidence supplied during secret release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct GuardianAttestation {
    /// Hash of runtime quote/certificate chain.
    pub quote_hash: [u8; 32],
    /// Runtime measurement hash.
    pub measurement_hash: [u8; 32],
    /// Ephemeral encryption key of guardian.
    pub guardian_ephemeral_public_key: Vec<u8>,
    /// Challenge nonce bound to the secret injection request.
    pub nonce: [u8; 32],
    /// Issued timestamp.
    pub issued_at_ms: u64,
    /// Expiration timestamp.
    pub expires_at_ms: u64,
}

/// Request to release a secret into an attested runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionRequest {
    /// Deterministic request id.
    pub request_id: [u8; 32],
    /// Session receiving secret material.
    pub session_id: [u8; 32],
    /// Logical agent id.
    pub agent_id: String,
    /// Alias of secret requested.
    pub secret_alias: String,
    /// Action target/context requiring this secret.
    pub target: ActionTarget,
    /// Challenge nonce for attestation binding.
    pub attestation_nonce: [u8; 32],
    /// Requested timestamp.
    pub requested_at_ms: u64,
}

/// Secret injection request bundle with attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionRequestRecord {
    /// Requested secret handoff context.
    pub request: SecretInjectionRequest,
    /// Guardian attestation bound to the request nonce/challenge.
    pub attestation: GuardianAttestation,
}

/// Sealed secret payload encrypted for a specific guardian runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionEnvelope {
    /// Encryption scheme used for the sealed payload.
    pub algorithm: String,
    /// Ciphertext encrypted to guardian ephemeral key.
    pub ciphertext: Vec<u8>,
    /// Optional AAD/metadata bytes.
    #[serde(default)]
    pub aad: Vec<u8>,
}

/// Granted secret handoff material bound to request + attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionGrant {
    /// Request id being fulfilled.
    pub request_id: [u8; 32],
    /// Secret id released.
    pub secret_id: String,
    /// Sealed payload for guardian.
    pub envelope: SecretInjectionEnvelope,
    /// Issued timestamp.
    pub issued_at_ms: u64,
    /// Expiration timestamp.
    pub expires_at_ms: u64,
}

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
