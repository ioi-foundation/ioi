use crate::app::{AccountId, SignatureSuite};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// State key prefix for registered guardian committee manifests.
pub const GUARDIAN_REGISTRY_COMMITTEE_PREFIX: &[u8] = b"guardian::committee::";
/// State key prefix for guardian measurement allowlists.
pub const GUARDIAN_REGISTRY_MEASUREMENT_PREFIX: &[u8] = b"guardian::measurement::";
/// State key prefix for anchored guardian transparency checkpoints.
pub const GUARDIAN_REGISTRY_CHECKPOINT_PREFIX: &[u8] = b"guardian::checkpoint::";
/// State key prefix for registered guardian transparency-log descriptors.
pub const GUARDIAN_REGISTRY_LOG_PREFIX: &[u8] = b"guardian::log::";
/// State key prefix for persisted guardian equivocation proofs.
pub const GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX: &[u8] = b"guardian::equivocation::";
/// State key prefix for registered experimental witness committee manifests.
pub const GUARDIAN_REGISTRY_WITNESS_PREFIX: &[u8] = b"guardian::witness::";
/// State key prefix for active witness committee sets by epoch.
pub const GUARDIAN_REGISTRY_WITNESS_SET_PREFIX: &[u8] = b"guardian::witness_set::";
/// State key prefix for deterministic witness assignment seeds by epoch.
pub const GUARDIAN_REGISTRY_WITNESS_SEED_PREFIX: &[u8] = b"guardian::witness_seed::";
/// State key prefix for persisted witness fault evidence.
pub const GUARDIAN_REGISTRY_WITNESS_FAULT_PREFIX: &[u8] = b"guardian::witness_fault::";

/// Builds the canonical state key for a guardian committee manifest hash.
pub fn guardian_registry_committee_key(manifest_hash: &[u8; 32]) -> Vec<u8> {
    [GUARDIAN_REGISTRY_COMMITTEE_PREFIX, manifest_hash.as_ref()].concat()
}

/// Builds the canonical state key for an experimental witness committee manifest hash.
pub fn guardian_registry_witness_key(manifest_hash: &[u8; 32]) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_PREFIX, manifest_hash.as_ref()].concat()
}

/// Builds the canonical state key for the active witness committee set of an epoch.
pub fn guardian_registry_witness_set_key(epoch: u64) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_SET_PREFIX, &epoch.to_be_bytes()].concat()
}

/// Builds the canonical state key for the deterministic witness assignment seed of an epoch.
pub fn guardian_registry_witness_seed_key(epoch: u64) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_SEED_PREFIX, &epoch.to_be_bytes()].concat()
}

/// Builds the canonical state key for witness fault evidence.
pub fn guardian_registry_witness_fault_key(evidence_id: &[u8; 32]) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_FAULT_PREFIX, evidence_id.as_ref()].concat()
}

/// Builds the canonical state key for an anchored transparency checkpoint.
pub fn guardian_registry_checkpoint_key(log_id: &str) -> Vec<u8> {
    [GUARDIAN_REGISTRY_CHECKPOINT_PREFIX, log_id.as_bytes()].concat()
}

/// Builds the canonical state key for a registered transparency-log descriptor.
pub fn guardian_registry_log_key(log_id: &str) -> Vec<u8> {
    [GUARDIAN_REGISTRY_LOG_PREFIX, log_id.as_bytes()].concat()
}

/// Deterministically derives the assigned witness committee for a slot.
pub fn derive_guardian_witness_assignment(
    seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    producer_account_id: AccountId,
    height: u64,
    view: u64,
    reassignment_depth: u8,
) -> Result<GuardianWitnessAssignment, String> {
    if seed.epoch != witness_set.epoch {
        return Err("witness epoch seed and active witness set epoch mismatch".into());
    }
    if witness_set.manifest_hashes.is_empty() {
        return Err("no active witness committees registered for epoch".into());
    }
    if reassignment_depth > seed.max_reassignment_depth {
        return Err(format!(
            "witness reassignment depth {} exceeds configured maximum {}",
            reassignment_depth, seed.max_reassignment_depth
        ));
    }

    let mut material = Vec::with_capacity(32 + 32 + 8 + 8 + 1);
    material.extend_from_slice(&seed.seed);
    material.extend_from_slice(producer_account_id.as_ref());
    material.extend_from_slice(&height.to_be_bytes());
    material.extend_from_slice(&view.to_be_bytes());
    material.push(reassignment_depth);
    let digest = DcryptSha256::digest(&material).map_err(|e| e.to_string())?;
    let slot = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .map_err(|_| "invalid witness-assignment digest".to_string())?,
    );
    let assigned_index = usize::try_from(slot % (witness_set.manifest_hashes.len() as u64))
        .map_err(|_| "witness assignment index conversion failed".to_string())?;

    Ok(GuardianWitnessAssignment {
        epoch: seed.epoch,
        producer_account_id,
        height,
        view,
        reassignment_depth,
        manifest_hash: witness_set.manifest_hashes[assigned_index],
        checkpoint_interval_blocks: witness_set.checkpoint_interval_blocks,
    })
}

/// Deployment profile for guardianized signing and egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum GuardianProductionMode {
    /// Development profile with permissive local fallbacks.
    Development,
    /// Compatibility profile for staged migrations.
    #[default]
    Compatibility,
    /// Production profile with hardware-backed key authority requirements.
    Production,
}

/// Backend used to resolve a signing or secret authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyAuthorityKind {
    /// Development-only in-memory secret material.
    #[default]
    DevMemory,
    /// TPM2-backed signing or unseal flow.
    Tpm2,
    /// PKCS#11 / HSM backed flow.
    Pkcs11,
    /// Cloud KMS backed flow.
    CloudKms,
}

/// Resolved authority handle used by guardianized runtimes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct KeyAuthorityDescriptor {
    /// The backend used for the authority.
    pub kind: KeyAuthorityKind,
    /// Logical key or secret identifier.
    pub key_id: String,
    /// Optional backend endpoint or URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional backend-specific metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Declares a single guardian committee member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianCommitteeMember {
    /// Stable member identifier.
    pub member_id: String,
    /// Public key suite used by this member for quorum signatures.
    pub signature_suite: SignatureSuite,
    /// Full public key bytes.
    #[serde(default)]
    pub public_key: Vec<u8>,
    /// Optional routable endpoint for remote committee RPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional provider label for diversity checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Optional region label for diversity checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional host class label for diversity checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_class: Option<String>,
    /// Optional root authority class expected for this member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_authority_kind: Option<KeyAuthorityKind>,
}

/// Immutable manifest describing a validator's guardian committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianCommitteeManifest {
    /// Validator identity this committee protects.
    pub validator_account_id: AccountId,
    /// Committee epoch.
    pub epoch: u64,
    /// Threshold required for a valid certificate.
    pub threshold: u16,
    /// Members participating in the committee.
    #[serde(default)]
    pub members: Vec<GuardianCommitteeMember>,
    /// Measurement profile root accepted for this epoch.
    pub measurement_profile_root: [u8; 32],
    /// Policy hash constraining committee behavior.
    pub policy_hash: [u8; 32],
    /// Transparency log identifier used by this committee.
    #[serde(default)]
    pub transparency_log_id: String,
}

/// On-chain allowlist of accepted runtime measurement roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianMeasurementProfile {
    /// Stable profile identifier.
    pub profile_id: String,
    /// Measurement roots accepted for this profile.
    #[serde(default)]
    pub allowed_measurement_roots: Vec<[u8; 32]>,
    /// Policy hash associated with the profile.
    pub policy_hash: [u8; 32],
}

/// Signed checkpoint published by the guardian witness log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianTransparencyLogDescriptor {
    /// Logical log identifier.
    pub log_id: String,
    /// Signature suite used by the log signer.
    pub signature_suite: SignatureSuite,
    /// Encoded public key bytes for checkpoint verification.
    #[serde(default)]
    pub public_key: Vec<u8>,
}

/// Append-only proof material for a signed transparency-log checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianLogProof {
    /// Tree size of the base checkpoint used to derive this proof.
    #[serde(default)]
    pub base_tree_size: u64,
    /// Index of the certified entry within the logical tree.
    #[serde(default)]
    pub leaf_index: u64,
    /// Canonical hash of the certified leaf entry.
    pub leaf_hash: [u8; 32],
    /// Ordered leaf hashes needed to recompute the checkpoint root.
    #[serde(default)]
    pub extension_leaf_hashes: Vec<[u8; 32]>,
}

/// Signed checkpoint published by the guardian witness log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianLogCheckpoint {
    /// Logical log identifier.
    pub log_id: String,
    /// Tree size at this checkpoint.
    pub tree_size: u64,
    /// Merkle root of the append-only log.
    pub root_hash: [u8; 32],
    /// Millisecond timestamp of checkpoint issuance.
    pub timestamp_ms: u64,
    /// Signature over the checkpoint payload.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Append-only proof material for this checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<GuardianLogProof>,
}

/// Immutable manifest describing an external witness committee for research-only nested guardian mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessCommitteeManifest {
    /// Stable witness committee identifier.
    pub committee_id: String,
    /// Committee epoch.
    pub epoch: u64,
    /// Threshold required for a valid witness certificate.
    pub threshold: u16,
    /// Members participating in the witness committee.
    #[serde(default)]
    pub members: Vec<GuardianCommitteeMember>,
    /// Policy hash constraining witness behavior.
    pub policy_hash: [u8; 32],
    /// Transparency log identifier used by this witness committee.
    #[serde(default)]
    pub transparency_log_id: String,
}

/// Active witness set for a specific epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessSet {
    /// Epoch whose witness committees are active.
    pub epoch: u64,
    /// Sorted registered witness manifest hashes active in this epoch.
    #[serde(default)]
    pub manifest_hashes: Vec<[u8; 32]>,
    /// Required checkpoint cadence for witness evidence.
    #[serde(default)]
    pub checkpoint_interval_blocks: u64,
}

/// Deterministic seed used for witness assignment in a specific epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessEpochSeed {
    /// Witness-assignment epoch.
    pub epoch: u64,
    /// Seed committed on-chain for deterministic witness assignment.
    pub seed: [u8; 32],
    /// Required checkpoint cadence for witness evidence.
    #[serde(default)]
    pub checkpoint_interval_blocks: u64,
    /// Maximum number of deterministic witness reassignments permitted.
    #[serde(default)]
    pub max_reassignment_depth: u8,
}

/// Deterministically assigned witness committee for a slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessAssignment {
    /// Assignment epoch.
    pub epoch: u64,
    /// Validator whose slot is being witnessed.
    pub producer_account_id: AccountId,
    /// Block height of the assignment.
    pub height: u64,
    /// Consensus view of the assignment.
    pub view: u64,
    /// Deterministic reassignment depth used to derive the witness committee.
    #[serde(default)]
    pub reassignment_depth: u8,
    /// Assigned witness manifest hash.
    pub manifest_hash: [u8; 32],
    /// Required checkpoint cadence for witness evidence.
    #[serde(default)]
    pub checkpoint_interval_blocks: u64,
}

/// Statement cross-signed by external witness committees in research-only nested guardian mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessStatement {
    /// Validator identity whose slot is being witnessed.
    pub producer_account_id: AccountId,
    /// Block height of the witnessed slot.
    pub height: u64,
    /// Consensus view of the witnessed slot.
    pub view: u64,
    /// Guardian committee manifest hash for the witnessed slot certificate.
    pub guardian_manifest_hash: [u8; 32],
    /// Canonical decision hash of the witnessed guardian certificate.
    pub guardian_decision_hash: [u8; 32],
    /// Monotonic guardian counter bound into the witnessed certificate.
    pub guardian_counter: u64,
    /// Guardian trace root bound into the witnessed certificate.
    pub guardian_trace_hash: [u8; 32],
    /// Guardian runtime measurement root bound into the witnessed certificate.
    pub guardian_measurement_root: [u8; 32],
    /// Witness-log checkpoint root anchoring the guardian certificate when available.
    pub guardian_checkpoint_root: [u8; 32],
}

/// Aggregated witness certificate for research-only nested guardian mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessCertificate {
    /// Hash of the registered witness committee manifest.
    pub manifest_hash: [u8; 32],
    /// Witness committee epoch.
    pub epoch: u64,
    /// Canonical hash of the signed witness statement payload.
    pub statement_hash: [u8; 32],
    /// Bitfield of witness committee members who signed.
    #[serde(default)]
    pub signers_bitfield: Vec<u8>,
    /// Aggregated BLS signature over the witness statement hash.
    #[serde(default)]
    pub aggregated_signature: Vec<u8>,
    /// Deterministic reassignment depth used to derive the assigned witness committee.
    #[serde(default)]
    pub reassignment_depth: u8,
    /// Optional witness-log checkpoint anchoring this witness certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<GuardianLogCheckpoint>,
}

/// Witness-fault classification for research-only nested guardian mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum GuardianWitnessFaultKind {
    /// Conflicting witness certificates were issued for the same slot.
    ConflictingCertificate,
    /// An assigned witness failed to issue a certificate before reassignment.
    Omission,
    /// A witness signed using stale registry or epoch state.
    StaleRegistryParticipation,
    /// The witness certificate or checkpoint is inconsistent with the assigned checkpoint policy.
    CheckpointInconsistency,
}

impl Default for GuardianWitnessFaultKind {
    fn default() -> Self {
        Self::ConflictingCertificate
    }
}

/// Evidence envelope for witness-specific slashing and operator response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessFaultEvidence {
    /// Stable evidence identifier.
    pub evidence_id: [u8; 32],
    /// Type of witnessed fault.
    pub kind: GuardianWitnessFaultKind,
    /// Witness epoch in which the fault occurred.
    pub epoch: u64,
    /// Validator whose slot was impacted.
    pub producer_account_id: AccountId,
    /// Block height of the slot.
    pub height: u64,
    /// Consensus view of the slot.
    pub view: u64,
    /// Witness committee expected for this slot.
    pub expected_manifest_hash: [u8; 32],
    /// Witness committee actually observed, when applicable.
    pub observed_manifest_hash: [u8; 32],
    /// Optional checkpoint root tied to the fault.
    #[serde(default)]
    pub checkpoint_root: [u8; 32],
    /// Optional witness certificate bytes relevant to the evidence.
    #[serde(default)]
    pub witness_certificate: Option<GuardianWitnessCertificate>,
    /// Human-readable operator detail.
    #[serde(default)]
    pub details: String,
}

/// Aggregated committee certificate for a guardian decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianQuorumCertificate {
    /// Hash of the registered committee manifest.
    pub manifest_hash: [u8; 32],
    /// Committee epoch.
    pub epoch: u64,
    /// Canonical hash of the signed decision payload.
    pub decision_hash: [u8; 32],
    /// Monotonic counter for the decision stream.
    pub counter: u64,
    /// Trace root chaining this decision to prior committee history.
    pub trace_hash: [u8; 32],
    /// Runtime measurement root bound to this decision.
    pub measurement_root: [u8; 32],
    /// Bitfield of committee members who signed.
    #[serde(default)]
    pub signers_bitfield: Vec<u8>,
    /// Aggregated BLS signature over the decision hash.
    #[serde(default)]
    pub aggregated_signature: Vec<u8>,
    /// Optional witness-log checkpoint anchoring this decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<GuardianLogCheckpoint>,
    /// Optional external witness committee certificate for research-only nested guardian mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental_witness_certificate: Option<GuardianWitnessCertificate>,
}

/// Result of a guardianized signing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianCertificate {
    /// Compatibility signature bytes for legacy call sites.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Monotonic counter value.
    pub counter: u64,
    /// Trace hash for the signing history.
    pub trace_hash: [u8; 32],
    /// Optional quorum certificate when operating in guardianized mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum: Option<GuardianQuorumCertificate>,
}

/// Domain of a guardianized decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum GuardianDecisionDomain {
    /// Decision to certify a consensus proposal slot.
    ConsensusSlot,
    /// Decision to authorize and receipt an outbound network effect.
    SecureEgress,
}

/// Canonical decision payload issued to guardian committee members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianDecision {
    /// Decision domain.
    pub domain: u8,
    /// Validator or runtime subject.
    #[serde(default)]
    pub subject: Vec<u8>,
    /// Canonical payload hash for the requested decision.
    pub payload_hash: [u8; 32],
    /// Monotonic counter checkpoint expected by the caller.
    pub counter: u64,
    /// Prior trace root expected by the caller.
    pub trace_hash: [u8; 32],
    /// Measurement root to bind into the certificate.
    pub measurement_root: [u8; 32],
    /// Optional policy hash for egress / runtime constraints.
    pub policy_hash: [u8; 32],
}

/// Verifier family used to validate guardian attestation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum GuardianAttestationVerifierKind {
    /// Legacy structural checks only.
    #[default]
    Structural,
    /// Hardware quote verification through tee-driver.
    TeeDriver,
    /// Software guardian verification through committee/log policy.
    SoftwareGuardian,
}

/// Rich evidence attached to guardian attestations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianAttestationEvidence {
    /// Verifier used for the evidence.
    pub verifier: GuardianAttestationVerifierKind,
    /// Hash of the committee manifest bound to this runtime.
    pub manifest_hash: [u8; 32],
    /// Measurement root of the attested runtime.
    pub measurement_root: [u8; 32],
    /// Optional transparency checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<GuardianLogCheckpoint>,
    /// Optional inclusion proof bytes.
    #[serde(default)]
    pub inclusion_proof: Vec<u8>,
    /// Opaque verifier evidence (quote blob, signed statement, etc.).
    #[serde(default)]
    pub evidence: Vec<u8>,
}

/// Canonical receipt for guardian-authorized egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct EgressReceipt {
    /// Canonical hash of the outbound request without secret bytes.
    pub request_hash: [u8; 32],
    /// Canonical TLS server name bound to the session.
    #[serde(default)]
    pub server_name: String,
    /// Receipt schema version for transcript binding semantics.
    #[serde(default)]
    pub transcript_version: u32,
    /// Redacted transcript root for request/response exchange.
    pub transcript_root: [u8; 32],
    /// TLS-session-bound handshake transcript digest.
    #[serde(default)]
    pub handshake_transcript_hash: [u8; 32],
    /// Hash of the HTTP request transcript sent over the TLS channel.
    #[serde(default)]
    pub request_transcript_hash: [u8; 32],
    /// Hash of the HTTP response transcript received over the TLS channel.
    #[serde(default)]
    pub response_transcript_hash: [u8; 32],
    /// Hash of the peer certificate chain, when available.
    pub peer_certificate_chain_hash: [u8; 32],
    /// Hash of the peer leaf certificate, when available.
    #[serde(default)]
    pub peer_leaf_certificate_hash: [u8; 32],
    /// Hash of the response body returned to the workload.
    pub response_hash: [u8; 32],
    /// Policy hash that authorized this egress.
    pub policy_hash: [u8; 32],
    /// Guardian certificate authorizing the effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_certificate: Option<GuardianQuorumCertificate>,
    /// Optional witness-log checkpoint anchoring the receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<GuardianLogCheckpoint>,
}
