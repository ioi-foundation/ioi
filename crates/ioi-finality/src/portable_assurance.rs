//! Runtime-independent, byte-oriented verifier for portable AFT assurance
//! receipts. The verifier consumes no node state and resolves no network refs.

use crate::{verify_portable_bundle, VerifiedPortableClaim};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair, VerifyingKey};
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaPublicKey, MldsaScheme, MldsaSignature};
use ioi_crypto::sign::slh_dsa::verify_initial_seal_share_v2;
use ioi_crypto::transport::pq_authenticated_channel::{
    verify_pq_channel_completion_evidence, PqChannelCompletionEvidenceV1,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, AccountabilityEvidenceV1, AccountabilityV1,
    BondSnapshotV1, CertificateOnlyGuaranteeVerifierV1, CertificateProfile, EconomicAssuranceV1,
    EconomicAssuranceVerifierV1, EffectManifestV1, ExternalResourceRecordV1, GuaranteeRank,
    GuaranteeRequirementsV1, GuaranteeTransformRuleV1, GuaranteeVectorV1, PrimitiveSuiteV1,
    SafetyModelV1, SealKeyManifestV1, SealShareV2, SignatureSuite,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Only accepted complete-receipt schema.
pub const PORTABLE_ASSURANCE_RECEIPT_V1: &str = "ioi.aft.portable-assurance-receipt.v1";
/// External trust-policy schema required for an authorization decision.
pub const PORTABLE_ASSURANCE_TRUST_V1: &str = "ioi.aft.portable-assurance-trust.v1";
/// Exact verifier behavior/profile identifier.
pub const PORTABLE_ASSURANCE_VERIFIER_V1: &str = "verifier://ioi/aft/portable-assurance/v1";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"ioi::aft::portable-assurance-receipt::v1\0";
const EXTERNALIZATION_SIGNATURE_DOMAIN: &[u8] =
    b"ioi::aft::portable-externalization-evidence::v1\0";
const TERMINAL_SEAL_ROOT_DOMAIN: &[u8] = b"ioi::aft::portable-terminal-seal-root::v1\0";
const CONFIGURATION_KEY_ROOT_VOTE_DOMAIN: &[u8] = b"ioi::aft::configuration-key-root-vote::v1\0";

pub const PORTABLE_PQ_CHANNEL_COVERAGE_V1: &str = "ioi.aft.pq-channel-coverage.v1";
pub const PORTABLE_EXTERNALIZATION_EVIDENCE_V1: &str = "ioi.aft.pq-externalization-evidence.v1";
pub const PORTABLE_TERMINAL_SEAL_V1: &str = "ioi.aft.terminal-seal.v1";

/// Configuration and active-key state committed by the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableConfigurationSnapshotV1 {
    pub network_id: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub epoch: u64,
    pub key_root: [u8; 32],
    pub snapshot_height: u64,
    pub key_root_votes: Vec<PortableConfigurationKeyRootVoteV1>,
}

/// One rooted configuration member's ML-DSA enrollment vote for the exact
/// terminal-key manifest commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableConfigurationKeyRootVoteV1 {
    pub member_id: AccountId,
    pub signature_base64: String,
}

/// Consequence evidence retained without requiring an Agentgres process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableConsequenceEvidenceV1 {
    pub manifest_root: [u8; 32],
    pub intent_root: [u8; 32],
    pub execution_root: [u8; 32],
    pub outcome_root: [u8; 32],
    pub reconciliation_root: [u8; 32],
    pub resource_record: ExternalResourceRecordV1,
    pub externalization_evidence: PortableExternalizationEvidenceV1,
}

/// PQ endpoint attestation over the complete modeled externalization result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableExternalizationEvidenceV1 {
    pub schema_version: String,
    pub algorithm: String,
    pub endpoint_public_key_base64: String,
    pub signature_base64: String,
}

/// Full-mesh completed PQ-channel evidence for the exact finality constituent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePqChannelCoverageV1 {
    pub schema_version: String,
    pub network_id: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub epoch: u64,
    pub protected_finality_hash: [u8; 32],
    pub sessions: Vec<PqChannelCompletionEvidenceV1>,
}

/// Unanimous, identity-attributable SLH-DSA terminal seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableTerminalSealV1 {
    pub schema_version: String,
    pub key_manifest: SealKeyManifestV1,
    pub shares: Vec<SealShareV2>,
}

/// Optional M6 proof package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableEconomicProofV1 {
    pub evidence: AccountabilityEvidenceV1,
    pub snapshot: BondSnapshotV1,
    pub claimed: EconomicAssuranceV1,
}

/// Requested external anchor/checkpoint, always carried with the exact hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableAnchorV1 {
    pub anchor_ref: String,
    pub anchor_hash: [u8; 32],
}

/// Relying-party input. None of these values may be learned from the receipt
/// being authorized: doing so would let a self-consistent parallel
/// configuration nominate its own roots and signing key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableAssuranceTrustV1 {
    pub schema_version: String,
    pub network_id: [u8; 32],
    pub configuration_hash: [u8; 32],
    pub epoch: u64,
    pub terminal_key_root: [u8; 32],
    pub allowed_receipt_public_keys_base64: BTreeSet<String>,
    pub required_anchors: Vec<PortableAnchorV1>,
    pub required_guarantees: GuaranteeRequirementsV1,
}

/// A verifier-confirmed, coordinate-specific transform in the receipt trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableVerifiedTransformV1 {
    pub rule: GuaranteeTransformRuleV1,
    pub theorem_id: String,
    pub evidence_hash: [u8; 32],
}

/// PQ signature over the canonical receipt preimage hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableReceiptSignatureV1 {
    pub algorithm: String,
    pub public_key_base64: String,
    pub signature_base64: String,
}

/// Complete offline receipt. Ordering, availability, seal/finality evidence,
/// and their key material remain inside `finality_bundle` and are reverified by
/// the version-pinned source-neutral finality verifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableAssuranceReceiptV1 {
    pub schema_version: String,
    pub verifier_profile: String,
    pub finality_bundle: Value,
    pub channel_coverage: PortablePqChannelCoverageV1,
    pub terminal_seal: PortableTerminalSealV1,
    pub effect_manifest: EffectManifestV1,
    pub policy: GuaranteeRequirementsV1,
    pub configuration_snapshot: PortableConfigurationSnapshotV1,
    pub consequence: PortableConsequenceEvidenceV1,
    pub economic_proof: Option<PortableEconomicProofV1>,
    pub requested_anchors: Vec<PortableAnchorV1>,
    pub claimed_achieved: GuaranteeVectorV1,
    pub transformation_trace: Vec<PortableVerifiedTransformV1>,
    pub receipt_hash: String,
    pub signature: PortableReceiptSignatureV1,
}

/// Machine-readable verified constituent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedConstituentV1 {
    pub kind: String,
    pub commitment: String,
}

/// Complete success output. Invalid inputs produce a report with one precise
/// refusal and no achieved vector rather than a partially trusted result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortableAssuranceVerificationV1 {
    pub accepted: bool,
    pub verifier_profile: String,
    pub receipt_hash: Option<String>,
    pub achieved_guarantee_vector: Option<GuaranteeVectorV1>,
    pub policy_satisfied: bool,
    pub refusal_reasons: Vec<String>,
    pub verified_constituents: Vec<VerifiedConstituentV1>,
    pub verified_transformations: Vec<PortableVerifiedTransformV1>,
}

impl PortableAssuranceVerificationV1 {
    fn refusal(reason: impl ToString) -> Self {
        Self {
            accepted: false,
            verifier_profile: PORTABLE_ASSURANCE_VERIFIER_V1.into(),
            receipt_hash: None,
            achieved_guarantee_vector: None,
            policy_satisfied: false,
            refusal_reasons: vec![reason.to_string()],
            verified_constituents: Vec::new(),
            verified_transformations: Vec::new(),
        }
    }
}

/// Verify canonical receipt bytes against relying-party trust input, without
/// node, database, clock, or network. Self-contained receipt bytes alone are
/// deliberately insufficient for an authorization decision.
pub fn verify_portable_assurance_bytes(
    bytes: &[u8],
    trust: &PortableAssuranceTrustV1,
) -> PortableAssuranceVerificationV1 {
    match verify_portable_assurance_inner(bytes, trust) {
        Ok(report) => report,
        Err(error) => PortableAssuranceVerificationV1::refusal(error),
    }
}

fn verify_portable_assurance_inner(
    bytes: &[u8],
    trust: &PortableAssuranceTrustV1,
) -> Result<PortableAssuranceVerificationV1, PortableAssuranceError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?;
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?;
    if canonical != bytes {
        return Err(PortableAssuranceError::NonCanonical);
    }
    let receipt: PortableAssuranceReceiptV1 = serde_json::from_value(value)
        .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?;
    if receipt.schema_version != PORTABLE_ASSURANCE_RECEIPT_V1 {
        return Err(PortableAssuranceError::UnsupportedVersion(
            receipt.schema_version,
        ));
    }
    if receipt.verifier_profile != PORTABLE_ASSURANCE_VERIFIER_V1 {
        return Err(PortableAssuranceError::UnsupportedVerifier(
            receipt.verifier_profile,
        ));
    }
    verify_external_trust(&receipt, trust)?;
    validate_hashes(&receipt)?;
    let expected_hash = receipt_hash(&receipt)?;
    if receipt.receipt_hash != expected_hash {
        return Err(PortableAssuranceError::ReceiptHash);
    }
    verify_receipt_signature(&receipt)?;

    let finality = verify_portable_bundle(&receipt.finality_bundle)
        .map_err(|error| PortableAssuranceError::Finality(error.to_string()))?;
    let mut achieved = match finality {
        VerifiedPortableClaim::RuntimeV3(claim) => claim.assurance,
        VerifiedPortableClaim::V2(_) => return Err(PortableAssuranceError::MissingVector),
    };
    let finality_hash = decode_hash(&hash_json(&receipt.finality_bundle)?)?;
    let finality_context = finality_pq_context(&receipt.finality_bundle)?;
    let members = &finality_context.members;
    if achieved.safety.configuration_hash != Some(finality_context.configuration_hash) {
        return Err(PortableAssuranceError::ConfigurationSnapshot);
    }
    verify_configuration_snapshot(&receipt.configuration_snapshot, &finality_context)?;
    let channel_hash =
        verify_channel_coverage(&receipt.channel_coverage, finality_hash, &finality_context)?;
    achieved.crypto.channel_pq = true;
    achieved.constituent_hashes.insert(channel_hash);
    achieved.theorem_ids.insert("T12".into());
    let mut constituents = vec![
        VerifiedConstituentV1 {
            kind: "ordering_availability_finality".into(),
            commitment: prefixed(finality_hash),
        },
        VerifiedConstituentV1 {
            kind: "pq_authenticated_channel_coverage".into(),
            commitment: prefixed(channel_hash),
        },
    ];

    receipt
        .effect_manifest
        .validate()
        .map_err(|error| PortableAssuranceError::Manifest(error.to_string()))?;
    let manifest_domain = receipt
        .effect_manifest
        .conflict_domain_commitment()
        .map_err(|error| PortableAssuranceError::Manifest(error.to_string()))?;
    if achieved.safety.conflict_domain_hash != Some(manifest_domain) {
        return Err(PortableAssuranceError::Manifest(
            "effect conflict domain differs from finality evidence".into(),
        ));
    }
    if receipt.effect_manifest.required_guarantees != receipt.policy {
        return Err(PortableAssuranceError::PolicyManifestMismatch);
    }
    let manifest_root = receipt
        .effect_manifest
        .commitment()
        .map_err(|error| PortableAssuranceError::Manifest(error.to_string()))?;
    if manifest_root != receipt.consequence.manifest_root {
        return Err(PortableAssuranceError::Consequence("manifest root".into()));
    }
    verify_consequence(&receipt.effect_manifest, &receipt.consequence)?;
    verify_externalization_evidence(&receipt.effect_manifest, &receipt.consequence)?;
    let consequence_hash = hash_serializable(&receipt.consequence)?;
    achieved.externalization = receipt
        .effect_manifest
        .resource_profile
        .advertised_externalization()
        .map_err(|error| PortableAssuranceError::Consequence(error.to_string()))?;
    achieved.crypto.externalization_pq =
        receipt.effect_manifest.resource_profile.externalization_pq;
    let seal_hash = verify_terminal_seal(
        &receipt.terminal_seal,
        &receipt.configuration_snapshot,
        &receipt.channel_coverage,
        members,
        terminal_seal_root(finality_hash, manifest_root, &receipt.consequence)?,
        manifest_domain,
    )?;
    let n = u32::try_from(members.len()).map_err(|_| {
        PortableAssuranceError::TerminalSeal("member count does not fit u32".into())
    })?;
    achieved.safety.model = SafetyModelV1::UnanimousAllButOne;
    achieved.safety.finality_rank = Some(GuaranteeRank::SealedAllButOne);
    achieved.safety.committee_n = Some(n);
    achieved.safety.fault_bound_f = Some(n - 1);
    achieved.safety.quorum_q = Some(n);
    achieved.accountability = AccountabilityV1::FullConfiguration;
    achieved
        .certificate_profiles
        .insert(CertificateProfile::PqUnanimousBoundaryClose);
    achieved
        .crypto
        .primitive_suites
        .insert(PrimitiveSuiteV1::HashBasedSignature);
    achieved.constituent_hashes.insert(seal_hash);
    achieved.theorem_ids.extend(["T1".into(), "T7".into()]);
    if achieved.crypto.consensus_pq
        && achieved.crypto.channel_pq
        && achieved.crypto.externalization_pq
    {
        achieved
            .crypto
            .primitive_suites
            .remove(&PrimitiveSuiteV1::Unresolved);
    }
    achieved.crypto.end_to_end_pq = achieved.crypto.consensus_pq
        && achieved.crypto.channel_pq
        && achieved.crypto.externalization_pq;
    achieved
        .constituent_hashes
        .insert(decode_hash(&consequence_hash)?);
    achieved.theorem_ids.insert("T10".into());
    let mut verified = CertificateOnlyGuaranteeVerifierV1::verify(&[achieved])
        .map_err(|error| PortableAssuranceError::Guarantee(error.to_string()))?;
    constituents.push(VerifiedConstituentV1 {
        kind: "effect_manifest".into(),
        commitment: prefixed(manifest_root),
    });
    constituents.push(VerifiedConstituentV1 {
        kind: "consequence".into(),
        commitment: consequence_hash,
    });
    constituents.push(VerifiedConstituentV1 {
        kind: "pq_terminal_seal".into(),
        commitment: prefixed(seal_hash),
    });

    let mut transforms = vec![
        PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishChannelPqFromTranscriptVerification,
            theorem_id: "T12".into(),
            evidence_hash: channel_hash,
        },
        PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishSafetyFromIndependentProof,
            theorem_id: "T1".into(),
            evidence_hash: seal_hash,
        },
        PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishExternalizationFromResourceProof,
            theorem_id: "T10".into(),
            evidence_hash: decode_hash(&hash_serializable(&receipt.consequence)?)?,
        },
    ];
    if let Some(package) = &receipt.economic_proof {
        let economic = EconomicAssuranceVerifierV1::verify(
            &package.evidence,
            &package.snapshot,
            &package.claimed,
        )
        .map_err(|error| PortableAssuranceError::Economic(error.to_string()))?;
        verified = economic
            .attach_to(&verified)
            .map_err(|error| PortableAssuranceError::Economic(error.to_string()))?;
        constituents.push(VerifiedConstituentV1 {
            kind: "distinct_collateral".into(),
            commitment: prefixed(economic.proof_commitment()),
        });
        transforms.push(PortableVerifiedTransformV1 {
            rule: GuaranteeTransformRuleV1::EstablishSlashableCollateralFromBondProof,
            theorem_id: "T11".into(),
            evidence_hash: economic.proof_commitment(),
        });
    }
    if transforms != receipt.transformation_trace {
        return Err(PortableAssuranceError::TransformationTrace);
    }
    if verified.achieved() != &receipt.claimed_achieved {
        return Err(PortableAssuranceError::ClaimMismatch);
    }
    if !receipt.policy.is_satisfied_by(&verified) {
        return Err(PortableAssuranceError::PolicyUnsatisfied);
    }
    if !trust.required_guarantees.is_satisfied_by(&verified) {
        return Err(PortableAssuranceError::ExternalPolicyUnsatisfied);
    }
    constituents.push(VerifiedConstituentV1 {
        kind: "configuration_key_snapshot".into(),
        commitment: hash_serializable(&receipt.configuration_snapshot)?,
    });
    for anchor in &receipt.requested_anchors {
        constituents.push(VerifiedConstituentV1 {
            kind: "requested_anchor".into(),
            commitment: prefixed(anchor.anchor_hash),
        });
    }

    Ok(PortableAssuranceVerificationV1 {
        accepted: true,
        verifier_profile: PORTABLE_ASSURANCE_VERIFIER_V1.into(),
        receipt_hash: Some(receipt.receipt_hash),
        achieved_guarantee_vector: Some(verified.into_achieved()),
        policy_satisfied: true,
        refusal_reasons: Vec::new(),
        verified_constituents: constituents,
        verified_transformations: transforms,
    })
}

fn verify_external_trust(
    receipt: &PortableAssuranceReceiptV1,
    trust: &PortableAssuranceTrustV1,
) -> Result<(), PortableAssuranceError> {
    if trust.schema_version != PORTABLE_ASSURANCE_TRUST_V1 {
        return Err(PortableAssuranceError::UnsupportedTrustVersion(
            trust.schema_version.clone(),
        ));
    }
    if trust.network_id == [0; 32]
        || trust.configuration_hash == [0; 32]
        || trust.terminal_key_root == [0; 32]
        || trust.allowed_receipt_public_keys_base64.is_empty()
    {
        return Err(PortableAssuranceError::ExternalTrust(
            "zero root or empty receipt-key allowlist".into(),
        ));
    }
    let snapshot = &receipt.configuration_snapshot;
    if snapshot.network_id != trust.network_id
        || snapshot.configuration_hash != trust.configuration_hash
        || snapshot.epoch != trust.epoch
        || snapshot.key_root != trust.terminal_key_root
    {
        return Err(PortableAssuranceError::ExternalTrust(
            "network/configuration/epoch/terminal-key root mismatch".into(),
        ));
    }
    if trust.required_guarantees.configuration_hash != Some(trust.configuration_hash) {
        return Err(PortableAssuranceError::ExternalTrust(
            "required guarantees must pin the trusted configuration".into(),
        ));
    }
    if !trust
        .allowed_receipt_public_keys_base64
        .contains(&receipt.signature.public_key_base64)
    {
        return Err(PortableAssuranceError::UntrustedReceiptSigner);
    }
    let anchors = canonical_anchor_map(&receipt.requested_anchors)?;
    let required = canonical_anchor_map(&trust.required_anchors)?;
    if anchors != required {
        return Err(PortableAssuranceError::ExternalAnchorMismatch);
    }
    Ok(())
}

fn canonical_anchor_map(
    anchors: &[PortableAnchorV1],
) -> Result<BTreeMap<String, [u8; 32]>, PortableAssuranceError> {
    if anchors.is_empty() {
        return Err(PortableAssuranceError::Anchor);
    }
    let mut out = BTreeMap::new();
    for anchor in anchors {
        if anchor.anchor_ref.trim().is_empty()
            || anchor.anchor_hash == [0; 32]
            || out
                .insert(anchor.anchor_ref.clone(), anchor.anchor_hash)
                .is_some()
        {
            return Err(PortableAssuranceError::Anchor);
        }
    }
    Ok(out)
}

fn validate_hashes(receipt: &PortableAssuranceReceiptV1) -> Result<(), PortableAssuranceError> {
    for (name, hash) in [
        (
            "configuration_hash",
            receipt.configuration_snapshot.configuration_hash,
        ),
        ("network_id", receipt.configuration_snapshot.network_id),
        ("key_root", receipt.configuration_snapshot.key_root),
        ("intent_root", receipt.consequence.intent_root),
        ("execution_root", receipt.consequence.execution_root),
        ("outcome_root", receipt.consequence.outcome_root),
        (
            "reconciliation_root",
            receipt.consequence.reconciliation_root,
        ),
    ] {
        if hash == [0; 32] {
            return Err(PortableAssuranceError::ZeroHash(name));
        }
    }
    if receipt.requested_anchors.is_empty()
        || receipt
            .requested_anchors
            .iter()
            .any(|anchor| anchor.anchor_ref.trim().is_empty() || anchor.anchor_hash == [0; 32])
    {
        return Err(PortableAssuranceError::Anchor);
    }
    Ok(())
}

fn verify_consequence(
    manifest: &EffectManifestV1,
    evidence: &PortableConsequenceEvidenceV1,
) -> Result<(), PortableAssuranceError> {
    evidence
        .resource_record
        .validate()
        .map_err(|error| PortableAssuranceError::Consequence(error.to_string()))?;
    let record = &evidence.resource_record;
    if !manifest.resource_profile.contract.supports_at_most_once()
        || record.resource_id != manifest.resource_id
        || record.idempotency_key != manifest.idempotency_key
        || record.request_root != manifest.request_root
        || record.predecessor_root != manifest.predecessor_root
        || record.outcome_root != manifest.expected_outcome_root
        || evidence.intent_root != manifest.intent_root
        || evidence.outcome_root != record.outcome_root
    {
        return Err(PortableAssuranceError::Consequence(
            "resource binding".into(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct FinalityPqContext {
    network_id: [u8; 32],
    configuration_hash: [u8; 32],
    epoch: u64,
    members: Vec<(AccountId, Vec<u8>)>,
}

fn finality_pq_context(bundle: &Value) -> Result<FinalityPqContext, PortableAssuranceError> {
    let certificate = bundle
        .pointer("/checkpoint/finality_certificate")
        .ok_or_else(|| {
            PortableAssuranceError::ChannelCoverage("missing finality certificate".into())
        })?;
    if certificate.get("signature_suite").and_then(Value::as_str) != Some("ml-dsa-44") {
        return Err(PortableAssuranceError::ChannelCoverage(
            "checkpoint issuer is not ML-DSA-44".into(),
        ));
    }
    let evidence = certificate.get("hash_async_evidence").ok_or_else(|| {
        PortableAssuranceError::ChannelCoverage(
            "PQ channel coverage v1 requires hash-async finality evidence".into(),
        )
    })?;
    let certificate_bytes = BASE64
        .decode(
            evidence
                .get("certificate_base64")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PortableAssuranceError::ChannelCoverage(
                        "hash-async certificate bytes are absent".into(),
                    )
                })?,
        )
        .map_err(|error| PortableAssuranceError::ChannelCoverage(error.to_string()))?;
    let async_certificate: ioi_types::app::AftAsyncExecutedBlockCertificateV1 =
        ioi_types::codec::from_bytes_canonical(&certificate_bytes)
            .map_err(|error| PortableAssuranceError::ChannelCoverage(error.to_string()))?;
    let scope = async_certificate.decision.instance.scope;
    let epoch = evidence
        .get("membership_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            PortableAssuranceError::ChannelCoverage("membership epoch is absent".into())
        })?;
    if epoch != scope.epoch {
        return Err(PortableAssuranceError::ChannelCoverage(
            "channel/finality epoch mismatch".into(),
        ));
    }
    let raw_members = evidence
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| PortableAssuranceError::ChannelCoverage("member list is absent".into()))?;
    if raw_members.len() < 2 || raw_members.len() > 128 {
        return Err(PortableAssuranceError::ChannelCoverage(
            "member count is outside the portable coverage profile".into(),
        ));
    }
    let mut members = Vec::with_capacity(raw_members.len());
    for member in raw_members {
        if member.get("signature_suite").and_then(Value::as_str) != Some("ml-dsa-44") {
            return Err(PortableAssuranceError::ChannelCoverage(
                "channel member is not rooted by an ML-DSA-44 consensus key".into(),
            ));
        }
        let public_key = hex::decode(
            member
                .get("public_key")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PortableAssuranceError::ChannelCoverage("member public key is absent".into())
                })?,
        )
        .map_err(|error| PortableAssuranceError::ChannelCoverage(error.to_string()))?;
        let account = AccountId(
            account_id_from_key_material(SignatureSuite::ML_DSA_44, &public_key)
                .map_err(|error| PortableAssuranceError::ChannelCoverage(error.to_string()))?,
        );
        members.push((account, public_key));
    }
    if members.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(PortableAssuranceError::ChannelCoverage(
            "finality members are not strictly account-sorted".into(),
        ));
    }
    Ok(FinalityPqContext {
        network_id: scope.network_id,
        configuration_hash: scope.configuration_hash,
        epoch,
        members,
    })
}

fn verify_channel_coverage(
    coverage: &PortablePqChannelCoverageV1,
    finality_hash: [u8; 32],
    context: &FinalityPqContext,
) -> Result<[u8; 32], PortableAssuranceError> {
    if coverage.schema_version != PORTABLE_PQ_CHANNEL_COVERAGE_V1
        || coverage.network_id != context.network_id
        || coverage.configuration_hash != context.configuration_hash
        || coverage.epoch != context.epoch
        || coverage.protected_finality_hash != finality_hash
    {
        return Err(PortableAssuranceError::ChannelCoverage(
            "coverage scope or protected finality commitment differs".into(),
        ));
    }
    let member_keys: BTreeMap<_, _> = context.members.iter().cloned().collect();
    let expected_pairs = context
        .members
        .len()
        .checked_mul(context.members.len() - 1)
        .and_then(|value| value.checked_div(2))
        .ok_or_else(|| PortableAssuranceError::ChannelCoverage("pair count overflow".into()))?;
    if coverage.sessions.len() != expected_pairs {
        return Err(PortableAssuranceError::ChannelCoverage(format!(
            "coverage has {} sessions; complete graph requires {expected_pairs}",
            coverage.sessions.len()
        )));
    }
    let mut pairs = BTreeSet::new();
    for session in &coverage.sessions {
        verify_pq_channel_completion_evidence(session)
            .map_err(|error| PortableAssuranceError::ChannelCoverage(error.to_string()))?;
        let scope = &session.client_hello.scope;
        if scope.network_id != coverage.network_id
            || scope.configuration_hash != coverage.configuration_hash
            || scope.epoch != coverage.epoch
            || session.protected_payload_hash != finality_hash
            || member_keys.get(&scope.initiator) != Some(&session.client_hello.identity_public_key)
            || member_keys.get(&scope.responder) != Some(&session.server_hello.identity_public_key)
        {
            return Err(PortableAssuranceError::ChannelCoverage(
                "one session is not an exact finality-member edge".into(),
            ));
        }
        let pair = if scope.initiator < scope.responder {
            (scope.initiator, scope.responder)
        } else {
            (scope.responder, scope.initiator)
        };
        if !pairs.insert(pair) {
            return Err(PortableAssuranceError::ChannelCoverage(
                "coverage repeats a member pair".into(),
            ));
        }
    }
    Ok(decode_hash(&hash_serializable(coverage)?)?)
}

fn configuration_key_root_vote_message(
    snapshot: &PortableConfigurationSnapshotV1,
) -> Result<Vec<u8>, PortableAssuranceError> {
    let material = (
        snapshot.network_id,
        snapshot.configuration_hash,
        snapshot.epoch,
        snapshot.key_root,
        snapshot.snapshot_height,
    );
    let mut bytes = CONFIGURATION_KEY_ROOT_VOTE_DOMAIN.to_vec();
    bytes.extend(
        serde_jcs::to_vec(&material)
            .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?,
    );
    Ok(bytes)
}

/// Attach unanimous ML-DSA enrollment votes to a configuration/key snapshot.
pub fn sign_portable_configuration_snapshot(
    snapshot: &mut PortableConfigurationSnapshotV1,
    members: &[(AccountId, MldsaKeyPair)],
) -> Result<(), PortableAssuranceError> {
    snapshot.key_root_votes.clear();
    let message = configuration_key_root_vote_message(snapshot)?;
    for (member_id, key) in members {
        let derived =
            AccountId(
                account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &key.public_key().to_bytes(),
                )
                .map_err(|error| {
                    PortableAssuranceError::ConfigurationEnrollment(error.to_string())
                })?,
            );
        if &derived != member_id {
            return Err(PortableAssuranceError::ConfigurationEnrollment(
                "snapshot signer key does not derive its member identity".into(),
            ));
        }
        snapshot
            .key_root_votes
            .push(PortableConfigurationKeyRootVoteV1 {
                member_id: *member_id,
                signature_base64: BASE64.encode(
                    key.sign(&message)
                        .map_err(|error| {
                            PortableAssuranceError::ConfigurationEnrollment(error.to_string())
                        })?
                        .to_bytes(),
                ),
            });
    }
    Ok(())
}

fn verify_configuration_snapshot(
    snapshot: &PortableConfigurationSnapshotV1,
    context: &FinalityPqContext,
) -> Result<(), PortableAssuranceError> {
    if snapshot.network_id != context.network_id
        || snapshot.configuration_hash != context.configuration_hash
        || snapshot.epoch != context.epoch
        || snapshot.key_root == [0; 32]
        || snapshot.snapshot_height == 0
        || snapshot.key_root_votes.len() != context.members.len()
    {
        return Err(PortableAssuranceError::ConfigurationEnrollment(
            "configuration/key snapshot scope or vote cardinality differs".into(),
        ));
    }
    let message = configuration_key_root_vote_message(snapshot)?;
    for (vote, (expected_member, public_bytes)) in
        snapshot.key_root_votes.iter().zip(&context.members)
    {
        if &vote.member_id != expected_member {
            return Err(PortableAssuranceError::ConfigurationEnrollment(
                "configuration/key votes are not exact member order".into(),
            ));
        }
        let public = MldsaPublicKey::from_bytes(public_bytes)
            .map_err(|error| PortableAssuranceError::ConfigurationEnrollment(error.to_string()))?;
        let signature =
            MldsaSignature::from_bytes(&BASE64.decode(&vote.signature_base64).map_err(
                |error| PortableAssuranceError::ConfigurationEnrollment(error.to_string()),
            )?)
            .map_err(|error| PortableAssuranceError::ConfigurationEnrollment(error.to_string()))?;
        public.verify(&message, &signature).map_err(|_| {
            PortableAssuranceError::ConfigurationEnrollment(
                "invalid configuration/key enrollment vote".into(),
            )
        })?;
    }
    Ok(())
}

fn terminal_seal_root(
    finality_hash: [u8; 32],
    manifest_root: [u8; 32],
    consequence: &PortableConsequenceEvidenceV1,
) -> Result<[u8; 32], PortableAssuranceError> {
    let material = (
        TERMINAL_SEAL_ROOT_DOMAIN,
        finality_hash,
        manifest_root,
        consequence.intent_root,
        consequence.execution_root,
        consequence.outcome_root,
        consequence.reconciliation_root,
    );
    Ok(Sha256::digest(
        serde_jcs::to_vec(&material)
            .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?,
    )
    .into())
}

fn verify_terminal_seal(
    seal: &PortableTerminalSealV1,
    snapshot: &PortableConfigurationSnapshotV1,
    coverage: &PortablePqChannelCoverageV1,
    members: &[(AccountId, Vec<u8>)],
    expected_root: [u8; 32],
    expected_domain: [u8; 32],
) -> Result<[u8; 32], PortableAssuranceError> {
    if seal.schema_version != PORTABLE_TERMINAL_SEAL_V1 {
        return Err(PortableAssuranceError::TerminalSeal(
            "unsupported terminal-seal version".into(),
        ));
    }
    seal.key_manifest
        .validate()
        .map_err(PortableAssuranceError::TerminalSeal)?;
    let key_root = seal
        .key_manifest
        .commitment()
        .map_err(PortableAssuranceError::TerminalSeal)?;
    if key_root != snapshot.key_root
        || seal.shares.len() != members.len()
        || seal.key_manifest.entries.len() != members.len()
    {
        return Err(PortableAssuranceError::TerminalSeal(
            "terminal manifest is not the enrolled unanimous configuration".into(),
        ));
    }
    let mut slot = None;
    for (index, (share, (member, _))) in seal.shares.iter().zip(members).enumerate() {
        let scope = &share.current_key.scope;
        if scope.network_id != coverage.network_id
            || scope.configuration_id != coverage.configuration_hash
            || scope.epoch != coverage.epoch
            || scope.conflict_domain_id != expected_domain
            || scope.member_id != *member
            || scope.member_index != index as u32
            || share.seal_root != expected_root
            || slot.is_some_and(|expected| expected != share.seal_slot)
        {
            return Err(PortableAssuranceError::TerminalSeal(
                "terminal share scope, slot, or root differs".into(),
            ));
        }
        slot = Some(share.seal_slot);
        verify_initial_seal_share_v2(share, &seal.key_manifest)
            .map_err(PortableAssuranceError::TerminalSeal)?;
    }
    Ok(decode_hash(&hash_serializable(seal)?)?)
}

fn externalization_signature_message(
    manifest: &EffectManifestV1,
    consequence: &PortableConsequenceEvidenceV1,
) -> Result<Vec<u8>, PortableAssuranceError> {
    let material = (
        manifest
            .commitment()
            .map_err(|error| PortableAssuranceError::Manifest(error.to_string()))?,
        manifest
            .resource_profile
            .commitment()
            .map_err(|error| PortableAssuranceError::Manifest(error.to_string()))?,
        &consequence.resource_record,
        consequence.intent_root,
        consequence.execution_root,
        consequence.outcome_root,
        consequence.reconciliation_root,
    );
    let mut bytes = EXTERNALIZATION_SIGNATURE_DOMAIN.to_vec();
    bytes.extend(
        serde_jcs::to_vec(&material)
            .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?,
    );
    Ok(bytes)
}

/// Sign the exact modeled externalization outcome with the endpoint key rooted
/// in the resource profile.
pub fn sign_portable_externalization_evidence(
    manifest: &EffectManifestV1,
    consequence: &mut PortableConsequenceEvidenceV1,
    endpoint: &MldsaKeyPair,
) -> Result<(), PortableAssuranceError> {
    let public = endpoint.public_key().to_bytes();
    let key_hash = account_id_from_key_material(SignatureSuite::ML_DSA_44, &public)
        .map_err(|error| PortableAssuranceError::ExternalizationEvidence(error.to_string()))?;
    if manifest.resource_profile.endpoint_pq_key_hash != Some(key_hash) {
        return Err(PortableAssuranceError::ExternalizationEvidence(
            "endpoint key is not rooted in the resource profile".into(),
        ));
    }
    consequence.externalization_evidence = PortableExternalizationEvidenceV1 {
        schema_version: PORTABLE_EXTERNALIZATION_EVIDENCE_V1.into(),
        algorithm: "ml-dsa-44".into(),
        endpoint_public_key_base64: BASE64.encode(&public),
        signature_base64: String::new(),
    };
    let message = externalization_signature_message(manifest, consequence)?;
    consequence.externalization_evidence.signature_base64 = BASE64.encode(
        endpoint
            .sign(&message)
            .map_err(|error| PortableAssuranceError::ExternalizationEvidence(error.to_string()))?
            .to_bytes(),
    );
    Ok(())
}

fn verify_externalization_evidence(
    manifest: &EffectManifestV1,
    consequence: &PortableConsequenceEvidenceV1,
) -> Result<(), PortableAssuranceError> {
    let evidence = &consequence.externalization_evidence;
    if evidence.schema_version != PORTABLE_EXTERNALIZATION_EVIDENCE_V1
        || evidence.algorithm != "ml-dsa-44"
        || !manifest.resource_profile.externalization_pq
    {
        return Err(PortableAssuranceError::ExternalizationEvidence(
            "unsupported externalization evidence profile".into(),
        ));
    }
    let public_bytes = BASE64
        .decode(&evidence.endpoint_public_key_base64)
        .map_err(|error| PortableAssuranceError::ExternalizationEvidence(error.to_string()))?;
    let key_hash = account_id_from_key_material(SignatureSuite::ML_DSA_44, &public_bytes)
        .map_err(|error| PortableAssuranceError::ExternalizationEvidence(error.to_string()))?;
    if manifest.resource_profile.endpoint_pq_key_hash != Some(key_hash) {
        return Err(PortableAssuranceError::ExternalizationEvidence(
            "externalization endpoint key differs from the resource profile".into(),
        ));
    }
    let public = MldsaPublicKey::from_bytes(&public_bytes)
        .map_err(|error| PortableAssuranceError::ExternalizationEvidence(error.to_string()))?;
    let signature = MldsaSignature::from_bytes(
        &BASE64
            .decode(&evidence.signature_base64)
            .map_err(|error| PortableAssuranceError::ExternalizationEvidence(error.to_string()))?,
    )
    .map_err(|error| PortableAssuranceError::ExternalizationEvidence(error.to_string()))?;
    public
        .verify(
            &externalization_signature_message(manifest, consequence)?,
            &signature,
        )
        .map_err(|_| {
            PortableAssuranceError::ExternalizationEvidence(
                "invalid ML-DSA endpoint signature".into(),
            )
        })
}

fn verify_receipt_signature(
    receipt: &PortableAssuranceReceiptV1,
) -> Result<(), PortableAssuranceError> {
    if receipt.signature.algorithm != "ml-dsa-44" {
        return Err(PortableAssuranceError::UnsupportedAlgorithm(
            receipt.signature.algorithm.clone(),
        ));
    }
    let public_bytes = BASE64
        .decode(&receipt.signature.public_key_base64)
        .map_err(|error| PortableAssuranceError::Signature(error.to_string()))?;
    let signature_bytes = BASE64
        .decode(&receipt.signature.signature_base64)
        .map_err(|error| PortableAssuranceError::Signature(error.to_string()))?;
    let public = MldsaPublicKey::from_bytes(&public_bytes)
        .map_err(|error| PortableAssuranceError::Signature(error.to_string()))?;
    let signature = MldsaSignature::from_bytes(&signature_bytes)
        .map_err(|error| PortableAssuranceError::Signature(error.to_string()))?;
    public
        .verify(
            signature_message(&receipt.receipt_hash).as_slice(),
            &signature,
        )
        .map_err(|_| PortableAssuranceError::Signature("invalid ML-DSA-44 signature".into()))
}

/// Sign a completely populated receipt. Intended for source-neutral emitters;
/// verification never needs the private key or runtime state.
pub fn sign_portable_assurance_receipt(
    receipt: &mut PortableAssuranceReceiptV1,
    keypair: &MldsaKeyPair,
) -> Result<Vec<u8>, PortableAssuranceError> {
    receipt.signature.algorithm = "ml-dsa-44".into();
    receipt.signature.public_key_base64 = BASE64.encode(keypair.public_key().to_bytes());
    receipt.signature.signature_base64.clear();
    receipt.receipt_hash = receipt_hash(receipt)?;
    let signature = keypair
        .private_key()
        .sign(&signature_message(&receipt.receipt_hash))
        .map_err(|error| PortableAssuranceError::Signature(error.to_string()))?;
    receipt.signature.signature_base64 = BASE64.encode(signature.to_bytes());
    serde_jcs::to_vec(receipt).map_err(|error| PortableAssuranceError::Malformed(error.to_string()))
}

/// Generate a fresh ML-DSA-44 receipt key. Key custody is an emitter concern.
pub fn generate_portable_receipt_key() -> Result<MldsaKeyPair, PortableAssuranceError> {
    MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .map_err(|error| PortableAssuranceError::Signature(error.to_string()))
}

fn receipt_hash(receipt: &PortableAssuranceReceiptV1) -> Result<String, PortableAssuranceError> {
    let mut value = serde_json::to_value(receipt)
        .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| PortableAssuranceError::Malformed("receipt is not an object".into()))?;
    object.remove("receipt_hash");
    object.remove("signature");
    hash_json(&value)
}

fn signature_message(receipt_hash: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + receipt_hash.len());
    message.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN);
    message.extend_from_slice(receipt_hash.as_bytes());
    message
}

fn hash_json(value: &Value) -> Result<String, PortableAssuranceError> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, PortableAssuranceError> {
    let value = serde_json::to_value(value)
        .map_err(|error| PortableAssuranceError::Malformed(error.to_string()))?;
    hash_json(&value)
}

fn prefixed(hash: [u8; 32]) -> String {
    format!("sha256:{}", hex::encode(hash))
}

fn decode_hash(value: &str) -> Result<[u8; 32], PortableAssuranceError> {
    let raw = value
        .strip_prefix("sha256:")
        .ok_or(PortableAssuranceError::ReceiptHash)?;
    hex::decode(raw)
        .map_err(|_| PortableAssuranceError::ReceiptHash)?
        .try_into()
        .map_err(|_| PortableAssuranceError::ReceiptHash)
}

/// Closed refusal vocabulary used by the CLI report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortableAssuranceError {
    #[error("malformed receipt: {0}")]
    Malformed(String),
    #[error("receipt bytes are not canonical RFC 8785/JCS")]
    NonCanonical,
    #[error("unsupported receipt schema version: {0}")]
    UnsupportedVersion(String),
    #[error("unsupported verifier profile: {0}")]
    UnsupportedVerifier(String),
    #[error("unsupported external trust schema version: {0}")]
    UnsupportedTrustVersion(String),
    #[error("external trust policy refused: {0}")]
    ExternalTrust(String),
    #[error("receipt signer is not allowed by external trust policy")]
    UntrustedReceiptSigner,
    #[error("receipt anchors differ from externally pinned anchors")]
    ExternalAnchorMismatch,
    #[error("unsupported receipt signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("receipt preimage hash differs from receipt_hash")]
    ReceiptHash,
    #[error("receipt signature refused: {0}")]
    Signature(String),
    #[error("finality evidence refused: {0}")]
    Finality(String),
    #[error("runtime finality proof supplies no GuaranteeVectorV1")]
    MissingVector,
    #[error("effect manifest refused: {0}")]
    Manifest(String),
    #[error("receipt policy differs from the manifest policy")]
    PolicyManifestMismatch,
    #[error("consequence evidence refused: {0}")]
    Consequence(String),
    #[error("PQ externalization evidence refused: {0}")]
    ExternalizationEvidence(String),
    #[error("PQ channel coverage refused: {0}")]
    ChannelCoverage(String),
    #[error("terminal seal refused: {0}")]
    TerminalSeal(String),
    #[error("configuration/key enrollment refused: {0}")]
    ConfigurationEnrollment(String),
    #[error("economic proof refused: {0}")]
    Economic(String),
    #[error("guarantee vector refused: {0}")]
    Guarantee(String),
    #[error("verified transformation trace differs from the receipt")]
    TransformationTrace,
    #[error("claimed achieved vector differs from independent verification")]
    ClaimMismatch,
    #[error("verified guarantee vector does not satisfy policy")]
    PolicyUnsatisfied,
    #[error("verified guarantee vector does not satisfy relying-party policy")]
    ExternalPolicyUnsatisfied,
    #[error("required commitment is zero: {0}")]
    ZeroHash(&'static str),
    #[error("requested anchor set is empty or malformed")]
    Anchor,
    #[error("configuration snapshot differs from finality evidence")]
    ConfigurationSnapshot,
}

#[cfg(test)]
mod tests;
