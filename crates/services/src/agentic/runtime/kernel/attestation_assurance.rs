use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationEvidenceKind {
    TrustedOperator,
    SoftwareOnly,
    MeasuredBoot,
    SecureElement,
    CpuTee,
    GpuConfidentialCompute,
}

impl AttestationEvidenceKind {
    fn requires_endorsement(self) -> bool {
        matches!(
            self,
            Self::MeasuredBoot | Self::SecureElement | Self::CpuTee | Self::GpuConfidentialCompute
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationAssurancePosture {
    Unverified,
    TrustedOperator,
    SoftwareOnly,
    MeasuredBoot,
    SecureElement,
    CpuTee,
    GpuConfidentialCompute,
    CpuTeeAndGpuConfidentialCompute,
}

impl AttestationAssurancePosture {
    pub fn is_hardware_or_measured(self) -> bool {
        matches!(
            self,
            Self::MeasuredBoot
                | Self::SecureElement
                | Self::CpuTee
                | Self::GpuConfidentialCompute
                | Self::CpuTeeAndGpuConfidentialCompute
        )
    }

    fn requires_hardware_endorsement(self) -> bool {
        self.is_hardware_or_measured()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationNonceUseStatus {
    ConsumedForThisAppraisal,
    AlreadyConsumed,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationAppraisalStatus {
    Pass,
    Fail,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRevocationStatus {
    Current,
    Revoked,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationAssurancePolicy {
    pub policy_id: String,
    pub required_posture: AttestationAssurancePosture,
    pub relying_party_id: String,
    pub expected_nonce: String,
    pub expected_workload_identity: String,
    pub expected_daemon_build_hash: String,
    pub expected_policy_build_hash: String,
    pub expected_appraisal_policy_ref: String,
    pub expected_lease_ref: String,
    pub required_revocation_epoch: u64,
    pub now_ms: u64,
    pub max_appraisal_age_ms: u64,
    pub max_reattestation_interval_ms: u64,
    pub trusted_endorsement_refs: Vec<String>,
    pub trusted_reference_value_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub evidence_ref: String,
    pub kind: AttestationEvidenceKind,
    pub attester_id: String,
    pub verifier_id: String,
    pub appraiser_id: String,
    pub relying_party_id: String,
    pub nonce: String,
    pub nonce_use_status: AttestationNonceUseStatus,
    pub nonce_consumption_receipt_ref: Option<String>,
    pub workload_identity: String,
    pub daemon_build_hash: String,
    pub policy_build_hash: String,
    pub endorsement_refs: Vec<String>,
    pub reference_value_refs: Vec<String>,
    pub appraisal_policy_ref: String,
    pub appraisal_result_ref: Option<String>,
    pub appraisal_status: AttestationAppraisalStatus,
    pub appraised_at_ms: u64,
    pub appraisal_expires_at_ms: u64,
    pub reattest_by_ms: u64,
    pub lease_ref: Option<String>,
    pub lease_expires_at_ms: Option<u64>,
    pub revocation_epoch: Option<u64>,
    pub revocation_status: AttestationRevocationStatus,
    pub revocation_check_receipt_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationAssuranceInput {
    pub policy: AttestationAssurancePolicy,
    #[serde(default)]
    pub evidence: Vec<AttestationEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationFailureCode {
    RequiredBindingMissing,
    DuplicateEvidenceRef,
    RoleCollapse,
    WrongRelyingParty,
    NonceMismatch,
    NonceReplay,
    NonceSingleUseUnproven,
    WorkloadIdentityMismatch,
    DaemonBuildMismatch,
    PolicyBuildMismatch,
    UntrustedEndorsement,
    UntrustedReferenceValue,
    AppraisalPolicyMismatch,
    AppraisalRejected,
    AppraisalResultMissing,
    AppraisalStale,
    ReattestationOverdue,
    ReattestationCadenceExceeded,
    LeaseMissing,
    LeaseMismatch,
    LeaseExpired,
    RevocationEvidenceMissing,
    Revoked,
    RevocationEpochStale,
}

impl AttestationFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequiredBindingMissing => "required_binding_missing",
            Self::DuplicateEvidenceRef => "duplicate_evidence_ref",
            Self::RoleCollapse => "role_collapse",
            Self::WrongRelyingParty => "wrong_relying_party",
            Self::NonceMismatch => "nonce_mismatch",
            Self::NonceReplay => "nonce_replay",
            Self::NonceSingleUseUnproven => "nonce_single_use_unproven",
            Self::WorkloadIdentityMismatch => "workload_identity_mismatch",
            Self::DaemonBuildMismatch => "daemon_build_mismatch",
            Self::PolicyBuildMismatch => "policy_build_mismatch",
            Self::UntrustedEndorsement => "untrusted_endorsement",
            Self::UntrustedReferenceValue => "untrusted_reference_value",
            Self::AppraisalPolicyMismatch => "appraisal_policy_mismatch",
            Self::AppraisalRejected => "appraisal_rejected",
            Self::AppraisalResultMissing => "appraisal_result_missing",
            Self::AppraisalStale => "appraisal_stale",
            Self::ReattestationOverdue => "reattestation_overdue",
            Self::ReattestationCadenceExceeded => "reattestation_cadence_exceeded",
            Self::LeaseMissing => "lease_missing",
            Self::LeaseMismatch => "lease_mismatch",
            Self::LeaseExpired => "lease_expired",
            Self::RevocationEvidenceMissing => "revocation_evidence_missing",
            Self::Revoked => "revoked",
            Self::RevocationEpochStale => "revocation_epoch_stale",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::RequiredBindingMissing => "one or more required bindings are empty",
            Self::DuplicateEvidenceRef => "evidence reference is duplicated",
            Self::RoleCollapse => {
                "attester, verifier/appraiser, and relying-party roles are not separated"
            }
            Self::WrongRelyingParty => "evidence targets a different relying party",
            Self::NonceMismatch => "challenge nonce does not match",
            Self::NonceReplay => "challenge nonce was already consumed by another appraisal",
            Self::NonceSingleUseUnproven => {
                "single-use nonce consumption is not backed by a receipt"
            }
            Self::WorkloadIdentityMismatch => "workload identity does not match",
            Self::DaemonBuildMismatch => "daemon build hash does not match",
            Self::PolicyBuildMismatch => "policy build hash does not match",
            Self::UntrustedEndorsement => {
                "hardware or measured evidence lacks a trusted endorsement"
            }
            Self::UntrustedReferenceValue => "reference value is absent or not trusted",
            Self::AppraisalPolicyMismatch => "appraisal policy does not match",
            Self::AppraisalRejected => "appraisal did not pass",
            Self::AppraisalResultMissing => "appraisal result reference is missing",
            Self::AppraisalStale => "appraisal is stale or outside its validity window",
            Self::ReattestationOverdue => "re-attestation deadline has passed",
            Self::ReattestationCadenceExceeded => {
                "declared re-attestation deadline exceeds policy cadence"
            }
            Self::LeaseMissing => "capability lease evidence is missing",
            Self::LeaseMismatch => "capability lease does not match",
            Self::LeaseExpired => "capability lease is expired",
            Self::RevocationEvidenceMissing => "revocation check evidence is missing",
            Self::Revoked => "evidence or lease is revoked",
            Self::RevocationEpochStale => "revocation epoch is stale",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationFinding {
    pub evidence_ref: String,
    pub evidence_kind: AttestationEvidenceKind,
    pub code: AttestationFailureCode,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidenceDecision {
    pub evidence_ref: String,
    pub evidence_kind: AttestationEvidenceKind,
    pub eligible: bool,
    pub findings: Vec<AttestationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPolicyFinding {
    pub field: String,
    pub code: AttestationFailureCode,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationAssuranceReport {
    pub policy_id: String,
    pub required_posture: AttestationAssurancePosture,
    pub effective_posture: AttestationAssurancePosture,
    pub allowed: bool,
    pub hardware_or_measured_attested: bool,
    pub accepted_evidence_refs: Vec<String>,
    pub policy_findings: Vec<AttestationPolicyFinding>,
    pub evidence_decisions: Vec<AttestationEvidenceDecision>,
}

#[derive(Debug, Default, Clone)]
pub struct AttestationAssuranceEvaluator;

impl AttestationAssuranceEvaluator {
    pub fn evaluate(input: &AttestationAssuranceInput) -> AttestationAssuranceReport {
        let policy_findings = evaluate_policy(&input.policy);
        let mut evidence_ref_counts = BTreeMap::new();
        for evidence in &input.evidence {
            *evidence_ref_counts
                .entry(evidence.evidence_ref.as_str())
                .or_insert(0usize) += 1;
        }
        let duplicate_evidence_refs = evidence_ref_counts
            .into_iter()
            .filter_map(|(evidence_ref, count)| (count > 1).then_some(evidence_ref))
            .collect::<BTreeSet<_>>();
        let mut accepted_kinds = Vec::new();
        let mut accepted_evidence_refs = Vec::new();
        let evidence_decisions = input
            .evidence
            .iter()
            .map(|evidence| {
                let findings = evaluate_evidence(
                    &input.policy,
                    evidence,
                    duplicate_evidence_refs.contains(evidence.evidence_ref.as_str()),
                );
                let eligible = findings.is_empty();
                if eligible {
                    accepted_kinds.push(evidence.kind);
                    accepted_evidence_refs.push(evidence.evidence_ref.clone());
                }
                AttestationEvidenceDecision {
                    evidence_ref: evidence.evidence_ref.clone(),
                    evidence_kind: evidence.kind,
                    eligible,
                    findings,
                }
            })
            .collect();

        let effective_posture = strongest_posture(&accepted_kinds);
        AttestationAssuranceReport {
            policy_id: input.policy.policy_id.clone(),
            required_posture: input.policy.required_posture,
            effective_posture,
            allowed: policy_findings.is_empty()
                && accepted_kinds_satisfy(&accepted_kinds, input.policy.required_posture),
            hardware_or_measured_attested: effective_posture.is_hardware_or_measured(),
            accepted_evidence_refs,
            policy_findings,
            evidence_decisions,
        }
    }
}

fn evaluate_policy(policy: &AttestationAssurancePolicy) -> Vec<AttestationPolicyFinding> {
    let mut missing = Vec::new();
    for (field, value) in [
        ("policy_id", policy.policy_id.as_str()),
        ("relying_party_id", policy.relying_party_id.as_str()),
        ("expected_nonce", policy.expected_nonce.as_str()),
        (
            "expected_workload_identity",
            policy.expected_workload_identity.as_str(),
        ),
        (
            "expected_daemon_build_hash",
            policy.expected_daemon_build_hash.as_str(),
        ),
        (
            "expected_policy_build_hash",
            policy.expected_policy_build_hash.as_str(),
        ),
        (
            "expected_appraisal_policy_ref",
            policy.expected_appraisal_policy_ref.as_str(),
        ),
        ("expected_lease_ref", policy.expected_lease_ref.as_str()),
    ] {
        if value.trim().is_empty() {
            missing.push(field.to_string());
        }
    }
    if policy.trusted_reference_value_refs.is_empty()
        || policy
            .trusted_reference_value_refs
            .iter()
            .any(|value| value.trim().is_empty())
    {
        missing.push("trusted_reference_value_refs".to_string());
    }
    if policy
        .trusted_endorsement_refs
        .iter()
        .any(|value| value.trim().is_empty())
        || (policy.required_posture.requires_hardware_endorsement()
            && policy.trusted_endorsement_refs.is_empty())
    {
        missing.push("trusted_endorsement_refs".to_string());
    }

    missing
        .into_iter()
        .map(|field| AttestationPolicyFinding {
            field,
            code: AttestationFailureCode::RequiredBindingMissing,
            reason: AttestationFailureCode::RequiredBindingMissing
                .reason()
                .to_string(),
        })
        .collect()
}

fn accepted_kinds_satisfy(
    kinds: &[AttestationEvidenceKind],
    required: AttestationAssurancePosture,
) -> bool {
    let has = |kind| kinds.contains(&kind);
    match required {
        AttestationAssurancePosture::Unverified => true,
        AttestationAssurancePosture::TrustedOperator => !kinds.is_empty(),
        AttestationAssurancePosture::SoftwareOnly => kinds
            .iter()
            .any(|kind| !matches!(kind, AttestationEvidenceKind::TrustedOperator)),
        AttestationAssurancePosture::MeasuredBoot => has(AttestationEvidenceKind::MeasuredBoot),
        AttestationAssurancePosture::SecureElement => has(AttestationEvidenceKind::SecureElement),
        AttestationAssurancePosture::CpuTee => has(AttestationEvidenceKind::CpuTee),
        AttestationAssurancePosture::GpuConfidentialCompute => {
            has(AttestationEvidenceKind::GpuConfidentialCompute)
        }
        AttestationAssurancePosture::CpuTeeAndGpuConfidentialCompute => {
            has(AttestationEvidenceKind::CpuTee)
                && has(AttestationEvidenceKind::GpuConfidentialCompute)
        }
    }
}

fn evaluate_evidence(
    policy: &AttestationAssurancePolicy,
    evidence: &AttestationEvidence,
    evidence_ref_is_duplicate: bool,
) -> Vec<AttestationFinding> {
    let mut codes = Vec::new();

    if [
        evidence.evidence_ref.as_str(),
        evidence.attester_id.as_str(),
        evidence.verifier_id.as_str(),
        evidence.appraiser_id.as_str(),
        evidence.relying_party_id.as_str(),
        evidence.nonce.as_str(),
        evidence.workload_identity.as_str(),
        evidence.daemon_build_hash.as_str(),
        evidence.policy_build_hash.as_str(),
        evidence.appraisal_policy_ref.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        codes.push(AttestationFailureCode::RequiredBindingMissing);
    }
    if evidence_ref_is_duplicate {
        codes.push(AttestationFailureCode::DuplicateEvidenceRef);
    }
    if evidence.attester_id == evidence.verifier_id
        || evidence.attester_id == evidence.appraiser_id
        || evidence.attester_id == evidence.relying_party_id
        || evidence.verifier_id == evidence.relying_party_id
        || evidence.appraiser_id == evidence.relying_party_id
    {
        codes.push(AttestationFailureCode::RoleCollapse);
    }
    if evidence.relying_party_id != policy.relying_party_id {
        codes.push(AttestationFailureCode::WrongRelyingParty);
    }
    if evidence.nonce != policy.expected_nonce {
        codes.push(AttestationFailureCode::NonceMismatch);
    }
    match evidence.nonce_use_status {
        AttestationNonceUseStatus::ConsumedForThisAppraisal
            if !has_nonempty_option(&evidence.nonce_consumption_receipt_ref) =>
        {
            codes.push(AttestationFailureCode::NonceSingleUseUnproven);
        }
        AttestationNonceUseStatus::AlreadyConsumed => {
            codes.push(AttestationFailureCode::NonceReplay);
        }
        AttestationNonceUseStatus::Unverified => {
            codes.push(AttestationFailureCode::NonceSingleUseUnproven);
        }
        AttestationNonceUseStatus::ConsumedForThisAppraisal => {}
    }
    if evidence.workload_identity != policy.expected_workload_identity {
        codes.push(AttestationFailureCode::WorkloadIdentityMismatch);
    }
    if evidence.daemon_build_hash != policy.expected_daemon_build_hash {
        codes.push(AttestationFailureCode::DaemonBuildMismatch);
    }
    if evidence.policy_build_hash != policy.expected_policy_build_hash {
        codes.push(AttestationFailureCode::PolicyBuildMismatch);
    }
    if evidence.kind.requires_endorsement()
        && (evidence.endorsement_refs.is_empty()
            || evidence
                .endorsement_refs
                .iter()
                .any(|value| !policy.trusted_endorsement_refs.contains(value)))
    {
        codes.push(AttestationFailureCode::UntrustedEndorsement);
    }
    if evidence.reference_value_refs.is_empty()
        || evidence
            .reference_value_refs
            .iter()
            .any(|value| !policy.trusted_reference_value_refs.contains(value))
    {
        codes.push(AttestationFailureCode::UntrustedReferenceValue);
    }
    if evidence.appraisal_policy_ref != policy.expected_appraisal_policy_ref {
        codes.push(AttestationFailureCode::AppraisalPolicyMismatch);
    }
    if evidence.appraisal_status != AttestationAppraisalStatus::Pass {
        codes.push(AttestationFailureCode::AppraisalRejected);
    }
    if !has_nonempty_option(&evidence.appraisal_result_ref) {
        codes.push(AttestationFailureCode::AppraisalResultMissing);
    }
    if evidence.appraised_at_ms > policy.now_ms
        || evidence.appraisal_expires_at_ms <= policy.now_ms
        || evidence.appraisal_expires_at_ms <= evidence.appraised_at_ms
        || policy.now_ms.saturating_sub(evidence.appraised_at_ms) > policy.max_appraisal_age_ms
    {
        codes.push(AttestationFailureCode::AppraisalStale);
    }
    if evidence.reattest_by_ms <= policy.now_ms {
        codes.push(AttestationFailureCode::ReattestationOverdue);
    }
    if evidence.reattest_by_ms <= evidence.appraised_at_ms
        || evidence
            .reattest_by_ms
            .saturating_sub(evidence.appraised_at_ms)
            > policy.max_reattestation_interval_ms
    {
        codes.push(AttestationFailureCode::ReattestationCadenceExceeded);
    }
    match (&evidence.lease_ref, evidence.lease_expires_at_ms) {
        (Some(lease_ref), Some(expires_at_ms)) if !lease_ref.trim().is_empty() => {
            if lease_ref != &policy.expected_lease_ref {
                codes.push(AttestationFailureCode::LeaseMismatch);
            }
            if expires_at_ms <= policy.now_ms {
                codes.push(AttestationFailureCode::LeaseExpired);
            }
        }
        _ => codes.push(AttestationFailureCode::LeaseMissing),
    }
    match (
        evidence.revocation_epoch,
        evidence.revocation_status,
        &evidence.revocation_check_receipt_ref,
    ) {
        (Some(epoch), AttestationRevocationStatus::Current, Some(receipt_ref))
            if !receipt_ref.trim().is_empty() =>
        {
            if epoch < policy.required_revocation_epoch {
                codes.push(AttestationFailureCode::RevocationEpochStale);
            }
        }
        (_, AttestationRevocationStatus::Revoked, _) => {
            codes.push(AttestationFailureCode::Revoked);
        }
        _ => codes.push(AttestationFailureCode::RevocationEvidenceMissing),
    }

    codes
        .into_iter()
        .map(|code| AttestationFinding {
            evidence_ref: evidence.evidence_ref.clone(),
            evidence_kind: evidence.kind,
            code,
            reason: code.reason().to_string(),
        })
        .collect()
}

fn has_nonempty_option(value: &Option<String>) -> bool {
    value.as_ref().is_some_and(|value| !value.trim().is_empty())
}

fn strongest_posture(kinds: &[AttestationEvidenceKind]) -> AttestationAssurancePosture {
    let has = |kind| kinds.contains(&kind);
    if has(AttestationEvidenceKind::CpuTee) && has(AttestationEvidenceKind::GpuConfidentialCompute)
    {
        AttestationAssurancePosture::CpuTeeAndGpuConfidentialCompute
    } else if has(AttestationEvidenceKind::GpuConfidentialCompute) {
        AttestationAssurancePosture::GpuConfidentialCompute
    } else if has(AttestationEvidenceKind::CpuTee) {
        AttestationAssurancePosture::CpuTee
    } else if has(AttestationEvidenceKind::SecureElement) {
        AttestationAssurancePosture::SecureElement
    } else if has(AttestationEvidenceKind::MeasuredBoot) {
        AttestationAssurancePosture::MeasuredBoot
    } else if has(AttestationEvidenceKind::SoftwareOnly) {
        AttestationAssurancePosture::SoftwareOnly
    } else if has(AttestationEvidenceKind::TrustedOperator) {
        AttestationAssurancePosture::TrustedOperator
    } else {
        AttestationAssurancePosture::Unverified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(required_posture: AttestationAssurancePosture) -> AttestationAssurancePolicy {
        AttestationAssurancePolicy {
            policy_id: "policy://attestation/v1".to_string(),
            required_posture,
            relying_party_id: "runtime://startup-gate".to_string(),
            expected_nonce: "nonce-123".to_string(),
            expected_workload_identity: "workload://agent/7".to_string(),
            expected_daemon_build_hash: "sha256:daemon".to_string(),
            expected_policy_build_hash: "sha256:policy".to_string(),
            expected_appraisal_policy_ref: "policy://appraisal/v3".to_string(),
            expected_lease_ref: "lease://runtime/42".to_string(),
            required_revocation_epoch: 9,
            now_ms: 10_000,
            max_appraisal_age_ms: 2_000,
            max_reattestation_interval_ms: 3_000,
            trusted_endorsement_refs: vec!["endorsement://vendor/cpu".to_string()],
            trusted_reference_value_refs: vec!["reference://golden/7".to_string()],
        }
    }

    fn evidence(kind: AttestationEvidenceKind, suffix: &str) -> AttestationEvidence {
        AttestationEvidence {
            evidence_ref: format!("attestation://{suffix}"),
            kind,
            attester_id: "node://attester".to_string(),
            verifier_id: "service://verifier".to_string(),
            appraiser_id: "service://verifier".to_string(),
            relying_party_id: "runtime://startup-gate".to_string(),
            nonce: "nonce-123".to_string(),
            nonce_use_status: AttestationNonceUseStatus::ConsumedForThisAppraisal,
            nonce_consumption_receipt_ref: Some(format!("receipt://nonce/{suffix}")),
            workload_identity: "workload://agent/7".to_string(),
            daemon_build_hash: "sha256:daemon".to_string(),
            policy_build_hash: "sha256:policy".to_string(),
            endorsement_refs: if kind.requires_endorsement() {
                vec!["endorsement://vendor/cpu".to_string()]
            } else {
                vec![]
            },
            reference_value_refs: vec!["reference://golden/7".to_string()],
            appraisal_policy_ref: "policy://appraisal/v3".to_string(),
            appraisal_result_ref: Some(format!("appraisal://{suffix}")),
            appraisal_status: AttestationAppraisalStatus::Pass,
            appraised_at_ms: 9_000,
            appraisal_expires_at_ms: 11_000,
            reattest_by_ms: 11_500,
            lease_ref: Some("lease://runtime/42".to_string()),
            lease_expires_at_ms: Some(12_000),
            revocation_epoch: Some(9),
            revocation_status: AttestationRevocationStatus::Current,
            revocation_check_receipt_ref: Some(format!("receipt://revocation/{suffix}")),
        }
    }

    fn report(
        required_posture: AttestationAssurancePosture,
        evidence: Vec<AttestationEvidence>,
    ) -> AttestationAssuranceReport {
        AttestationAssuranceEvaluator::evaluate(&AttestationAssuranceInput {
            policy: policy(required_posture),
            evidence,
        })
    }

    #[test]
    fn valid_cpu_and_gpu_evidence_selects_composite_posture() {
        let report = report(
            AttestationAssurancePosture::CpuTee,
            vec![
                evidence(AttestationEvidenceKind::CpuTee, "cpu"),
                evidence(AttestationEvidenceKind::GpuConfidentialCompute, "gpu"),
            ],
        );

        assert!(report.allowed);
        assert!(report.hardware_or_measured_attested);
        assert_eq!(
            report.effective_posture,
            AttestationAssurancePosture::CpuTeeAndGpuConfidentialCompute
        );
    }

    #[test]
    fn replayed_hardware_evidence_narrows_to_valid_software_without_overclaim() {
        let mut replayed = evidence(AttestationEvidenceKind::CpuTee, "cpu-replay");
        replayed.nonce_use_status = AttestationNonceUseStatus::AlreadyConsumed;
        let report = report(
            AttestationAssurancePosture::SoftwareOnly,
            vec![
                replayed,
                evidence(AttestationEvidenceKind::SoftwareOnly, "software"),
            ],
        );

        assert!(report.allowed);
        assert_eq!(
            report.effective_posture,
            AttestationAssurancePosture::SoftwareOnly
        );
        assert!(!report.hardware_or_measured_attested);
        assert!(report.evidence_decisions[0]
            .findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::NonceReplay));
    }

    #[test]
    fn wrong_workload_and_build_refuse_stronger_evidence() {
        let mut wrong = evidence(AttestationEvidenceKind::CpuTee, "wrong-build");
        wrong.workload_identity = "workload://other".to_string();
        wrong.daemon_build_hash = "sha256:other-daemon".to_string();
        wrong.policy_build_hash = "sha256:other-policy".to_string();
        let report = report(AttestationAssurancePosture::CpuTee, vec![wrong]);

        assert!(!report.allowed);
        assert_eq!(
            report.effective_posture,
            AttestationAssurancePosture::Unverified
        );
        let findings = &report.evidence_decisions[0].findings;
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::WorkloadIdentityMismatch));
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::DaemonBuildMismatch));
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::PolicyBuildMismatch));
    }

    #[test]
    fn stale_appraisal_and_reattestation_deadline_refuse_hardware() {
        let mut stale = evidence(AttestationEvidenceKind::MeasuredBoot, "stale");
        stale.appraised_at_ms = 1_000;
        stale.appraisal_expires_at_ms = 9_999;
        stale.reattest_by_ms = 9_999;
        let report = report(AttestationAssurancePosture::MeasuredBoot, vec![stale]);

        assert!(!report.allowed);
        let findings = &report.evidence_decisions[0].findings;
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::AppraisalStale));
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::ReattestationOverdue));
    }

    #[test]
    fn untrusted_endorsement_and_reference_value_refuse_hardware() {
        let mut untrusted = evidence(AttestationEvidenceKind::SecureElement, "untrusted");
        untrusted.endorsement_refs = vec!["endorsement://foreign".to_string()];
        untrusted.reference_value_refs = vec!["reference://foreign".to_string()];
        let report = report(AttestationAssurancePosture::SecureElement, vec![untrusted]);

        assert!(!report.allowed);
        let findings = &report.evidence_decisions[0].findings;
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::UntrustedEndorsement));
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::UntrustedReferenceValue));
    }

    #[test]
    fn missing_lease_and_revocation_evidence_refuse_hardware() {
        let mut missing = evidence(AttestationEvidenceKind::CpuTee, "missing-state");
        missing.lease_ref = None;
        missing.lease_expires_at_ms = None;
        missing.revocation_epoch = None;
        missing.revocation_check_receipt_ref = None;
        missing.revocation_status = AttestationRevocationStatus::Unverified;
        let report = report(AttestationAssurancePosture::CpuTee, vec![missing]);

        assert!(!report.allowed);
        let findings = &report.evidence_decisions[0].findings;
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::LeaseMissing));
        assert!(findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::RevocationEvidenceMissing));
    }

    #[test]
    fn lost_gpu_evidence_deterministically_narrows_to_cpu_tee() {
        let cpu = evidence(AttestationEvidenceKind::CpuTee, "cpu");
        let mut gpu = evidence(AttestationEvidenceKind::GpuConfidentialCompute, "gpu");
        gpu.appraisal_status = AttestationAppraisalStatus::Fail;
        let report = report(AttestationAssurancePosture::CpuTee, vec![cpu, gpu]);

        assert!(report.allowed);
        assert_eq!(
            report.effective_posture,
            AttestationAssurancePosture::CpuTee
        );
        assert!(report.hardware_or_measured_attested);
    }

    #[test]
    fn trusted_operator_fallback_never_becomes_hardware_attested() {
        let mut failed_hardware = evidence(AttestationEvidenceKind::CpuTee, "cpu");
        failed_hardware.endorsement_refs.clear();
        let report = report(
            AttestationAssurancePosture::TrustedOperator,
            vec![
                failed_hardware,
                evidence(AttestationEvidenceKind::TrustedOperator, "operator"),
            ],
        );

        assert!(report.allowed);
        assert_eq!(
            report.effective_posture,
            AttestationAssurancePosture::TrustedOperator
        );
        assert!(!report.hardware_or_measured_attested);
    }

    #[test]
    fn gpu_display_precedence_does_not_substitute_for_required_cpu_tee() {
        let report = report(
            AttestationAssurancePosture::CpuTee,
            vec![evidence(
                AttestationEvidenceKind::GpuConfidentialCompute,
                "gpu-only",
            )],
        );

        assert!(!report.allowed);
        assert_eq!(
            report.effective_posture,
            AttestationAssurancePosture::GpuConfidentialCompute
        );
    }

    #[test]
    fn collapsed_attester_and_verifier_roles_are_ineligible() {
        let mut collapsed = evidence(AttestationEvidenceKind::MeasuredBoot, "collapsed");
        collapsed.verifier_id = collapsed.attester_id.clone();
        let report = report(AttestationAssurancePosture::MeasuredBoot, vec![collapsed]);

        assert!(!report.allowed);
        assert!(report.evidence_decisions[0]
            .findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::RoleCollapse));
    }

    #[test]
    fn empty_policy_identity_blocks_otherwise_valid_evidence() {
        let mut policy = policy(AttestationAssurancePosture::SoftwareOnly);
        policy.policy_id = "   ".to_string();
        let report = AttestationAssuranceEvaluator::evaluate(&AttestationAssuranceInput {
            policy,
            evidence: vec![evidence(AttestationEvidenceKind::SoftwareOnly, "software")],
        });

        assert!(!report.allowed);
        assert!(report.policy_findings.iter().any(|finding| {
            finding.field == "policy_id"
                && finding.code == AttestationFailureCode::RequiredBindingMissing
        }));
    }

    #[test]
    fn empty_evidence_and_role_bindings_are_ineligible() {
        let mut missing = evidence(AttestationEvidenceKind::SoftwareOnly, "missing-bindings");
        missing.evidence_ref = String::new();
        missing.attester_id = String::new();
        missing.appraiser_id = String::new();
        let report = report(AttestationAssurancePosture::SoftwareOnly, vec![missing]);

        assert!(!report.allowed);
        assert!(report.evidence_decisions[0]
            .findings
            .iter()
            .any(|finding| finding.code == AttestationFailureCode::RequiredBindingMissing));
    }

    #[test]
    fn duplicate_evidence_refs_are_refused() {
        let first = evidence(AttestationEvidenceKind::SoftwareOnly, "duplicate");
        let second = evidence(AttestationEvidenceKind::SoftwareOnly, "duplicate");
        let report = report(
            AttestationAssurancePosture::SoftwareOnly,
            vec![first, second],
        );

        assert!(!report.allowed);
        assert!(report.evidence_decisions.iter().all(|decision| {
            decision
                .findings
                .iter()
                .any(|finding| finding.code == AttestationFailureCode::DuplicateEvidenceRef)
        }));
    }

    #[test]
    fn verifier_and_appraiser_may_be_the_same_combined_role() {
        let combined = evidence(AttestationEvidenceKind::MeasuredBoot, "combined-role");
        assert_eq!(combined.verifier_id, combined.appraiser_id);

        let report = report(AttestationAssurancePosture::MeasuredBoot, vec![combined]);

        assert!(report.allowed);
        assert!(report.policy_findings.is_empty());
    }
}
