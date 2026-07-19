use serde::{Deserialize, Serialize};

use super::attestation_assurance::{
    AttestationAssuranceEvaluator, AttestationAssuranceInput, AttestationAssuranceReport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    Dev,
    Test,
    LocalProduct,
    Production,
    Marketplace,
    Validator,
}

impl RuntimeProfile {
    pub fn fail_closed(self) -> bool {
        matches!(self, Self::Production | Self::Marketplace | Self::Validator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProfileConfig {
    pub profile: RuntimeProfile,
    pub browser_no_sandbox_enabled: bool,
    pub dev_filesystem_mcp_enabled: bool,
    pub unverified_mcp_allowed: bool,
    pub unconfined_mcp_allowed: bool,
    pub unconfined_plugin_allowed: bool,
    pub unconfined_connector_allowed: bool,
    pub receipt_strictness_enabled: bool,
    pub external_approval_enforced: bool,
}

impl RuntimeProfileConfig {
    pub fn strict(profile: RuntimeProfile) -> Self {
        Self {
            profile,
            browser_no_sandbox_enabled: false,
            dev_filesystem_mcp_enabled: false,
            unverified_mcp_allowed: false,
            unconfined_mcp_allowed: false,
            unconfined_plugin_allowed: false,
            unconfined_connector_allowed: false,
            receipt_strictness_enabled: true,
            external_approval_enforced: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeProfileViolation {
    pub key: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStartupVerification {
    Verified,
    Failed { reason: String },
    Unavailable { reason: String },
    NotRequired { reason: String },
}

impl RuntimeStartupVerification {
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn is_verified_or_not_required(&self) -> bool {
        matches!(self, Self::Verified | Self::NotRequired { .. })
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Verified => None,
            Self::Failed { reason }
            | Self::Unavailable { reason }
            | Self::NotRequired { reason } => Some(reason.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStartupGateInput {
    pub profile_config: RuntimeProfileConfig,
    pub license: RuntimeStartupVerification,
    pub security_attestation: RuntimeStartupVerification,
    #[serde(default)]
    pub attestation_assurance: Option<AttestationAssuranceInput>,
    pub policy_config: RuntimeStartupVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStartupGateFailure {
    pub key: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStartupGateReport {
    pub profile: RuntimeProfile,
    pub fail_closed: bool,
    pub allowed: bool,
    #[serde(default)]
    pub attestation_assurance: Option<AttestationAssuranceReport>,
    pub failures: Vec<RuntimeStartupGateFailure>,
    pub warnings: Vec<RuntimeStartupGateFailure>,
}

impl RuntimeStartupGateReport {
    pub fn into_result(self) -> Result<Self, Self> {
        if self.allowed {
            Ok(self)
        } else {
            Err(self)
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeProfileValidator;

impl RuntimeProfileValidator {
    pub fn validate(config: &RuntimeProfileConfig) -> Result<(), Vec<RuntimeProfileViolation>> {
        if !config.profile.fail_closed() {
            return Ok(());
        }

        let mut violations = Vec::new();
        push_if(
            &mut violations,
            config.browser_no_sandbox_enabled,
            "browser_no_sandbox_enabled",
            "production profiles require browser sandboxing",
        );
        push_if(
            &mut violations,
            config.dev_filesystem_mcp_enabled,
            "dev_filesystem_mcp_enabled",
            "production profiles reject development filesystem MCP servers",
        );
        push_if(
            &mut violations,
            config.unverified_mcp_allowed,
            "unverified_mcp_allowed",
            "production profiles reject unverified MCP servers",
        );
        push_if(
            &mut violations,
            config.unconfined_mcp_allowed,
            "unconfined_mcp_allowed",
            "production profiles reject unconfined MCP servers",
        );
        push_if(
            &mut violations,
            config.unconfined_plugin_allowed,
            "unconfined_plugin_allowed",
            "production profiles reject unconfined plugins",
        );
        push_if(
            &mut violations,
            config.unconfined_connector_allowed,
            "unconfined_connector_allowed",
            "production profiles reject unconfined connectors",
        );
        push_if(
            &mut violations,
            !config.receipt_strictness_enabled,
            "receipt_strictness_enabled",
            "production profiles require strict receipt settlement",
        );
        push_if(
            &mut violations,
            !config.external_approval_enforced,
            "external_approval_enforced",
            "production profiles require external approval enforcement",
        );

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }

    pub fn evaluate_startup_gate(input: RuntimeStartupGateInput) -> RuntimeStartupGateReport {
        let fail_closed = input.profile_config.profile.fail_closed();
        let mut failures = Vec::new();
        let mut warnings = Vec::new();
        let attestation_assurance = input
            .attestation_assurance
            .as_ref()
            .map(AttestationAssuranceEvaluator::evaluate);

        if let Err(violations) = Self::validate(&input.profile_config) {
            for violation in violations {
                failures.push(RuntimeStartupGateFailure {
                    key: format!("profile.{}", violation.key),
                    reason: violation.reason.to_string(),
                });
            }
        }

        push_startup_verification(
            "license",
            input.license,
            fail_closed,
            &mut failures,
            &mut warnings,
        );
        if let Some(report) = &attestation_assurance {
            match input.security_attestation {
                RuntimeStartupVerification::Failed { reason } => {
                    failures.push(RuntimeStartupGateFailure {
                        key: "security_attestation.legacy_verifier".to_string(),
                        reason: format!(
                            "explicit legacy attestation failure cannot be superseded: {reason}"
                        ),
                    });
                }
                RuntimeStartupVerification::Unavailable { reason } => {
                    warnings.push(RuntimeStartupGateFailure {
                        key: "security_attestation.legacy_verifier".to_string(),
                        reason: format!(
                            "legacy verifier unavailable; independently evaluated structured evidence is authoritative: {reason}"
                        ),
                    });
                }
                RuntimeStartupVerification::Verified
                | RuntimeStartupVerification::NotRequired { .. } => {}
            }
            for finding in &report.policy_findings {
                failures.push(RuntimeStartupGateFailure {
                    key: format!("attestation_assurance.policy.{}", finding.field),
                    reason: finding.reason.clone(),
                });
            }
            for decision in report
                .evidence_decisions
                .iter()
                .filter(|decision| !decision.eligible)
            {
                let codes = decision
                    .findings
                    .iter()
                    .map(|finding| finding.code.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                warnings.push(RuntimeStartupGateFailure {
                    key: format!("attestation_assurance.evidence.{}", decision.evidence_ref),
                    reason: format!("{:?} evidence rejected: {codes}", decision.evidence_kind),
                });
            }
            if report.policy_findings.is_empty() && !report.allowed {
                failures.push(RuntimeStartupGateFailure {
                    key: "attestation_assurance.minimum_posture".to_string(),
                    reason: format!(
                        "effective posture {:?} does not satisfy required posture {:?}",
                        report.effective_posture, report.required_posture
                    ),
                });
            }
        } else {
            push_startup_verification(
                "security_attestation",
                input.security_attestation,
                fail_closed,
                &mut failures,
                &mut warnings,
            );
        }
        push_startup_verification(
            "policy_config",
            input.policy_config,
            fail_closed,
            &mut failures,
            &mut warnings,
        );

        RuntimeStartupGateReport {
            profile: input.profile_config.profile,
            fail_closed,
            allowed: failures.is_empty(),
            attestation_assurance,
            failures,
            warnings,
        }
    }
}

fn push_if(
    violations: &mut Vec<RuntimeProfileViolation>,
    condition: bool,
    key: &'static str,
    reason: &'static str,
) {
    if condition {
        violations.push(RuntimeProfileViolation { key, reason });
    }
}

fn push_startup_verification(
    key: &'static str,
    verification: RuntimeStartupVerification,
    fail_closed: bool,
    failures: &mut Vec<RuntimeStartupGateFailure>,
    warnings: &mut Vec<RuntimeStartupGateFailure>,
) {
    if verification.is_verified_or_not_required() {
        return;
    }

    let record = RuntimeStartupGateFailure {
        key: key.to_string(),
        reason: verification
            .reason()
            .unwrap_or("startup verification failed")
            .to_string(),
    };

    if fail_closed {
        failures.push(record);
    } else {
        warnings.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::attestation_assurance::{
        AttestationAppraisalStatus, AttestationAssurancePolicy, AttestationAssurancePosture,
        AttestationEvidence, AttestationEvidenceKind, AttestationNonceUseStatus,
        AttestationRevocationStatus,
    };

    fn gate_input(
        profile: RuntimeProfile,
        license: RuntimeStartupVerification,
    ) -> RuntimeStartupGateInput {
        RuntimeStartupGateInput {
            profile_config: RuntimeProfileConfig::strict(profile),
            license,
            security_attestation: RuntimeStartupVerification::NotRequired {
                reason: "test profile does not configure remote attestation".to_string(),
            },
            attestation_assurance: None,
            policy_config: RuntimeStartupVerification::Verified,
        }
    }

    fn structured_attestation_input(
        required_posture: AttestationAssurancePosture,
        evidence: Vec<AttestationEvidence>,
    ) -> AttestationAssuranceInput {
        AttestationAssuranceInput {
            policy: AttestationAssurancePolicy {
                policy_id: "policy://startup-attestation/v1".to_string(),
                required_posture,
                relying_party_id: "runtime://startup-gate".to_string(),
                expected_nonce: "nonce-1".to_string(),
                expected_workload_identity: "workload://agent".to_string(),
                expected_daemon_build_hash: "sha256:daemon".to_string(),
                expected_policy_build_hash: "sha256:policy".to_string(),
                expected_appraisal_policy_ref: "policy://appraisal/v1".to_string(),
                expected_lease_ref: "lease://agent".to_string(),
                required_revocation_epoch: 4,
                now_ms: 1_000,
                max_appraisal_age_ms: 500,
                max_reattestation_interval_ms: 1_000,
                trusted_endorsement_refs: vec!["endorsement://vendor".to_string()],
                trusted_reference_value_refs: vec!["reference://approved".to_string()],
            },
            evidence,
        }
    }

    fn structured_evidence(
        kind: AttestationEvidenceKind,
        evidence_ref: &str,
    ) -> AttestationEvidence {
        AttestationEvidence {
            evidence_ref: evidence_ref.to_string(),
            kind,
            attester_id: "node://attester".to_string(),
            verifier_id: "service://verifier".to_string(),
            appraiser_id: "service://verifier".to_string(),
            relying_party_id: "runtime://startup-gate".to_string(),
            nonce: "nonce-1".to_string(),
            nonce_use_status: AttestationNonceUseStatus::ConsumedForThisAppraisal,
            nonce_consumption_receipt_ref: Some("receipt://nonce/1".to_string()),
            workload_identity: "workload://agent".to_string(),
            daemon_build_hash: "sha256:daemon".to_string(),
            policy_build_hash: "sha256:policy".to_string(),
            endorsement_refs: if matches!(
                kind,
                AttestationEvidenceKind::MeasuredBoot
                    | AttestationEvidenceKind::SecureElement
                    | AttestationEvidenceKind::CpuTee
                    | AttestationEvidenceKind::GpuConfidentialCompute
            ) {
                vec!["endorsement://vendor".to_string()]
            } else {
                vec![]
            },
            reference_value_refs: vec!["reference://approved".to_string()],
            appraisal_policy_ref: "policy://appraisal/v1".to_string(),
            appraisal_result_ref: Some("appraisal://1".to_string()),
            appraisal_status: AttestationAppraisalStatus::Pass,
            appraised_at_ms: 900,
            appraisal_expires_at_ms: 1_500,
            reattest_by_ms: 1_500,
            lease_ref: Some("lease://agent".to_string()),
            lease_expires_at_ms: Some(2_000),
            revocation_epoch: Some(4),
            revocation_status: AttestationRevocationStatus::Current,
            revocation_check_receipt_ref: Some("receipt://revocation/4".to_string()),
        }
    }

    #[test]
    fn startup_gate_blocks_failed_license_in_production_profile() {
        let report = RuntimeProfileValidator::evaluate_startup_gate(gate_input(
            RuntimeProfile::Production,
            RuntimeStartupVerification::failed("license proof rejected"),
        ));

        assert!(!report.allowed);
        assert!(report.fail_closed);
        assert!(report
            .failures
            .iter()
            .any(|failure| failure.key == "license"));
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn startup_gate_warns_for_failed_license_in_dev_profile() {
        let report = RuntimeProfileValidator::evaluate_startup_gate(gate_input(
            RuntimeProfile::Dev,
            RuntimeStartupVerification::failed("license verifier unavailable"),
        ));

        assert!(report.allowed);
        assert!(!report.fail_closed);
        assert!(report.failures.is_empty());
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.key == "license"));
    }

    #[test]
    fn startup_gate_includes_profile_violations_in_fail_closed_profiles() {
        let mut profile_config = RuntimeProfileConfig::strict(RuntimeProfile::Marketplace);
        profile_config.unverified_mcp_allowed = true;

        let report = RuntimeProfileValidator::evaluate_startup_gate(RuntimeStartupGateInput {
            profile_config,
            license: RuntimeStartupVerification::Verified,
            security_attestation: RuntimeStartupVerification::NotRequired {
                reason: "marketplace binary has no remote attestation hook in this test"
                    .to_string(),
            },
            attestation_assurance: None,
            policy_config: RuntimeStartupVerification::Verified,
        });

        assert!(!report.allowed);
        assert!(report
            .failures
            .iter()
            .any(|failure| failure.key == "profile.unverified_mcp_allowed"));
    }

    #[test]
    fn startup_gate_attestation_assurance_preserves_valid_fallback() {
        let mut replayed_hardware =
            structured_evidence(AttestationEvidenceKind::CpuTee, "attestation://cpu");
        replayed_hardware.nonce_use_status = AttestationNonceUseStatus::AlreadyConsumed;
        let software = structured_evidence(
            AttestationEvidenceKind::SoftwareOnly,
            "attestation://software",
        );
        let mut input = gate_input(
            RuntimeProfile::Production,
            RuntimeStartupVerification::Verified,
        );
        input.attestation_assurance = Some(structured_attestation_input(
            AttestationAssurancePosture::SoftwareOnly,
            vec![replayed_hardware, software],
        ));

        let report = RuntimeProfileValidator::evaluate_startup_gate(input);

        assert!(report.allowed);
        let attestation = report.attestation_assurance.expect("structured report");
        assert_eq!(
            attestation.effective_posture,
            AttestationAssurancePosture::SoftwareOnly
        );
        assert!(!attestation.hardware_or_measured_attested);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.reason.contains("nonce_replay")));
    }

    #[test]
    fn startup_gate_attestation_assurance_blocks_unmet_minimum_posture() {
        let mut wrong_build =
            structured_evidence(AttestationEvidenceKind::CpuTee, "attestation://cpu");
        wrong_build.daemon_build_hash = "sha256:foreign".to_string();
        let mut input = gate_input(RuntimeProfile::Dev, RuntimeStartupVerification::Verified);
        input.attestation_assurance = Some(structured_attestation_input(
            AttestationAssurancePosture::CpuTee,
            vec![wrong_build],
        ));

        let report = RuntimeProfileValidator::evaluate_startup_gate(input);

        assert!(!report.allowed);
        assert!(report
            .failures
            .iter()
            .any(|failure| failure.key == "attestation_assurance.minimum_posture"));
    }

    #[test]
    fn startup_gate_attestation_assurance_cannot_hide_explicit_legacy_failure() {
        let software = structured_evidence(
            AttestationEvidenceKind::SoftwareOnly,
            "attestation://software",
        );
        let mut input = gate_input(RuntimeProfile::Dev, RuntimeStartupVerification::Verified);
        input.security_attestation =
            RuntimeStartupVerification::failed("legacy signature verification rejected");
        input.attestation_assurance = Some(structured_attestation_input(
            AttestationAssurancePosture::SoftwareOnly,
            vec![software],
        ));

        let report = RuntimeProfileValidator::evaluate_startup_gate(input);

        assert!(!report.allowed);
        assert!(report
            .failures
            .iter()
            .any(|failure| failure.key == "security_attestation.legacy_verifier"));
    }

    #[test]
    fn startup_gate_attestation_assurance_reports_superseded_legacy_unavailability() {
        let software = structured_evidence(
            AttestationEvidenceKind::SoftwareOnly,
            "attestation://software",
        );
        let mut input = gate_input(
            RuntimeProfile::Production,
            RuntimeStartupVerification::Verified,
        );
        input.security_attestation =
            RuntimeStartupVerification::unavailable("legacy verifier is offline");
        input.attestation_assurance = Some(structured_attestation_input(
            AttestationAssurancePosture::SoftwareOnly,
            vec![software],
        ));

        let report = RuntimeProfileValidator::evaluate_startup_gate(input);

        assert!(report.allowed);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.key == "security_attestation.legacy_verifier"));
    }
}
