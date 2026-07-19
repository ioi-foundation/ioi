//! Pure deployment-policy obligation projection.
//!
//! This module evaluates the already-owned `JurisdictionPolicyPack`,
//! `AssuranceEvidenceBundle`, and `AssurancePostureProjection` semantics. It
//! does not create a policy registry, send reports, erase data, or determine
//! legal conformity.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentClockBasis {
    DetectedAt,
    ConfirmedAt,
    MaterialityDeterminedAt,
    AuthorityRequestReceivedAt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBundleValidity {
    Valid,
    Incomplete,
    Stale,
    Disputed,
    Revoked,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProjectionState {
    Complete,
    Incomplete,
    Stale,
    Disputed,
    Revoked,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReportingState {
    NotTriggered,
    ClockRunning,
    NoticeDue,
    NoticeSubmitted,
    ReportDue,
    ReportSubmitted,
    Overdue,
    Disputed,
    NotApplicable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureEvidenceState {
    NotRequested,
    Pending,
    CryptoShredded,
    VerifiedErased,
    PartiallyErased,
    Excepted,
    Disputed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalConformityClaim {
    NotDetermined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentObligationDisposition {
    Current,
    ActionRequired,
    EvidenceIncomplete,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentObligationFindingSeverity {
    InvalidInput,
    ObligationDue,
    EvidenceGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentObligationFindingCode {
    RequiredBindingMissing,
    InvalidSemanticVersion,
    DuplicateIncidentRule,
    IncidentRuleMissing,
    IncidentClockEvidenceMissing,
    IncidentClockInFuture,
    DeadlineOrderInvalid,
    DeadlineOverflow,
    SubmissionEvidenceIncomplete,
    SubmissionBeforeClock,
    SubmissionInFuture,
    NoticeOverdue,
    ReportOverdue,
    NoticeSubmittedLate,
    ReportSubmittedLate,
    EvidenceBundleIncomplete,
    EvidenceProjectionStale,
    EvidenceProjectionInFuture,
    EvidenceDisputed,
    EvidenceRevoked,
    EvidenceUnavailable,
    CryptoShreddingNotEligible,
    CryptoShreddingPolicyMissing,
    ErasureVerificationProfileMissing,
    ErasureVerificationEvidenceMissing,
    ErasureScopeIncomplete,
    ErasureBlockedByRetention,
    ExceptionPolicyMissing,
    ErasureEvidenceContradiction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentObligationFinding {
    pub code: DeploymentObligationFindingCode,
    pub severity: DeploymentObligationFindingSeverity,
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentDeadlineRule {
    pub rule_id: String,
    pub deadline_version: String,
    pub incident_class: String,
    pub clock_start_basis: IncidentClockBasis,
    pub initial_notice_within_ms: Option<u64>,
    pub full_report_within_ms: Option<u64>,
    pub recipient_ref: String,
    pub evidence_projection_profile_ref: String,
    pub responsible_ref: String,
    pub accountable_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JurisdictionPolicyPackEvaluationInput {
    pub pack_ref: String,
    pub pack_version: String,
    pub incident_rules_version: String,
    pub issuer_ref: String,
    pub responsible_issuer_ref: String,
    pub accountable_issuer_ref: String,
    pub incident_deadline_rules: Vec<IncidentDeadlineRule>,
    pub crypto_shredding_eligible: bool,
    pub crypto_shredding_policy_ref: Option<String>,
    pub erasure_verification_profile_ref: Option<String>,
    pub erasure_exception_policy_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentClockFacts {
    pub incident_ref: String,
    pub incident_class: String,
    pub detected_at_ms: Option<u64>,
    pub confirmed_at_ms: Option<u64>,
    pub materiality_determined_at_ms: Option<u64>,
    pub authority_request_received_at_ms: Option<u64>,
    pub clock_evidence_ref: String,
    #[serde(default)]
    pub disputed: bool,
}

impl IncidentClockFacts {
    fn timestamp_for(&self, basis: IncidentClockBasis) -> Option<u64> {
        match basis {
            IncidentClockBasis::DetectedAt => self.detected_at_ms,
            IncidentClockBasis::ConfirmedAt => self.confirmed_at_ms,
            IncidentClockBasis::MaterialityDeterminedAt => self.materiality_determined_at_ms,
            IncidentClockBasis::AuthorityRequestReceivedAt => self.authority_request_received_at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportingSubmissionEvidence {
    pub submitted_at_ms: u64,
    pub receipt_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IncidentReportingEvidence {
    pub notice: Option<ReportingSubmissionEvidence>,
    pub report: Option<ReportingSubmissionEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ErasureEvidenceInput {
    pub erasure_request_ref: Option<String>,
    pub crypto_shredding_receipt_refs: Vec<String>,
    pub deletion_receipt_refs: Vec<String>,
    pub verification_receipt_refs: Vec<String>,
    pub exception_refs: Vec<String>,
    #[serde(default)]
    pub replica_scope_complete: bool,
    #[serde(default)]
    pub derivative_scope_complete: bool,
    #[serde(default)]
    pub backup_scope_complete: bool,
    #[serde(default)]
    pub retention_lock_active: bool,
    #[serde(default)]
    pub legal_hold_active: bool,
    #[serde(default)]
    pub disputed: bool,
}

impl ErasureEvidenceInput {
    fn has_any_evidence(&self) -> bool {
        !self.crypto_shredding_receipt_refs.is_empty()
            || !self.deletion_receipt_refs.is_empty()
            || !self.verification_receipt_refs.is_empty()
            || !self.exception_refs.is_empty()
    }

    fn scope_complete(&self) -> bool {
        self.replica_scope_complete && self.derivative_scope_complete && self.backup_scope_complete
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceEvidenceBundleEvaluationInput {
    pub bundle_ref: String,
    pub validity: EvidenceBundleValidity,
    pub evidence_watermark: String,
    pub evaluated_at_ms: u64,
    pub maximum_projection_age_ms: u64,
    pub evidence_refs: Vec<String>,
    pub incident: Option<IncidentClockFacts>,
    #[serde(default)]
    pub reporting_evidence: IncidentReportingEvidence,
    #[serde(default)]
    pub erasure_evidence: ErasureEvidenceInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPolicyObligationsInput {
    pub now_ms: u64,
    pub jurisdiction_policy_pack: JurisdictionPolicyPackEvaluationInput,
    pub assurance_evidence_bundle: AssuranceEvidenceBundleEvaluationInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReportingProjection {
    pub incident_ref: Option<String>,
    pub selected_rule_id: Option<String>,
    pub selected_deadline_version: Option<String>,
    pub incident_rules_version: String,
    pub clock_start_basis: Option<IncidentClockBasis>,
    pub clock_started_at_ms: Option<u64>,
    pub clock_evidence_ref: Option<String>,
    pub notice_due_at_ms: Option<u64>,
    pub report_due_at_ms: Option<u64>,
    pub notice_submitted_at_ms: Option<u64>,
    pub notice_receipt_ref: Option<String>,
    pub report_submitted_at_ms: Option<u64>,
    pub report_receipt_ref: Option<String>,
    pub recipient_ref: Option<String>,
    pub responsible_ref: Option<String>,
    pub accountable_ref: Option<String>,
    pub state: IncidentReportingState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPolicyObligationsProjection {
    pub jurisdiction_policy_pack_ref: String,
    pub jurisdiction_policy_pack_version: String,
    pub issuer_ref: String,
    pub responsible_issuer_ref: String,
    pub accountable_issuer_ref: String,
    pub assurance_evidence_bundle_ref: String,
    pub evidence_watermark: String,
    pub evidence_projection_state: EvidenceProjectionState,
    pub incident_reporting: IncidentReportingProjection,
    pub erasure_evidence_state: ErasureEvidenceState,
    pub legal_conformity_claim: LegalConformityClaim,
    pub generated_at_ms: u64,
    pub disposition: DeploymentObligationDisposition,
    pub findings: Vec<DeploymentObligationFinding>,
}

#[derive(Debug, Default, Clone)]
pub struct DeploymentPolicyObligationsEvaluator;

impl DeploymentPolicyObligationsEvaluator {
    pub fn evaluate(
        input: &DeploymentPolicyObligationsInput,
    ) -> DeploymentPolicyObligationsProjection {
        let mut findings = Vec::new();
        validate_pack(&input.jurisdiction_policy_pack, &mut findings);
        validate_bundle_bindings(&input.assurance_evidence_bundle, &mut findings);

        let evidence_projection_state = project_evidence_state(input, &mut findings);
        let incident_reporting = project_incident_reporting(input, &mut findings);
        let erasure_evidence_state = project_erasure_state(input, &mut findings);
        let disposition = disposition_for(&findings);

        DeploymentPolicyObligationsProjection {
            jurisdiction_policy_pack_ref: input.jurisdiction_policy_pack.pack_ref.clone(),
            jurisdiction_policy_pack_version: input.jurisdiction_policy_pack.pack_version.clone(),
            issuer_ref: input.jurisdiction_policy_pack.issuer_ref.clone(),
            responsible_issuer_ref: input
                .jurisdiction_policy_pack
                .responsible_issuer_ref
                .clone(),
            accountable_issuer_ref: input
                .jurisdiction_policy_pack
                .accountable_issuer_ref
                .clone(),
            assurance_evidence_bundle_ref: input.assurance_evidence_bundle.bundle_ref.clone(),
            evidence_watermark: input.assurance_evidence_bundle.evidence_watermark.clone(),
            evidence_projection_state,
            incident_reporting,
            erasure_evidence_state,
            legal_conformity_claim: LegalConformityClaim::NotDetermined,
            generated_at_ms: input.now_ms,
            disposition,
            findings,
        }
    }
}

fn validate_pack(
    pack: &JurisdictionPolicyPackEvaluationInput,
    findings: &mut Vec<DeploymentObligationFinding>,
) {
    for (field, value) in [
        ("jurisdiction_policy_pack.pack_ref", pack.pack_ref.as_str()),
        (
            "jurisdiction_policy_pack.issuer_ref",
            pack.issuer_ref.as_str(),
        ),
        (
            "jurisdiction_policy_pack.responsible_issuer_ref",
            pack.responsible_issuer_ref.as_str(),
        ),
        (
            "jurisdiction_policy_pack.accountable_issuer_ref",
            pack.accountable_issuer_ref.as_str(),
        ),
    ] {
        require_binding(field, value, findings);
    }
    validate_version(
        "jurisdiction_policy_pack.pack_version",
        &pack.pack_version,
        findings,
    );
    validate_version(
        "jurisdiction_policy_pack.incident_rules_version",
        &pack.incident_rules_version,
        findings,
    );

    let mut incident_classes = BTreeSet::new();
    let mut rule_ids = BTreeSet::new();
    for rule in &pack.incident_deadline_rules {
        for (field, value) in [
            ("incident_rule.rule_id", rule.rule_id.as_str()),
            ("incident_rule.incident_class", rule.incident_class.as_str()),
            ("incident_rule.recipient_ref", rule.recipient_ref.as_str()),
            (
                "incident_rule.evidence_projection_profile_ref",
                rule.evidence_projection_profile_ref.as_str(),
            ),
            (
                "incident_rule.responsible_ref",
                rule.responsible_ref.as_str(),
            ),
            (
                "incident_rule.accountable_ref",
                rule.accountable_ref.as_str(),
            ),
        ] {
            require_binding(field, value, findings);
        }
        validate_version(
            "incident_rule.deadline_version",
            &rule.deadline_version,
            findings,
        );
        if rule.initial_notice_within_ms.is_none() && rule.full_report_within_ms.is_none() {
            push_finding(
                findings,
                DeploymentObligationFindingCode::DeadlineOrderInvalid,
                DeploymentObligationFindingSeverity::InvalidInput,
                "incident_rule.deadlines",
                "incident deadline rule must declare a notice or full-report deadline",
            );
        }
        if let (Some(notice), Some(report)) =
            (rule.initial_notice_within_ms, rule.full_report_within_ms)
        {
            if notice > report {
                push_finding(
                    findings,
                    DeploymentObligationFindingCode::DeadlineOrderInvalid,
                    DeploymentObligationFindingSeverity::InvalidInput,
                    "incident_rule.deadlines",
                    "initial notice deadline cannot be later than full report deadline",
                );
            }
        }

        if !incident_classes.insert(rule.incident_class.as_str())
            || !rule_ids.insert(rule.rule_id.as_str())
        {
            push_finding(
                findings,
                DeploymentObligationFindingCode::DuplicateIncidentRule,
                DeploymentObligationFindingSeverity::InvalidInput,
                "incident_rule",
                "incident class and rule id must each be unique within an active pack",
            );
        }
    }
}

fn validate_bundle_bindings(
    bundle: &AssuranceEvidenceBundleEvaluationInput,
    findings: &mut Vec<DeploymentObligationFinding>,
) {
    require_binding(
        "assurance_evidence_bundle.bundle_ref",
        &bundle.bundle_ref,
        findings,
    );
    require_binding(
        "assurance_evidence_bundle.evidence_watermark",
        &bundle.evidence_watermark,
        findings,
    );
    if bundle.maximum_projection_age_ms == 0 {
        push_finding(
            findings,
            DeploymentObligationFindingCode::RequiredBindingMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "assurance_evidence_bundle.maximum_projection_age_ms",
            "maximum projection age must be greater than zero",
        );
    }
    if bundle
        .evidence_refs
        .iter()
        .any(|value| value.trim().is_empty())
    {
        push_finding(
            findings,
            DeploymentObligationFindingCode::RequiredBindingMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "assurance_evidence_bundle.evidence_refs",
            "evidence references must be nonempty",
        );
    }
}

fn project_evidence_state(
    input: &DeploymentPolicyObligationsInput,
    findings: &mut Vec<DeploymentObligationFinding>,
) -> EvidenceProjectionState {
    let bundle = &input.assurance_evidence_bundle;
    if bundle.evidence_refs.is_empty() || bundle.evidence_watermark.trim().is_empty() {
        push_finding(
            findings,
            DeploymentObligationFindingCode::EvidenceBundleIncomplete,
            DeploymentObligationFindingSeverity::EvidenceGap,
            "assurance_evidence_bundle",
            "a complete projection requires evidence refs and a watermark",
        );
        return EvidenceProjectionState::Incomplete;
    }

    match bundle.validity {
        EvidenceBundleValidity::Valid => {
            if bundle.evaluated_at_ms > input.now_ms {
                push_finding(
                    findings,
                    DeploymentObligationFindingCode::EvidenceProjectionInFuture,
                    DeploymentObligationFindingSeverity::InvalidInput,
                    "assurance_evidence_bundle.evaluated_at_ms",
                    "evidence projection timestamp cannot be in the future",
                );
                EvidenceProjectionState::Stale
            } else if input.now_ms.saturating_sub(bundle.evaluated_at_ms)
                > bundle.maximum_projection_age_ms
            {
                push_finding(
                    findings,
                    DeploymentObligationFindingCode::EvidenceProjectionStale,
                    DeploymentObligationFindingSeverity::EvidenceGap,
                    "assurance_evidence_bundle.evaluated_at_ms",
                    "evidence projection is outside its admitted freshness window",
                );
                EvidenceProjectionState::Stale
            } else {
                EvidenceProjectionState::Complete
            }
        }
        EvidenceBundleValidity::Incomplete => {
            push_finding(
                findings,
                DeploymentObligationFindingCode::EvidenceBundleIncomplete,
                DeploymentObligationFindingSeverity::EvidenceGap,
                "assurance_evidence_bundle.validity",
                "evidence bundle is incomplete",
            );
            EvidenceProjectionState::Incomplete
        }
        EvidenceBundleValidity::Stale => {
            push_finding(
                findings,
                DeploymentObligationFindingCode::EvidenceProjectionStale,
                DeploymentObligationFindingSeverity::EvidenceGap,
                "assurance_evidence_bundle.validity",
                "evidence bundle is stale",
            );
            EvidenceProjectionState::Stale
        }
        EvidenceBundleValidity::Disputed => {
            push_finding(
                findings,
                DeploymentObligationFindingCode::EvidenceDisputed,
                DeploymentObligationFindingSeverity::EvidenceGap,
                "assurance_evidence_bundle.validity",
                "evidence bundle is disputed",
            );
            EvidenceProjectionState::Disputed
        }
        EvidenceBundleValidity::Revoked => {
            push_finding(
                findings,
                DeploymentObligationFindingCode::EvidenceRevoked,
                DeploymentObligationFindingSeverity::EvidenceGap,
                "assurance_evidence_bundle.validity",
                "evidence bundle is revoked",
            );
            EvidenceProjectionState::Revoked
        }
        EvidenceBundleValidity::Unavailable => {
            push_finding(
                findings,
                DeploymentObligationFindingCode::EvidenceUnavailable,
                DeploymentObligationFindingSeverity::EvidenceGap,
                "assurance_evidence_bundle.validity",
                "evidence bundle is unavailable",
            );
            EvidenceProjectionState::Unavailable
        }
    }
}

fn project_incident_reporting(
    input: &DeploymentPolicyObligationsInput,
    findings: &mut Vec<DeploymentObligationFinding>,
) -> IncidentReportingProjection {
    let pack = &input.jurisdiction_policy_pack;
    let bundle = &input.assurance_evidence_bundle;
    let Some(incident) = &bundle.incident else {
        if bundle.reporting_evidence.notice.is_some() || bundle.reporting_evidence.report.is_some()
        {
            push_finding(
                findings,
                DeploymentObligationFindingCode::SubmissionEvidenceIncomplete,
                DeploymentObligationFindingSeverity::InvalidInput,
                "assurance_evidence_bundle.reporting_evidence",
                "reporting submissions cannot exist without an incident binding",
            );
            return empty_incident_projection(
                &pack.incident_rules_version,
                IncidentReportingState::Unknown,
            );
        }
        return empty_incident_projection(
            &pack.incident_rules_version,
            IncidentReportingState::NotTriggered,
        );
    };

    require_binding("incident.incident_ref", &incident.incident_ref, findings);
    require_binding(
        "incident.incident_class",
        &incident.incident_class,
        findings,
    );
    require_binding(
        "incident.clock_evidence_ref",
        &incident.clock_evidence_ref,
        findings,
    );

    let rules = pack
        .incident_deadline_rules
        .iter()
        .filter(|rule| rule.incident_class == incident.incident_class)
        .collect::<Vec<_>>();
    if rules.len() != 1 {
        push_finding(
            findings,
            if rules.is_empty() {
                DeploymentObligationFindingCode::IncidentRuleMissing
            } else {
                DeploymentObligationFindingCode::DuplicateIncidentRule
            },
            DeploymentObligationFindingSeverity::InvalidInput,
            "incident.incident_class",
            "incident must resolve to exactly one deadline rule",
        );
        return IncidentReportingProjection {
            incident_ref: Some(incident.incident_ref.clone()),
            selected_rule_id: None,
            selected_deadline_version: None,
            incident_rules_version: pack.incident_rules_version.clone(),
            clock_start_basis: None,
            clock_started_at_ms: None,
            clock_evidence_ref: None,
            notice_due_at_ms: None,
            report_due_at_ms: None,
            notice_submitted_at_ms: None,
            notice_receipt_ref: None,
            report_submitted_at_ms: None,
            report_receipt_ref: None,
            recipient_ref: None,
            responsible_ref: None,
            accountable_ref: None,
            state: IncidentReportingState::Unknown,
        };
    }
    let rule = rules[0];
    let Some(clock_started_at_ms) = incident.timestamp_for(rule.clock_start_basis) else {
        push_finding(
            findings,
            DeploymentObligationFindingCode::IncidentClockEvidenceMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "incident.clock",
            "selected incident clock basis has no timestamp evidence",
        );
        return incident_projection_for_rule(
            pack,
            incident,
            rule,
            None,
            None,
            None,
            None,
            None,
            IncidentReportingState::Unknown,
        );
    };
    if incident.clock_evidence_ref.trim().is_empty() {
        push_finding(
            findings,
            DeploymentObligationFindingCode::IncidentClockEvidenceMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "incident.clock_evidence_ref",
            "incident clock timestamp requires evidence",
        );
    }
    if clock_started_at_ms > input.now_ms {
        push_finding(
            findings,
            DeploymentObligationFindingCode::IncidentClockInFuture,
            DeploymentObligationFindingSeverity::InvalidInput,
            "incident.clock",
            "incident reporting clock cannot start in the future",
        );
    }

    let notice_due_at_ms = deadline_at(
        clock_started_at_ms,
        rule.initial_notice_within_ms,
        "incident_rule.initial_notice_within_ms",
        findings,
    );
    let report_due_at_ms = deadline_at(
        clock_started_at_ms,
        rule.full_report_within_ms,
        "incident_rule.full_report_within_ms",
        findings,
    );
    let notice = validate_submission(
        "notice",
        bundle.reporting_evidence.notice.as_ref(),
        clock_started_at_ms,
        input.now_ms,
        findings,
    );
    let report = validate_submission(
        "report",
        bundle.reporting_evidence.report.as_ref(),
        clock_started_at_ms,
        input.now_ms,
        findings,
    );

    if let (Some(submission), Some(due_at_ms)) = (notice, notice_due_at_ms) {
        if submission.submitted_at_ms > due_at_ms {
            push_finding(
                findings,
                DeploymentObligationFindingCode::NoticeSubmittedLate,
                DeploymentObligationFindingSeverity::ObligationDue,
                "reporting_evidence.notice.submitted_at_ms",
                "initial notice was submitted after its deadline",
            );
        }
    }
    if let (Some(submission), Some(due_at_ms)) = (report, report_due_at_ms) {
        if submission.submitted_at_ms > due_at_ms {
            push_finding(
                findings,
                DeploymentObligationFindingCode::ReportSubmittedLate,
                DeploymentObligationFindingSeverity::ObligationDue,
                "reporting_evidence.report.submitted_at_ms",
                "full report was submitted after its deadline",
            );
        }
    }

    let state = if incident.disputed {
        push_finding(
            findings,
            DeploymentObligationFindingCode::EvidenceDisputed,
            DeploymentObligationFindingSeverity::EvidenceGap,
            "incident.disputed",
            "incident reporting state is disputed",
        );
        IncidentReportingState::Disputed
    } else if report.is_some() {
        if notice.is_none() && notice_due_at_ms.is_some_and(|due_at_ms| input.now_ms > due_at_ms) {
            push_finding(
                findings,
                DeploymentObligationFindingCode::NoticeOverdue,
                DeploymentObligationFindingSeverity::ObligationDue,
                "reporting_evidence.notice",
                "required initial notice is missing after its deadline",
            );
        }
        IncidentReportingState::ReportSubmitted
    } else if report_due_at_ms.is_some_and(|due_at_ms| input.now_ms > due_at_ms) {
        push_finding(
            findings,
            DeploymentObligationFindingCode::ReportOverdue,
            DeploymentObligationFindingSeverity::ObligationDue,
            "reporting_evidence.report",
            "full report is overdue",
        );
        IncidentReportingState::Overdue
    } else if notice.is_none() && notice_due_at_ms.is_some_and(|due_at_ms| input.now_ms > due_at_ms)
    {
        push_finding(
            findings,
            DeploymentObligationFindingCode::NoticeOverdue,
            DeploymentObligationFindingSeverity::ObligationDue,
            "reporting_evidence.notice",
            "initial notice is overdue",
        );
        IncidentReportingState::Overdue
    } else if report_due_at_ms.is_some_and(|due_at_ms| input.now_ms == due_at_ms) {
        IncidentReportingState::ReportDue
    } else if notice.is_none()
        && notice_due_at_ms.is_some_and(|due_at_ms| input.now_ms == due_at_ms)
    {
        IncidentReportingState::NoticeDue
    } else if notice.is_some() {
        IncidentReportingState::NoticeSubmitted
    } else {
        IncidentReportingState::ClockRunning
    };

    incident_projection_for_rule(
        pack,
        incident,
        rule,
        Some(clock_started_at_ms),
        notice_due_at_ms,
        report_due_at_ms,
        notice,
        report,
        state,
    )
}

fn project_erasure_state(
    input: &DeploymentPolicyObligationsInput,
    findings: &mut Vec<DeploymentObligationFinding>,
) -> ErasureEvidenceState {
    let pack = &input.jurisdiction_policy_pack;
    let erasure = &input.assurance_evidence_bundle.erasure_evidence;
    let request_present = nonempty_option(&erasure.erasure_request_ref);

    if erasure.erasure_request_ref.is_some() && !request_present {
        push_finding(
            findings,
            DeploymentObligationFindingCode::RequiredBindingMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "erasure_evidence.erasure_request_ref",
            "erasure request ref must be nonempty",
        );
        return ErasureEvidenceState::Unknown;
    }
    if !request_present {
        if erasure.has_any_evidence() {
            push_finding(
                findings,
                DeploymentObligationFindingCode::ErasureEvidenceContradiction,
                DeploymentObligationFindingSeverity::InvalidInput,
                "erasure_evidence",
                "erasure evidence cannot exist without an erasure request binding",
            );
            return ErasureEvidenceState::Unknown;
        }
        return ErasureEvidenceState::NotRequested;
    }

    if erasure.disputed {
        push_finding(
            findings,
            DeploymentObligationFindingCode::EvidenceDisputed,
            DeploymentObligationFindingSeverity::EvidenceGap,
            "erasure_evidence.disputed",
            "erasure evidence is disputed",
        );
        return ErasureEvidenceState::Disputed;
    }
    if contains_empty(&erasure.crypto_shredding_receipt_refs)
        || contains_empty(&erasure.deletion_receipt_refs)
        || contains_empty(&erasure.verification_receipt_refs)
        || contains_empty(&erasure.exception_refs)
    {
        push_finding(
            findings,
            DeploymentObligationFindingCode::RequiredBindingMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "erasure_evidence.receipt_refs",
            "erasure evidence and exception refs must be nonempty",
        );
        return ErasureEvidenceState::Unknown;
    }

    if !erasure.exception_refs.is_empty() {
        if !nonempty_option(&pack.erasure_exception_policy_ref) {
            push_finding(
                findings,
                DeploymentObligationFindingCode::ExceptionPolicyMissing,
                DeploymentObligationFindingSeverity::InvalidInput,
                "jurisdiction_policy_pack.erasure_exception_policy_ref",
                "erasure exception evidence requires the pack's exception policy",
            );
            return ErasureEvidenceState::Unknown;
        }
        return ErasureEvidenceState::Excepted;
    }

    let has_crypto = !erasure.crypto_shredding_receipt_refs.is_empty();
    let has_deletion = !erasure.deletion_receipt_refs.is_empty();
    let has_verification = !erasure.verification_receipt_refs.is_empty();

    if has_crypto && !pack.crypto_shredding_eligible {
        push_finding(
            findings,
            DeploymentObligationFindingCode::CryptoShreddingNotEligible,
            DeploymentObligationFindingSeverity::InvalidInput,
            "erasure_evidence.crypto_shredding_receipt_refs",
            "policy pack does not permit crypto-shredding as erasure evidence",
        );
        return ErasureEvidenceState::Unknown;
    }
    if has_crypto && !nonempty_option(&pack.crypto_shredding_policy_ref) {
        push_finding(
            findings,
            DeploymentObligationFindingCode::CryptoShreddingPolicyMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "jurisdiction_policy_pack.crypto_shredding_policy_ref",
            "crypto-shredding evidence requires a bound policy",
        );
        return ErasureEvidenceState::Unknown;
    }
    if has_verification && !nonempty_option(&pack.erasure_verification_profile_ref) {
        push_finding(
            findings,
            DeploymentObligationFindingCode::ErasureVerificationProfileMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            "jurisdiction_policy_pack.erasure_verification_profile_ref",
            "erasure verification receipts require a verification profile",
        );
        return ErasureEvidenceState::Unknown;
    }
    if has_verification && !(has_crypto || has_deletion) {
        push_finding(
            findings,
            DeploymentObligationFindingCode::ErasureEvidenceContradiction,
            DeploymentObligationFindingSeverity::InvalidInput,
            "erasure_evidence.verification_receipt_refs",
            "verification cannot prove erasure without bound destructive evidence",
        );
        return ErasureEvidenceState::Unknown;
    }

    if !erasure.has_any_evidence() {
        push_finding(
            findings,
            DeploymentObligationFindingCode::ErasureScopeIncomplete,
            DeploymentObligationFindingSeverity::EvidenceGap,
            "erasure_evidence",
            "erasure request is pending evidence",
        );
        return ErasureEvidenceState::Pending;
    }

    if (has_crypto || has_deletion) && !has_verification {
        push_finding(
            findings,
            DeploymentObligationFindingCode::ErasureVerificationEvidenceMissing,
            DeploymentObligationFindingSeverity::EvidenceGap,
            "erasure_evidence.verification_receipt_refs",
            "destructive evidence is not yet a verified-erased projection",
        );
    }

    let retention_blocked = erasure.retention_lock_active || erasure.legal_hold_active;
    if retention_blocked {
        push_finding(
            findings,
            DeploymentObligationFindingCode::ErasureBlockedByRetention,
            DeploymentObligationFindingSeverity::EvidenceGap,
            "erasure_evidence.retention",
            "retention lock or legal hold prevents a verified-erased projection",
        );
    }
    if !erasure.scope_complete() {
        push_finding(
            findings,
            DeploymentObligationFindingCode::ErasureScopeIncomplete,
            DeploymentObligationFindingSeverity::EvidenceGap,
            "erasure_evidence.scope",
            "replica, derivative, and backup scope must all be complete",
        );
    }

    if has_verification && erasure.scope_complete() && !retention_blocked {
        ErasureEvidenceState::VerifiedErased
    } else if has_crypto && !has_deletion && !has_verification {
        ErasureEvidenceState::CryptoShredded
    } else {
        ErasureEvidenceState::PartiallyErased
    }
}

fn empty_incident_projection(
    incident_rules_version: &str,
    state: IncidentReportingState,
) -> IncidentReportingProjection {
    IncidentReportingProjection {
        incident_ref: None,
        selected_rule_id: None,
        selected_deadline_version: None,
        incident_rules_version: incident_rules_version.to_string(),
        clock_start_basis: None,
        clock_started_at_ms: None,
        clock_evidence_ref: None,
        notice_due_at_ms: None,
        report_due_at_ms: None,
        notice_submitted_at_ms: None,
        notice_receipt_ref: None,
        report_submitted_at_ms: None,
        report_receipt_ref: None,
        recipient_ref: None,
        responsible_ref: None,
        accountable_ref: None,
        state,
    }
}

fn incident_projection_for_rule(
    pack: &JurisdictionPolicyPackEvaluationInput,
    incident: &IncidentClockFacts,
    rule: &IncidentDeadlineRule,
    clock_started_at_ms: Option<u64>,
    notice_due_at_ms: Option<u64>,
    report_due_at_ms: Option<u64>,
    notice: Option<&ReportingSubmissionEvidence>,
    report: Option<&ReportingSubmissionEvidence>,
    state: IncidentReportingState,
) -> IncidentReportingProjection {
    IncidentReportingProjection {
        incident_ref: Some(incident.incident_ref.clone()),
        selected_rule_id: Some(rule.rule_id.clone()),
        selected_deadline_version: Some(rule.deadline_version.clone()),
        incident_rules_version: pack.incident_rules_version.clone(),
        clock_start_basis: Some(rule.clock_start_basis),
        clock_started_at_ms,
        clock_evidence_ref: Some(incident.clock_evidence_ref.clone()),
        notice_due_at_ms,
        report_due_at_ms,
        notice_submitted_at_ms: notice.map(|submission| submission.submitted_at_ms),
        notice_receipt_ref: notice.map(|submission| submission.receipt_ref.clone()),
        report_submitted_at_ms: report.map(|submission| submission.submitted_at_ms),
        report_receipt_ref: report.map(|submission| submission.receipt_ref.clone()),
        recipient_ref: Some(rule.recipient_ref.clone()),
        responsible_ref: Some(rule.responsible_ref.clone()),
        accountable_ref: Some(rule.accountable_ref.clone()),
        state,
    }
}

fn deadline_at(
    clock_started_at_ms: u64,
    within_ms: Option<u64>,
    field: &str,
    findings: &mut Vec<DeploymentObligationFinding>,
) -> Option<u64> {
    within_ms.and_then(
        |within_ms| match clock_started_at_ms.checked_add(within_ms) {
            Some(deadline) => Some(deadline),
            None => {
                push_finding(
                    findings,
                    DeploymentObligationFindingCode::DeadlineOverflow,
                    DeploymentObligationFindingSeverity::InvalidInput,
                    field,
                    "incident deadline overflows the timestamp domain",
                );
                None
            }
        },
    )
}

fn validate_submission<'a>(
    kind: &str,
    submission: Option<&'a ReportingSubmissionEvidence>,
    clock_started_at_ms: u64,
    now_ms: u64,
    findings: &mut Vec<DeploymentObligationFinding>,
) -> Option<&'a ReportingSubmissionEvidence> {
    let submission = submission?;
    if submission.receipt_ref.trim().is_empty() {
        push_finding(
            findings,
            DeploymentObligationFindingCode::SubmissionEvidenceIncomplete,
            DeploymentObligationFindingSeverity::InvalidInput,
            &format!("reporting_evidence.{kind}.receipt_ref"),
            "reporting submission timestamp requires a receipt ref",
        );
        return None;
    }
    if submission.submitted_at_ms < clock_started_at_ms {
        push_finding(
            findings,
            DeploymentObligationFindingCode::SubmissionBeforeClock,
            DeploymentObligationFindingSeverity::InvalidInput,
            &format!("reporting_evidence.{kind}.submitted_at_ms"),
            "reporting submission cannot predate its incident clock",
        );
        return None;
    }
    if submission.submitted_at_ms > now_ms {
        push_finding(
            findings,
            DeploymentObligationFindingCode::SubmissionInFuture,
            DeploymentObligationFindingSeverity::InvalidInput,
            &format!("reporting_evidence.{kind}.submitted_at_ms"),
            "reporting submission cannot be in the future",
        );
        return None;
    }
    Some(submission)
}

fn disposition_for(findings: &[DeploymentObligationFinding]) -> DeploymentObligationDisposition {
    if findings
        .iter()
        .any(|finding| finding.severity == DeploymentObligationFindingSeverity::InvalidInput)
    {
        DeploymentObligationDisposition::Invalid
    } else if findings
        .iter()
        .any(|finding| finding.severity == DeploymentObligationFindingSeverity::ObligationDue)
    {
        DeploymentObligationDisposition::ActionRequired
    } else if findings
        .iter()
        .any(|finding| finding.severity == DeploymentObligationFindingSeverity::EvidenceGap)
    {
        DeploymentObligationDisposition::EvidenceIncomplete
    } else {
        DeploymentObligationDisposition::Current
    }
}

fn require_binding(field: &str, value: &str, findings: &mut Vec<DeploymentObligationFinding>) {
    if value.trim().is_empty() {
        push_finding(
            findings,
            DeploymentObligationFindingCode::RequiredBindingMissing,
            DeploymentObligationFindingSeverity::InvalidInput,
            field,
            "required binding is empty",
        );
    }
}

fn validate_version(field: &str, value: &str, findings: &mut Vec<DeploymentObligationFinding>) {
    if !is_semver(value) {
        push_finding(
            findings,
            DeploymentObligationFindingCode::InvalidSemanticVersion,
            DeploymentObligationFindingSeverity::InvalidInput,
            field,
            "version must be a nonempty semantic version",
        );
    }
}

fn is_semver(value: &str) -> bool {
    if value.is_empty() || value.trim() != value {
        return false;
    }
    let build_parts = value.split('+').collect::<Vec<_>>();
    if build_parts.len() > 2
        || build_parts
            .get(1)
            .is_some_and(|build| !valid_semver_identifiers(build, false))
    {
        return false;
    }
    let without_build = build_parts[0];
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if prerelease.is_some_and(|value| !valid_semver_identifiers(value, true)) {
        return false;
    }
    let segments = core.split('.').collect::<Vec<_>>();
    segments.len() == 3
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.chars().all(|value| value.is_ascii_digit())
                && (segment == &"0" || !segment.starts_with('0'))
        })
}

fn valid_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .chars()
                    .all(|value| value.is_ascii_alphanumeric() || value == '-')
                && (!reject_numeric_leading_zero
                    || !identifier.chars().all(|value| value.is_ascii_digit())
                    || identifier == "0"
                    || !identifier.starts_with('0'))
        })
}

fn nonempty_option(value: &Option<String>) -> bool {
    value.as_ref().is_some_and(|value| !value.trim().is_empty())
}

fn contains_empty(values: &[String]) -> bool {
    values.iter().any(|value| value.trim().is_empty())
}

fn push_finding(
    findings: &mut Vec<DeploymentObligationFinding>,
    code: DeploymentObligationFindingCode,
    severity: DeploymentObligationFindingSeverity,
    field: impl Into<String>,
    reason: impl Into<String>,
) {
    findings.push(DeploymentObligationFinding {
        code,
        severity,
        field: field.into(),
        reason: reason.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> DeploymentPolicyObligationsInput {
        DeploymentPolicyObligationsInput {
            now_ms: 1_000_000,
            jurisdiction_policy_pack: JurisdictionPolicyPackEvaluationInput {
                pack_ref: "jurisdiction_policy_pack://us-ny/1".to_string(),
                pack_version: "1.2.0".to_string(),
                incident_rules_version: "2.1.0".to_string(),
                issuer_ref: "org://assurance-issuer".to_string(),
                responsible_issuer_ref: "role://compliance-owner".to_string(),
                accountable_issuer_ref: "role://executive-owner".to_string(),
                incident_deadline_rules: vec![IncidentDeadlineRule {
                    rule_id: "incident-rule://material/v1".to_string(),
                    deadline_version: "1.0.0".to_string(),
                    incident_class: "material_security_incident".to_string(),
                    clock_start_basis: IncidentClockBasis::DetectedAt,
                    initial_notice_within_ms: Some(2_000),
                    full_report_within_ms: Some(8_000),
                    recipient_ref: "authority://regulator".to_string(),
                    evidence_projection_profile_ref: "assurance_profile://incident/v1".to_string(),
                    responsible_ref: "role://incident-responder".to_string(),
                    accountable_ref: "role://incident-owner".to_string(),
                }],
                crypto_shredding_eligible: true,
                crypto_shredding_policy_ref: Some("policy://crypto-shredding/v1".to_string()),
                erasure_verification_profile_ref: Some(
                    "assurance_profile://erasure/v1".to_string(),
                ),
                erasure_exception_policy_ref: Some("policy://erasure-exception/v1".to_string()),
            },
            assurance_evidence_bundle: AssuranceEvidenceBundleEvaluationInput {
                bundle_ref: "assurance_evidence://deployment/1".to_string(),
                validity: EvidenceBundleValidity::Valid,
                evidence_watermark: "sha256:evidence-watermark".to_string(),
                evaluated_at_ms: 999_000,
                maximum_projection_age_ms: 5_000,
                evidence_refs: vec!["receipt://deployment/1".to_string()],
                incident: Some(IncidentClockFacts {
                    incident_ref: "incident://1".to_string(),
                    incident_class: "material_security_incident".to_string(),
                    detected_at_ms: Some(990_000),
                    confirmed_at_ms: None,
                    materiality_determined_at_ms: None,
                    authority_request_received_at_ms: None,
                    clock_evidence_ref: "receipt://incident-clock/1".to_string(),
                    disputed: false,
                }),
                reporting_evidence: IncidentReportingEvidence {
                    notice: Some(ReportingSubmissionEvidence {
                        submitted_at_ms: 991_000,
                        receipt_ref: "receipt://incident-notice/1".to_string(),
                    }),
                    report: Some(ReportingSubmissionEvidence {
                        submitted_at_ms: 997_000,
                        receipt_ref: "receipt://incident-report/1".to_string(),
                    }),
                },
                erasure_evidence: ErasureEvidenceInput::default(),
            },
        }
    }

    fn evaluate(input: DeploymentPolicyObligationsInput) -> DeploymentPolicyObligationsProjection {
        DeploymentPolicyObligationsEvaluator::evaluate(&input)
    }

    #[test]
    fn current_projection_binds_versions_owners_and_never_claims_legal_conformity() {
        let projection = evaluate(valid_input());

        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Current
        );
        assert_eq!(
            projection.incident_reporting.state,
            IncidentReportingState::ReportSubmitted
        );
        assert_eq!(
            projection.evidence_projection_state,
            EvidenceProjectionState::Complete
        );
        assert_eq!(
            projection.incident_reporting.clock_start_basis,
            Some(IncidentClockBasis::DetectedAt)
        );
        assert_eq!(
            projection.incident_reporting.clock_evidence_ref.as_deref(),
            Some("receipt://incident-clock/1")
        );
        assert_eq!(
            projection.incident_reporting.report_receipt_ref.as_deref(),
            Some("receipt://incident-report/1")
        );
        assert_eq!(projection.evidence_watermark, "sha256:evidence-watermark");
        assert_eq!(
            projection.legal_conformity_claim,
            LegalConformityClaim::NotDetermined
        );
        assert_eq!(
            serde_json::to_value(&projection)
                .unwrap()
                .get("legal_conformity_claim")
                .and_then(|value| value.as_str()),
            Some("not_determined")
        );
    }

    #[test]
    fn missing_responsible_or_accountable_issuer_is_invalid() {
        let mut input = valid_input();
        input
            .jurisdiction_policy_pack
            .responsible_issuer_ref
            .clear();
        input
            .jurisdiction_policy_pack
            .accountable_issuer_ref
            .clear();
        let projection = evaluate(input);

        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Invalid
        );
        assert!(
            projection
                .findings
                .iter()
                .filter(|finding| {
                    finding.code == DeploymentObligationFindingCode::RequiredBindingMissing
                })
                .count()
                >= 2
        );
    }

    #[test]
    fn invalid_or_duplicate_deadline_versions_are_refused() {
        let mut input = valid_input();
        input.jurisdiction_policy_pack.pack_version = "latest".to_string();
        let duplicate = input.jurisdiction_policy_pack.incident_deadline_rules[0].clone();
        input
            .jurisdiction_policy_pack
            .incident_deadline_rules
            .push(duplicate);
        let projection = evaluate(input);

        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Invalid
        );
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::InvalidSemanticVersion
        }));
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::DuplicateIncidentRule
        }));
    }

    #[test]
    fn missing_selected_clock_fact_is_invalid_and_unknown() {
        let mut input = valid_input();
        input.jurisdiction_policy_pack.incident_deadline_rules[0].clock_start_basis =
            IncidentClockBasis::ConfirmedAt;
        let projection = evaluate(input);

        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Invalid
        );
        assert_eq!(
            projection.incident_reporting.state,
            IncidentReportingState::Unknown
        );
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::IncidentClockEvidenceMissing
        }));
    }

    #[test]
    fn overdue_notice_is_action_required() {
        let mut input = valid_input();
        input.assurance_evidence_bundle.reporting_evidence = IncidentReportingEvidence::default();
        input.now_ms = 993_000;
        input.assurance_evidence_bundle.evaluated_at_ms = 992_500;
        let projection = evaluate(input);

        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::ActionRequired
        );
        assert_eq!(
            projection.incident_reporting.state,
            IncidentReportingState::Overdue
        );
        assert!(projection
            .findings
            .iter()
            .any(|finding| { finding.code == DeploymentObligationFindingCode::NoticeOverdue }));
    }

    #[test]
    fn submission_timestamp_without_receipt_is_invalid() {
        let mut input = valid_input();
        input
            .assurance_evidence_bundle
            .reporting_evidence
            .report
            .as_mut()
            .unwrap()
            .receipt_ref
            .clear();
        let projection = evaluate(input);

        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Invalid
        );
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::SubmissionEvidenceIncomplete
        }));
    }

    #[test]
    fn late_full_report_remains_submitted_but_action_required() {
        let mut input = valid_input();
        input
            .assurance_evidence_bundle
            .reporting_evidence
            .report
            .as_mut()
            .unwrap()
            .submitted_at_ms = 999_000;
        let projection = evaluate(input);

        assert_eq!(
            projection.incident_reporting.state,
            IncidentReportingState::ReportSubmitted
        );
        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::ActionRequired
        );
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::ReportSubmittedLate
        }));
    }

    #[test]
    fn stale_bundle_projects_stale_without_a_legal_claim() {
        let mut input = valid_input();
        input.assurance_evidence_bundle.evaluated_at_ms = 900_000;
        let projection = evaluate(input);

        assert_eq!(
            projection.evidence_projection_state,
            EvidenceProjectionState::Stale
        );
        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::EvidenceIncomplete
        );
        assert_eq!(
            projection.legal_conformity_claim,
            LegalConformityClaim::NotDetermined
        );
    }

    #[test]
    fn future_evidence_projection_timestamp_is_invalid() {
        let mut input = valid_input();
        input.assurance_evidence_bundle.evaluated_at_ms = input.now_ms + 1;
        let projection = evaluate(input);

        assert_eq!(
            projection.evidence_projection_state,
            EvidenceProjectionState::Stale
        );
        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Invalid
        );
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::EvidenceProjectionInFuture
        }));
    }

    #[test]
    fn crypto_shredding_alone_never_projects_verified_erasure() {
        let mut input = valid_input();
        input.assurance_evidence_bundle.erasure_evidence = ErasureEvidenceInput {
            erasure_request_ref: Some("request://erase/1".to_string()),
            crypto_shredding_receipt_refs: vec!["receipt://crypto-shred/1".to_string()],
            replica_scope_complete: true,
            derivative_scope_complete: true,
            backup_scope_complete: true,
            ..ErasureEvidenceInput::default()
        };
        let projection = evaluate(input);

        assert_eq!(
            projection.erasure_evidence_state,
            ErasureEvidenceState::CryptoShredded
        );
        assert_ne!(
            projection.erasure_evidence_state,
            ErasureEvidenceState::VerifiedErased
        );
        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::EvidenceIncomplete
        );
    }

    #[test]
    fn crypto_shredding_requires_pack_eligibility_and_policy() {
        let mut input = valid_input();
        input.jurisdiction_policy_pack.crypto_shredding_eligible = false;
        input.assurance_evidence_bundle.erasure_evidence = ErasureEvidenceInput {
            erasure_request_ref: Some("request://erase/1".to_string()),
            crypto_shredding_receipt_refs: vec!["receipt://crypto-shred/1".to_string()],
            ..ErasureEvidenceInput::default()
        };
        let ineligible = evaluate(input.clone());

        assert_eq!(
            ineligible.erasure_evidence_state,
            ErasureEvidenceState::Unknown
        );
        assert!(ineligible.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::CryptoShreddingNotEligible
        }));

        input.jurisdiction_policy_pack.crypto_shredding_eligible = true;
        input.jurisdiction_policy_pack.crypto_shredding_policy_ref = None;
        let unbound = evaluate(input);
        assert!(unbound.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::CryptoShreddingPolicyMissing
        }));
    }

    #[test]
    fn complete_scoped_erasure_with_verification_projects_verified_erased() {
        let mut input = valid_input();
        input.assurance_evidence_bundle.erasure_evidence = ErasureEvidenceInput {
            erasure_request_ref: Some("request://erase/1".to_string()),
            crypto_shredding_receipt_refs: vec!["receipt://crypto-shred/1".to_string()],
            deletion_receipt_refs: vec!["receipt://delete/1".to_string()],
            verification_receipt_refs: vec!["receipt://erasure-verify/1".to_string()],
            replica_scope_complete: true,
            derivative_scope_complete: true,
            backup_scope_complete: true,
            ..ErasureEvidenceInput::default()
        };
        let projection = evaluate(input);

        assert_eq!(
            projection.erasure_evidence_state,
            ErasureEvidenceState::VerifiedErased
        );
        assert_eq!(
            projection.legal_conformity_claim,
            LegalConformityClaim::NotDetermined
        );
    }

    #[test]
    fn retention_hold_and_incomplete_scope_prevent_verified_erasure() {
        let mut input = valid_input();
        input.assurance_evidence_bundle.erasure_evidence = ErasureEvidenceInput {
            erasure_request_ref: Some("request://erase/1".to_string()),
            deletion_receipt_refs: vec!["receipt://delete/1".to_string()],
            verification_receipt_refs: vec!["receipt://erasure-verify/1".to_string()],
            replica_scope_complete: true,
            derivative_scope_complete: false,
            backup_scope_complete: true,
            legal_hold_active: true,
            ..ErasureEvidenceInput::default()
        };
        let projection = evaluate(input);

        assert_eq!(
            projection.erasure_evidence_state,
            ErasureEvidenceState::PartiallyErased
        );
        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::EvidenceIncomplete
        );
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::ErasureBlockedByRetention
        }));
        assert!(projection.findings.iter().any(|finding| {
            finding.code == DeploymentObligationFindingCode::ErasureScopeIncomplete
        }));
    }

    #[test]
    fn exception_requires_pack_policy_and_never_projects_erased() {
        let mut input = valid_input();
        input.jurisdiction_policy_pack.erasure_exception_policy_ref = None;
        input.assurance_evidence_bundle.erasure_evidence = ErasureEvidenceInput {
            erasure_request_ref: Some("request://erase/1".to_string()),
            exception_refs: vec!["decision://erasure-exception/1".to_string()],
            ..ErasureEvidenceInput::default()
        };
        let invalid = evaluate(input.clone());

        assert_eq!(
            invalid.erasure_evidence_state,
            ErasureEvidenceState::Unknown
        );
        assert_eq!(
            invalid.disposition,
            DeploymentObligationDisposition::Invalid
        );

        input.jurisdiction_policy_pack.erasure_exception_policy_ref =
            Some("policy://exception/v1".to_string());
        let excepted = evaluate(input);
        assert_eq!(
            excepted.erasure_evidence_state,
            ErasureEvidenceState::Excepted
        );
        assert_ne!(
            excepted.erasure_evidence_state,
            ErasureEvidenceState::VerifiedErased
        );
    }

    #[test]
    fn empty_erasure_request_ref_is_invalid_not_not_requested() {
        let mut input = valid_input();
        input
            .assurance_evidence_bundle
            .erasure_evidence
            .erasure_request_ref = Some(" ".to_string());
        let projection = evaluate(input);

        assert_eq!(
            projection.erasure_evidence_state,
            ErasureEvidenceState::Unknown
        );
        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Invalid
        );
    }

    #[test]
    fn timestamp_overflow_is_invalid() {
        let mut input = valid_input();
        let incident = input.assurance_evidence_bundle.incident.as_mut().unwrap();
        incident.detected_at_ms = Some(u64::MAX - 5);
        input.now_ms = u64::MAX;
        input.assurance_evidence_bundle.evaluated_at_ms = u64::MAX - 1;
        let projection = evaluate(input);

        assert_eq!(
            projection.disposition,
            DeploymentObligationDisposition::Invalid
        );
        assert!(projection
            .findings
            .iter()
            .any(|finding| { finding.code == DeploymentObligationFindingCode::DeadlineOverflow }));
    }
}
