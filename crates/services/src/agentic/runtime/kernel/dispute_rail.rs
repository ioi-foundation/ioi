//! Deterministic challenge and dispute-rail admission.
//!
//! The kernel consumes a versioned rail profile and an owner-produced case
//! snapshot. It does not hold escrow, adjudicate evidence, or move value. It
//! validates windows/defaults and emits the exact remedy and conserved integer
//! bond allocation that the owning settlement rail must execute and receipt.

use std::collections::{BTreeMap, BTreeSet};

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BASIS_POINTS: u64 = 10_000;
const MAX_SAFE_FIXED_POINT_UNITS: u64 = 9_007_199_254_740_991;
pub const DISPUTE_RAIL_BUNDLE_CONTRACT_ID: &str = "schema://ioi/foundations/dispute-rail-bundle/v1";
pub const DISPUTE_RAIL_BUNDLE_SCHEMA_VERSION: &str = "ioi.foundations.dispute-rail-bundle.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeRailDenial {
    pub code: &'static str,
    pub message: String,
}

impl DisputeRailDenial {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeRailKind {
    InternalReview,
    MarketplaceEscrow,
    AiipDispute,
    PublicSettlement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeOutcome {
    ChallengerUpheld,
    RespondentUpheld,
    Partial,
    NoFault,
    Escalated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeRemedy {
    None,
    Refund,
    PartialRefund,
    Payout,
    PartialPayout,
    Slash,
    Retry,
    Revise,
    Escalate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeResolutionState {
    Proposed,
    Admitted,
    Appealed,
    Superseded,
    ExecutionPending,
    Executed,
    ExecutionFailed,
}

impl DisputeRemedy {
    fn carries_value(self) -> bool {
        matches!(
            self,
            Self::Refund | Self::PartialRefund | Self::Payout | Self::PartialPayout | Self::Slash
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondRoundingRecipient {
    ChallengerReturn,
    RespondentReturn,
    ChallengerAward,
    RespondentAward,
    VerifierFunding,
    Treasury,
    Burn,
}

/// Exact denomination binding for every disputed-value, remedy, bond, and
/// allocation amount in one v1 dispute. V1 deliberately has no conversion:
/// a different asset or atomic unit requires a different admitted case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeValueUnitBinding {
    pub asset_ref: String,
    pub unit_ref: String,
    pub unit_version: u32,
    pub unit_body_hash: String,
    pub atomic_unit_code: String,
    pub decimals: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondDistributionBps {
    pub challenger_return_bps: u64,
    pub respondent_return_bps: u64,
    pub challenger_award_bps: u64,
    pub respondent_award_bps: u64,
    pub verifier_funding_bps: u64,
    pub treasury_bps: u64,
    pub burn_bps: u64,
    pub rounding_recipient: BondRoundingRecipient,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeOutcomeRule {
    pub remedy: DisputeRemedy,
    pub maximum_remedy_bps_of_disputed_value: u64,
    pub bond_distribution: BondDistributionBps,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeRailProfile {
    pub profile_ref: String,
    pub profile_version: u32,
    pub rail_kind: DisputeRailKind,
    pub value_unit: DisputeValueUnitBinding,
    pub ordinary_verification_funding_ref: Option<String>,
    pub challenger_bond_units: u64,
    pub respondent_bond_units: u64,
    pub evidence_window_ms: u64,
    pub response_window_ms: u64,
    pub appeal_window_ms: u64,
    pub evidence_unavailable_default: DisputeOutcome,
    pub respondent_timeout_default: DisputeOutcome,
    pub allowed_remedies: BTreeSet<DisputeRemedy>,
    pub outcome_rules: BTreeMap<DisputeOutcome, DisputeOutcomeRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeCaseSnapshot {
    pub dispute_ref: String,
    pub dispute_rail_profile_ref: String,
    pub dispute_rail_profile_version: u32,
    pub dispute_rail_profile_body_hash: String,
    pub value_unit: DisputeValueUnitBinding,
    pub challenged_ref: String,
    pub challenger_ref: String,
    pub respondent_ref: String,
    pub opened_at_ms: u64,
    pub evidence_retained_until_ms: u64,
    pub disputed_value_units: u64,
    pub challenger_bond_hold_ref: Option<String>,
    pub challenger_bond_held_units: u64,
    pub respondent_bond_hold_ref: Option<String>,
    pub respondent_bond_held_units: u64,
    pub escrow_ref: Option<String>,
    pub collaboration_terms_ref: Option<String>,
    pub collaboration_terms_root: Option<String>,
    pub settlement_profile_ref: Option<String>,
    pub network_enrollment_ref: Option<String>,
    pub case_head_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeResolutionRequest {
    pub dispute_resolution_ref: String,
    pub dispute_ref: String,
    pub dispute_rail_profile_ref: String,
    pub dispute_rail_profile_version: u32,
    pub dispute_rail_profile_body_hash: String,
    pub value_unit: DisputeValueUnitBinding,
    pub expected_case_head_hash: String,
    pub idempotency_key: String,
    pub decided_at_ms: u64,
    pub requested_outcome: DisputeOutcome,
    pub requested_remedy: DisputeRemedy,
    pub requested_remedy_units: u64,
    pub evidence_available: bool,
    pub response_received: bool,
    pub evidence_refs: Vec<String>,
    pub response_refs: Vec<String>,
    pub adjudicator_ref: String,
    pub appeal_of_resolution_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BondAllocationUnits {
    pub challenger_return_units: u64,
    pub respondent_return_units: u64,
    pub challenger_award_units: u64,
    pub respondent_award_units: u64,
    pub verifier_funding_units: u64,
    pub treasury_units: u64,
    pub burn_units: u64,
}

impl BondAllocationUnits {
    fn total(&self) -> Option<u64> {
        [
            self.challenger_return_units,
            self.respondent_return_units,
            self.challenger_award_units,
            self.respondent_award_units,
            self.verifier_funding_units,
            self.treasury_units,
            self.burn_units,
        ]
        .into_iter()
        .try_fold(0u64, u64::checked_add)
    }

    fn add_rounding(
        &mut self,
        recipient: BondRoundingRecipient,
        units: u64,
    ) -> Result<(), DisputeRailDenial> {
        let target = match recipient {
            BondRoundingRecipient::ChallengerReturn => &mut self.challenger_return_units,
            BondRoundingRecipient::RespondentReturn => &mut self.respondent_return_units,
            BondRoundingRecipient::ChallengerAward => &mut self.challenger_award_units,
            BondRoundingRecipient::RespondentAward => &mut self.respondent_award_units,
            BondRoundingRecipient::VerifierFunding => &mut self.verifier_funding_units,
            BondRoundingRecipient::Treasury => &mut self.treasury_units,
            BondRoundingRecipient::Burn => &mut self.burn_units,
        };
        *target = target.checked_add(units).ok_or_else(|| {
            DisputeRailDenial::new(
                "dispute_bond_allocation_overflow",
                "rounding allocation overflowed",
            )
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeResolutionDecision {
    pub dispute_resolution_ref: String,
    pub dispute_ref: String,
    pub profile_ref: String,
    pub profile_version: u32,
    pub profile_body_hash: String,
    pub rail_kind: DisputeRailKind,
    pub value_unit: DisputeValueUnitBinding,
    pub case_head_hash: String,
    pub request_hash: String,
    pub idempotency_key: String,
    pub adjudicator_ref: String,
    pub decided_at_ms: u64,
    pub evidence_refs: Vec<String>,
    pub response_refs: Vec<String>,
    pub appeal_of_resolution_ref: Option<String>,
    pub outcome: DisputeOutcome,
    pub remedy: DisputeRemedy,
    pub remedy_units: u64,
    pub bond_pool_units: u64,
    pub bond_allocation: BondAllocationUnits,
    pub used_evidence_unavailable_default: bool,
    pub used_respondent_timeout_default: bool,
    pub appeal_deadline_ms: u64,
    pub required_receipt_kinds: Vec<String>,
    pub resolution_state: DisputeResolutionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorDisputeResolution {
    pub idempotency_key: String,
    pub request_hash: String,
    pub decision: DisputeResolutionDecision,
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn present(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(nonempty)
}

fn require_ref(name: &str, value: &str) -> Result<(), DisputeRailDenial> {
    let Some((scheme, tail)) = value.split_once("://") else {
        return Err(DisputeRailDenial::new(
            "dispute_ref_invalid",
            format!("{name} must be a typed ref"),
        ));
    };
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_lowercase)
        || tail.trim().is_empty()
        || tail.bytes().any(|byte| byte.is_ascii_whitespace())
        || !scheme.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
        })
    {
        return Err(DisputeRailDenial::new(
            "dispute_ref_invalid",
            format!("{name} must be a typed lowercase-scheme ref"),
        ));
    }
    Ok(())
}

fn require_optional_ref(name: &str, value: &Option<String>) -> Result<(), DisputeRailDenial> {
    if let Some(value) = value {
        require_ref(name, value)?;
    }
    Ok(())
}

fn require_hash(name: &str, value: &str) -> Result<(), DisputeRailDenial> {
    let Some(hash) = value.strip_prefix("sha256:") else {
        return Err(DisputeRailDenial::new(
            "dispute_hash_invalid",
            format!("{name} must be a sha256 hash"),
        ));
    };
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DisputeRailDenial::new(
            "dispute_hash_invalid",
            format!("{name} must contain 64 lowercase hex characters"),
        ));
    }
    Ok(())
}

fn require_safe(name: &str, value: u64) -> Result<(), DisputeRailDenial> {
    if value > MAX_SAFE_FIXED_POINT_UNITS {
        return Err(DisputeRailDenial::new(
            "dispute_fixed_point_overflow",
            format!("{name} exceeds the portable safe-integer ceiling"),
        ));
    }
    Ok(())
}

fn validate_value_unit(value_unit: &DisputeValueUnitBinding) -> Result<(), DisputeRailDenial> {
    require_ref("value_unit.asset_ref", &value_unit.asset_ref)?;
    require_ref("value_unit.unit_ref", &value_unit.unit_ref)?;
    require_hash("value_unit.unit_body_hash", &value_unit.unit_body_hash)?;
    if value_unit.unit_version == 0
        || value_unit.atomic_unit_code.trim().is_empty()
        || !value_unit
            .atomic_unit_code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(DisputeRailDenial::new(
            "dispute_value_unit_invalid",
            "value unit requires a positive version and portable atomic-unit code",
        ));
    }
    Ok(())
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, DisputeRailDenial> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        DisputeRailDenial::new("dispute_canonical_hash_failed", error.to_string())
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn profile_body_hash(profile: &DisputeRailProfile) -> Result<String, DisputeRailDenial> {
    canonical_hash(profile)
}

fn checked_deadlines(
    profile: &DisputeRailProfile,
    opened_at_ms: u64,
) -> Result<(u64, u64, u64), DisputeRailDenial> {
    let evidence_deadline = opened_at_ms
        .checked_add(profile.evidence_window_ms)
        .ok_or_else(|| {
            DisputeRailDenial::new("dispute_window_overflow", "evidence window overflowed")
        })?;
    let response_deadline = evidence_deadline
        .checked_add(profile.response_window_ms)
        .ok_or_else(|| {
            DisputeRailDenial::new("dispute_window_overflow", "response window overflowed")
        })?;
    let appeal_deadline = response_deadline
        .checked_add(profile.appeal_window_ms)
        .ok_or_else(|| {
            DisputeRailDenial::new("dispute_window_overflow", "appeal window overflowed")
        })?;
    require_safe("evidence_deadline_ms", evidence_deadline)?;
    require_safe("response_deadline_ms", response_deadline)?;
    require_safe("appeal_deadline_ms", appeal_deadline)?;
    Ok((evidence_deadline, response_deadline, appeal_deadline))
}

fn validate_distribution(distribution: &BondDistributionBps) -> Result<(), DisputeRailDenial> {
    let total = [
        distribution.challenger_return_bps,
        distribution.respondent_return_bps,
        distribution.challenger_award_bps,
        distribution.respondent_award_bps,
        distribution.verifier_funding_bps,
        distribution.treasury_bps,
        distribution.burn_bps,
    ]
    .into_iter()
    .try_fold(0u64, u64::checked_add)
    .ok_or_else(|| {
        DisputeRailDenial::new(
            "dispute_bond_distribution_invalid",
            "bond basis points overflowed",
        )
    })?;
    if total != BASIS_POINTS {
        return Err(DisputeRailDenial::new(
            "dispute_bond_distribution_invalid",
            format!("bond distribution totals {total}, expected {BASIS_POINTS}"),
        ));
    }
    Ok(())
}

fn validate_profile(profile: &DisputeRailProfile) -> Result<(), DisputeRailDenial> {
    require_ref("profile_ref", &profile.profile_ref)?;
    validate_value_unit(&profile.value_unit)?;
    require_optional_ref(
        "ordinary_verification_funding_ref",
        &profile.ordinary_verification_funding_ref,
    )?;
    if profile.profile_version == 0 {
        return Err(DisputeRailDenial::new(
            "dispute_profile_invalid",
            "a positive profile version is required",
        ));
    }
    for (name, value) in [
        ("challenger_bond_units", profile.challenger_bond_units),
        ("respondent_bond_units", profile.respondent_bond_units),
        ("evidence_window_ms", profile.evidence_window_ms),
        ("response_window_ms", profile.response_window_ms),
        ("appeal_window_ms", profile.appeal_window_ms),
    ] {
        require_safe(name, value)?;
    }
    if profile.evidence_window_ms == 0
        || profile.response_window_ms == 0
        || profile.appeal_window_ms == 0
    {
        return Err(DisputeRailDenial::new(
            "dispute_profile_window_invalid",
            "evidence, response, and appeal windows must be positive",
        ));
    }
    if profile.allowed_remedies.is_empty() || profile.outcome_rules.is_empty() {
        return Err(DisputeRailDenial::new(
            "dispute_profile_rules_missing",
            "profile requires allowed remedies and outcome rules",
        ));
    }
    for required_outcome in [
        profile.evidence_unavailable_default,
        profile.respondent_timeout_default,
    ] {
        if !profile.outcome_rules.contains_key(&required_outcome) {
            return Err(DisputeRailDenial::new(
                "dispute_default_rule_missing",
                "every timeout/unavailable default requires an outcome rule",
            ));
        }
    }
    for rule in profile.outcome_rules.values() {
        if rule.maximum_remedy_bps_of_disputed_value > BASIS_POINTS
            || !profile.allowed_remedies.contains(&rule.remedy)
            || (!rule.remedy.carries_value() && rule.maximum_remedy_bps_of_disputed_value != 0)
        {
            return Err(DisputeRailDenial::new(
                "dispute_outcome_rule_invalid",
                "outcome remedy must be allowed, capped at 10000 basis points, and non-value remedies must have a zero value cap",
            ));
        }
        validate_distribution(&rule.bond_distribution)?;
    }
    if profile.rail_kind == DisputeRailKind::InternalReview
        && (profile.challenger_bond_units != 0 || profile.respondent_bond_units != 0)
    {
        return Err(DisputeRailDenial::new(
            "dispute_internal_review_bond_forbidden",
            "internal review is non-bonded in this rail family",
        ));
    }
    Ok(())
}

pub fn validate_dispute_case(
    profile: &DisputeRailProfile,
    case: &DisputeCaseSnapshot,
) -> Result<(), DisputeRailDenial> {
    validate_profile(profile)?;
    let expected_profile_hash = profile_body_hash(profile)?;
    for (name, value) in [
        ("dispute_ref", case.dispute_ref.as_str()),
        ("challenged_ref", case.challenged_ref.as_str()),
        ("challenger_ref", case.challenger_ref.as_str()),
        ("respondent_ref", case.respondent_ref.as_str()),
        (
            "dispute_rail_profile_ref",
            case.dispute_rail_profile_ref.as_str(),
        ),
    ] {
        require_ref(name, value)?;
    }
    require_hash("case_head_hash", &case.case_head_hash)?;
    require_hash(
        "dispute_rail_profile_body_hash",
        &case.dispute_rail_profile_body_hash,
    )?;
    validate_value_unit(&case.value_unit)?;
    for (name, value) in [
        ("opened_at_ms", case.opened_at_ms),
        (
            "evidence_retained_until_ms",
            case.evidence_retained_until_ms,
        ),
        ("disputed_value_units", case.disputed_value_units),
        (
            "challenger_bond_held_units",
            case.challenger_bond_held_units,
        ),
        (
            "respondent_bond_held_units",
            case.respondent_bond_held_units,
        ),
    ] {
        require_safe(name, value)?;
    }
    for (name, value) in [
        ("challenger_bond_hold_ref", &case.challenger_bond_hold_ref),
        ("respondent_bond_hold_ref", &case.respondent_bond_hold_ref),
        ("escrow_ref", &case.escrow_ref),
        ("collaboration_terms_ref", &case.collaboration_terms_ref),
        ("settlement_profile_ref", &case.settlement_profile_ref),
        ("network_enrollment_ref", &case.network_enrollment_ref),
    ] {
        require_optional_ref(name, value)?;
    }
    if let Some(root) = &case.collaboration_terms_root {
        require_hash("collaboration_terms_root", root)?;
    }
    if case.challenger_ref == case.respondent_ref {
        return Err(DisputeRailDenial::new(
            "dispute_case_identity_invalid",
            "case identities and head are required and parties must differ",
        ));
    }
    if case.dispute_rail_profile_ref != profile.profile_ref
        || case.dispute_rail_profile_version != profile.profile_version
        || case.dispute_rail_profile_body_hash != expected_profile_hash
    {
        return Err(DisputeRailDenial::new(
            "dispute_profile_binding_mismatch",
            "case must bind the exact admitted profile ref, version, and canonical body hash",
        ));
    }
    if case.value_unit != profile.value_unit {
        return Err(DisputeRailDenial::new(
            "dispute_value_unit_mismatch",
            "case disputed value and bond pool must use the profile's exact asset-unit binding",
        ));
    }
    let (_, _, appeal_deadline) = checked_deadlines(profile, case.opened_at_ms)?;
    if case.evidence_retained_until_ms < appeal_deadline {
        return Err(DisputeRailDenial::new(
            "dispute_evidence_retention_too_short",
            "evidence retention must cover the complete appeal window",
        ));
    }
    let challenger_hold_valid = case.challenger_bond_held_units == profile.challenger_bond_units
        && if profile.challenger_bond_units == 0 {
            case.challenger_bond_hold_ref.is_none()
        } else {
            present(&case.challenger_bond_hold_ref)
        };
    let respondent_hold_valid = case.respondent_bond_held_units == profile.respondent_bond_units
        && if profile.respondent_bond_units == 0 {
            case.respondent_bond_hold_ref.is_none()
        } else {
            present(&case.respondent_bond_hold_ref)
        };
    if !challenger_hold_valid || !respondent_hold_valid {
        return Err(DisputeRailDenial::new(
            "dispute_bond_hold_mismatch",
            "case bond amounts and hold-ref presence must exactly match the admitted profile",
        ));
    }
    match profile.rail_kind {
        DisputeRailKind::InternalReview => {}
        DisputeRailKind::MarketplaceEscrow => {
            if !present(&case.escrow_ref) {
                return Err(DisputeRailDenial::new(
                    "dispute_marketplace_escrow_required",
                    "marketplace dispute requires its escrow ref",
                ));
            }
        }
        DisputeRailKind::AiipDispute => {
            if !present(&case.collaboration_terms_ref)
                || !present(&case.collaboration_terms_root)
                || !present(&profile.ordinary_verification_funding_ref)
            {
                return Err(DisputeRailDenial::new(
                    "dispute_aiip_terms_or_verification_funding_missing",
                    "AIIP dispute requires exact collaboration terms and ordinary verification funding",
                ));
            }
        }
        DisputeRailKind::PublicSettlement => {
            if !present(&case.settlement_profile_ref) || !present(&case.network_enrollment_ref) {
                return Err(DisputeRailDenial::new(
                    "dispute_public_settlement_binding_missing",
                    "public dispute requires exact settlement profile and network enrollment",
                ));
            }
        }
    }
    Ok(())
}

fn request_hash(request: &DisputeResolutionRequest) -> Result<String, DisputeRailDenial> {
    canonical_hash(request)
        .map_err(|error| DisputeRailDenial::new("dispute_request_hash_failed", error.message))
}

fn allocate_component(total: u64, bps: u64) -> Result<u64, DisputeRailDenial> {
    let units = (u128::from(total) * u128::from(bps)) / u128::from(BASIS_POINTS);
    u64::try_from(units).map_err(|_| {
        DisputeRailDenial::new(
            "dispute_bond_allocation_overflow",
            "bond allocation exceeds u64",
        )
    })
}

fn allocate_bond_pool(
    total: u64,
    distribution: &BondDistributionBps,
) -> Result<BondAllocationUnits, DisputeRailDenial> {
    validate_distribution(distribution)?;
    let mut allocation = BondAllocationUnits {
        challenger_return_units: allocate_component(total, distribution.challenger_return_bps)?,
        respondent_return_units: allocate_component(total, distribution.respondent_return_bps)?,
        challenger_award_units: allocate_component(total, distribution.challenger_award_bps)?,
        respondent_award_units: allocate_component(total, distribution.respondent_award_bps)?,
        verifier_funding_units: allocate_component(total, distribution.verifier_funding_bps)?,
        treasury_units: allocate_component(total, distribution.treasury_bps)?,
        burn_units: allocate_component(total, distribution.burn_bps)?,
    };
    let allocated = allocation.total().ok_or_else(|| {
        DisputeRailDenial::new(
            "dispute_bond_allocation_overflow",
            "bond allocation total overflowed",
        )
    })?;
    let remainder = total.checked_sub(allocated).ok_or_else(|| {
        DisputeRailDenial::new(
            "dispute_bond_allocation_invalid",
            "allocated bond exceeds held bond pool",
        )
    })?;
    allocation.add_rounding(distribution.rounding_recipient, remainder)?;
    if allocation.total() != Some(total) {
        return Err(DisputeRailDenial::new(
            "dispute_bond_conservation_failed",
            "bond allocation did not conserve the held pool",
        ));
    }
    Ok(allocation)
}

pub fn resolve_dispute(
    profile: &DisputeRailProfile,
    case: &DisputeCaseSnapshot,
    request: &DisputeResolutionRequest,
    prior: Option<&PriorDisputeResolution>,
) -> Result<DisputeResolutionDecision, DisputeRailDenial> {
    validate_dispute_case(profile, case)?;
    let expected_profile_hash = profile_body_hash(profile)?;
    require_ref(
        "request.dispute_resolution_ref",
        &request.dispute_resolution_ref,
    )?;
    require_ref("request.dispute_ref", &request.dispute_ref)?;
    require_ref(
        "request.dispute_rail_profile_ref",
        &request.dispute_rail_profile_ref,
    )?;
    require_hash(
        "request.dispute_rail_profile_body_hash",
        &request.dispute_rail_profile_body_hash,
    )?;
    require_hash(
        "request.expected_case_head_hash",
        &request.expected_case_head_hash,
    )?;
    require_ref("request.adjudicator_ref", &request.adjudicator_ref)?;
    require_optional_ref(
        "request.appeal_of_resolution_ref",
        &request.appeal_of_resolution_ref,
    )?;
    validate_value_unit(&request.value_unit)?;
    require_safe("request.decided_at_ms", request.decided_at_ms)?;
    require_safe(
        "request.requested_remedy_units",
        request.requested_remedy_units,
    )?;
    for (name, refs) in [
        ("request.evidence_refs", &request.evidence_refs),
        ("request.response_refs", &request.response_refs),
    ] {
        let mut unique = BTreeSet::new();
        for value in refs {
            require_ref(name, value)?;
            if !unique.insert(value) {
                return Err(DisputeRailDenial::new(
                    "dispute_duplicate_evidence_ref",
                    format!("{name} contains a duplicate ref"),
                ));
            }
        }
    }
    if !nonempty(&request.idempotency_key)
        || request.dispute_ref != case.dispute_ref
        || request.dispute_rail_profile_ref != profile.profile_ref
        || request.dispute_rail_profile_version != profile.profile_version
        || request.dispute_rail_profile_body_hash != expected_profile_hash
        || request.value_unit != profile.value_unit
        || request.expected_case_head_hash != case.case_head_hash
    {
        return Err(DisputeRailDenial::new(
            "dispute_resolution_binding_invalid",
            "resolution requires idempotency plus exact dispute, profile, value-unit, adjudicator, and case-head bindings",
        ));
    }
    let computed_request_hash = request_hash(request)?;
    if let Some(prior) = prior {
        if prior.idempotency_key == request.idempotency_key {
            if prior.request_hash == computed_request_hash {
                let expected_decision = resolve_dispute(profile, case, request, None)?;
                if prior.decision != expected_decision {
                    return Err(DisputeRailDenial::new(
                        "dispute_prior_resolution_binding_invalid",
                        "prior replay decision is not the exact deterministic decision for this request",
                    ));
                }
                return Ok(prior.decision.clone());
            }
            return Err(DisputeRailDenial::new(
                "dispute_idempotency_conflict",
                "the idempotency key was already used for different resolution bytes",
            ));
        }
    }

    let (evidence_deadline, response_deadline, _) = checked_deadlines(profile, case.opened_at_ms)?;
    if request.decided_at_ms < case.opened_at_ms {
        return Err(DisputeRailDenial::new(
            "dispute_resolution_before_open",
            "resolution time cannot precede case opening",
        ));
    }
    let mut outcome = request.requested_outcome;
    let mut evidence_default = false;
    let mut response_default = false;

    if !request.evidence_available {
        if request.decided_at_ms < evidence_deadline {
            return Err(DisputeRailDenial::new(
                "dispute_evidence_window_open",
                "unavailable-evidence default cannot run before evidence deadline",
            ));
        }
        outcome = profile.evidence_unavailable_default;
        evidence_default = true;
    } else {
        if request.evidence_refs.is_empty() {
            return Err(DisputeRailDenial::new(
                "dispute_evidence_refs_required",
                "available evidence must bind durable evidence refs",
            ));
        }
        if !request.response_received {
            if request.decided_at_ms < response_deadline {
                return Err(DisputeRailDenial::new(
                    "dispute_response_window_open",
                    "respondent-timeout default cannot run before response deadline",
                ));
            }
            outcome = profile.respondent_timeout_default;
            response_default = true;
        } else if request.response_refs.is_empty() {
            return Err(DisputeRailDenial::new(
                "dispute_response_refs_required",
                "received response must bind durable response refs",
            ));
        }
    }

    let rule = profile.outcome_rules.get(&outcome).ok_or_else(|| {
        DisputeRailDenial::new(
            "dispute_outcome_rule_missing",
            "resolved outcome has no admitted profile rule",
        )
    })?;
    if request.requested_remedy != rule.remedy {
        return Err(DisputeRailDenial::new(
            "dispute_remedy_not_profile_selected",
            "caller-requested remedy does not match the selected outcome rule",
        ));
    }
    let maximum_remedy_units = u64::try_from(
        (u128::from(case.disputed_value_units)
            * u128::from(rule.maximum_remedy_bps_of_disputed_value))
            / u128::from(BASIS_POINTS),
    )
    .map_err(|_| {
        DisputeRailDenial::new(
            "dispute_remedy_overflow",
            "maximum remedy calculation overflowed",
        )
    })?;
    require_safe("maximum_remedy_units", maximum_remedy_units)?;
    if request.requested_remedy_units > maximum_remedy_units
        || (!rule.remedy.carries_value() && request.requested_remedy_units != 0)
    {
        return Err(DisputeRailDenial::new(
            "dispute_remedy_amount_exceeds_profile",
            "remedy amount exceeds the outcome rule cap",
        ));
    }

    let bond_pool_units = profile
        .challenger_bond_units
        .checked_add(profile.respondent_bond_units)
        .ok_or_else(|| {
            DisputeRailDenial::new("dispute_bond_pool_overflow", "held bond pool overflowed")
        })?;
    require_safe("bond_pool_units", bond_pool_units)?;
    let bond_allocation = allocate_bond_pool(bond_pool_units, &rule.bond_distribution)?;

    let mut required_receipt_kinds = vec![
        "dispute_resolution".to_string(),
        "bond_distribution".to_string(),
    ];
    if rule.remedy != DisputeRemedy::None {
        required_receipt_kinds.push("dispute_remedy_execution".to_string());
    }
    if outcome == DisputeOutcome::Escalated {
        required_receipt_kinds.push("dispute_escalation".to_string());
    }

    let appeal_deadline_ms = request
        .decided_at_ms
        .checked_add(profile.appeal_window_ms)
        .ok_or_else(|| {
            DisputeRailDenial::new("dispute_window_overflow", "appeal window overflowed")
        })?;
    require_safe("appeal_deadline_ms", appeal_deadline_ms)?;
    if case.evidence_retained_until_ms < appeal_deadline_ms {
        return Err(DisputeRailDenial::new(
            "dispute_evidence_retention_too_short",
            "evidence retention must cover the actual resolution appeal window",
        ));
    }

    Ok(DisputeResolutionDecision {
        dispute_resolution_ref: request.dispute_resolution_ref.clone(),
        dispute_ref: case.dispute_ref.clone(),
        profile_ref: profile.profile_ref.clone(),
        profile_version: profile.profile_version,
        profile_body_hash: expected_profile_hash,
        rail_kind: profile.rail_kind,
        value_unit: profile.value_unit.clone(),
        case_head_hash: case.case_head_hash.clone(),
        request_hash: computed_request_hash,
        idempotency_key: request.idempotency_key.clone(),
        adjudicator_ref: request.adjudicator_ref.clone(),
        decided_at_ms: request.decided_at_ms,
        evidence_refs: request.evidence_refs.clone(),
        response_refs: request.response_refs.clone(),
        appeal_of_resolution_ref: request.appeal_of_resolution_ref.clone(),
        outcome,
        remedy: rule.remedy,
        remedy_units: request.requested_remedy_units,
        bond_pool_units,
        bond_allocation,
        used_evidence_unavailable_default: evidence_default,
        used_respondent_timeout_default: response_default,
        appeal_deadline_ms,
        required_receipt_kinds,
        resolution_state: DisputeResolutionState::Admitted,
    })
}

pub fn export_dispute_rail_bundle(
    bundle_ref: &str,
    profile: &DisputeRailProfile,
    case: &DisputeCaseSnapshot,
    resolution: &DisputeResolutionDecision,
    exported_at_ms: u64,
) -> Result<Value, DisputeRailDenial> {
    require_ref("bundle_ref", bundle_ref)?;
    require_safe("exported_at_ms", exported_at_ms)?;
    validate_dispute_case(profile, case)?;
    let profile_hash = profile_body_hash(profile)?;
    require_ref(
        "resolution.dispute_resolution_ref",
        &resolution.dispute_resolution_ref,
    )?;
    require_ref("resolution.adjudicator_ref", &resolution.adjudicator_ref)?;
    require_hash("resolution.request_hash", &resolution.request_hash)?;
    require_safe("resolution.decided_at_ms", resolution.decided_at_ms)?;
    require_safe("resolution.remedy_units", resolution.remedy_units)?;
    require_safe("resolution.bond_pool_units", resolution.bond_pool_units)?;
    require_safe(
        "resolution.appeal_deadline_ms",
        resolution.appeal_deadline_ms,
    )?;
    let rule = profile
        .outcome_rules
        .get(&resolution.outcome)
        .ok_or_else(|| {
            DisputeRailDenial::new(
                "dispute_bundle_binding_invalid",
                "resolution outcome has no profile rule",
            )
        })?;
    let maximum_remedy_units = u64::try_from(
        (u128::from(case.disputed_value_units)
            * u128::from(rule.maximum_remedy_bps_of_disputed_value))
            / u128::from(BASIS_POINTS),
    )
    .map_err(|_| {
        DisputeRailDenial::new(
            "dispute_remedy_overflow",
            "maximum remedy calculation overflowed",
        )
    })?;
    let expected_bond_pool = profile
        .challenger_bond_units
        .checked_add(profile.respondent_bond_units)
        .ok_or_else(|| {
            DisputeRailDenial::new("dispute_bond_pool_overflow", "held bond pool overflowed")
        })?;
    let expected_allocation = allocate_bond_pool(expected_bond_pool, &rule.bond_distribution)?;
    let mut expected_receipt_kinds = vec![
        "dispute_resolution".to_string(),
        "bond_distribution".to_string(),
    ];
    if rule.remedy != DisputeRemedy::None {
        expected_receipt_kinds.push("dispute_remedy_execution".to_string());
    }
    if resolution.outcome == DisputeOutcome::Escalated {
        expected_receipt_kinds.push("dispute_escalation".to_string());
    }
    let expected_appeal_deadline = resolution
        .decided_at_ms
        .checked_add(profile.appeal_window_ms)
        .ok_or_else(|| {
            DisputeRailDenial::new("dispute_window_overflow", "appeal window overflowed")
        })?;
    if resolution.dispute_ref != case.dispute_ref
        || resolution.profile_ref != profile.profile_ref
        || resolution.profile_version != profile.profile_version
        || resolution.profile_body_hash != profile_hash
        || resolution.rail_kind != profile.rail_kind
        || resolution.value_unit != profile.value_unit
        || resolution.case_head_hash != case.case_head_hash
        || resolution.resolution_state != DisputeResolutionState::Admitted
        || resolution.remedy != rule.remedy
        || resolution.remedy_units > maximum_remedy_units
        || (!resolution.remedy.carries_value() && resolution.remedy_units != 0)
        || resolution.bond_pool_units != expected_bond_pool
        || resolution.bond_allocation != expected_allocation
        || resolution.required_receipt_kinds != expected_receipt_kinds
        || resolution.appeal_deadline_ms != expected_appeal_deadline
        || resolution.decided_at_ms < case.opened_at_ms
        || case.evidence_retained_until_ms < expected_appeal_deadline
        || (resolution.used_evidence_unavailable_default
            && resolution.outcome != profile.evidence_unavailable_default)
        || (resolution.used_respondent_timeout_default
            && resolution.outcome != profile.respondent_timeout_default)
        || (resolution.used_evidence_unavailable_default
            && resolution.used_respondent_timeout_default)
    {
        return Err(DisputeRailDenial::new(
            "dispute_bundle_binding_invalid",
            "resolution does not bind and conserve the supplied profile/case/value unit",
        ));
    }
    let outcome_rules = profile
        .outcome_rules
        .iter()
        .map(|(outcome, rule)| {
            json!({
                "outcome": outcome,
                "remedy": rule.remedy,
                "maximum_remedy_bps_of_disputed_value":
                    rule.maximum_remedy_bps_of_disputed_value,
                "bond_distribution": rule.bond_distribution,
            })
        })
        .collect::<Vec<_>>();
    let bundle = json!({
        "schema_version": DISPUTE_RAIL_BUNDLE_SCHEMA_VERSION,
        "bundle_ref": bundle_ref,
        "profile": {
            "dispute_rail_profile_ref": profile.profile_ref,
            "profile_version": profile.profile_version,
            "profile_body_hash": profile_hash,
            "rail_kind": profile.rail_kind,
            "value_unit": profile.value_unit,
            "ordinary_verification_funding_ref": profile.ordinary_verification_funding_ref,
            "challenger_bond_units": profile.challenger_bond_units,
            "respondent_bond_units": profile.respondent_bond_units,
            "evidence_window_ms": profile.evidence_window_ms,
            "response_window_ms": profile.response_window_ms,
            "appeal_window_ms": profile.appeal_window_ms,
            "evidence_unavailable_default": profile.evidence_unavailable_default,
            "respondent_timeout_default": profile.respondent_timeout_default,
            "allowed_remedies": profile.allowed_remedies,
            "outcome_rules": outcome_rules,
        },
        "dispute": case,
        "resolution": {
            "dispute_resolution_ref": resolution.dispute_resolution_ref,
            "dispute_ref": resolution.dispute_ref,
            "dispute_rail_profile_ref": resolution.profile_ref,
            "dispute_rail_profile_version": resolution.profile_version,
            "dispute_rail_profile_body_hash": resolution.profile_body_hash,
            "rail_kind": resolution.rail_kind,
            "value_unit": resolution.value_unit,
            "case_head_hash": resolution.case_head_hash,
            "request_hash": resolution.request_hash,
            "idempotency_key": resolution.idempotency_key,
            "adjudicator_ref": resolution.adjudicator_ref,
            "decided_at_ms": resolution.decided_at_ms,
            "evidence_refs": resolution.evidence_refs,
            "response_refs": resolution.response_refs,
            "appeal_of_resolution_ref": resolution.appeal_of_resolution_ref,
            "outcome": resolution.outcome,
            "remedy": resolution.remedy,
            "remedy_units": resolution.remedy_units,
            "bond_pool_units": resolution.bond_pool_units,
            "bond_allocation": resolution.bond_allocation,
            "used_evidence_unavailable_default":
                resolution.used_evidence_unavailable_default,
            "used_respondent_timeout_default":
                resolution.used_respondent_timeout_default,
            "appeal_deadline_ms": resolution.appeal_deadline_ms,
            "required_receipt_kinds": resolution.required_receipt_kinds,
            "resolution_state": resolution.resolution_state,
        },
        "exported_at_ms": exported_at_ms,
        "assurance_status": "deterministic_admission_only",
    });
    validate_architecture_contract(DISPUTE_RAIL_BUNDLE_CONTRACT_ID, &bundle).map_err(|error| {
        DisputeRailDenial::new(
            "dispute_bundle_contract_invalid",
            format!("exported dispute bundle violates the registered contract: {error}"),
        )
    })?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn value_unit() -> DisputeValueUnitBinding {
        DisputeValueUnitBinding {
            asset_ref: "asset://usdc/base".to_string(),
            unit_ref: "denomination://usdc/base/micro".to_string(),
            unit_version: 1,
            unit_body_hash: hash('a'),
            atomic_unit_code: "micro_usdc".to_string(),
            decimals: 6,
        }
    }

    fn distribution(
        challenger_return_bps: u64,
        respondent_return_bps: u64,
        challenger_award_bps: u64,
        respondent_award_bps: u64,
        verifier_funding_bps: u64,
        treasury_bps: u64,
        burn_bps: u64,
    ) -> BondDistributionBps {
        BondDistributionBps {
            challenger_return_bps,
            respondent_return_bps,
            challenger_award_bps,
            respondent_award_bps,
            verifier_funding_bps,
            treasury_bps,
            burn_bps,
            rounding_recipient: BondRoundingRecipient::VerifierFunding,
        }
    }

    fn profile() -> DisputeRailProfile {
        DisputeRailProfile {
            profile_ref: "policy://dispute/marketplace-v1".to_string(),
            profile_version: 1,
            rail_kind: DisputeRailKind::MarketplaceEscrow,
            value_unit: value_unit(),
            ordinary_verification_funding_ref: Some("budget://verification/1".to_string()),
            challenger_bond_units: 101,
            respondent_bond_units: 100,
            evidence_window_ms: 100,
            response_window_ms: 100,
            appeal_window_ms: 100,
            evidence_unavailable_default: DisputeOutcome::Escalated,
            respondent_timeout_default: DisputeOutcome::ChallengerUpheld,
            allowed_remedies: BTreeSet::from([
                DisputeRemedy::Refund,
                DisputeRemedy::None,
                DisputeRemedy::Escalate,
            ]),
            outcome_rules: BTreeMap::from([
                (
                    DisputeOutcome::ChallengerUpheld,
                    DisputeOutcomeRule {
                        remedy: DisputeRemedy::Refund,
                        maximum_remedy_bps_of_disputed_value: 10_000,
                        bond_distribution: distribution(5_000, 0, 3_000, 0, 1_000, 0, 1_000),
                    },
                ),
                (
                    DisputeOutcome::RespondentUpheld,
                    DisputeOutcomeRule {
                        remedy: DisputeRemedy::None,
                        maximum_remedy_bps_of_disputed_value: 0,
                        bond_distribution: distribution(0, 5_000, 0, 3_000, 1_000, 0, 1_000),
                    },
                ),
                (
                    DisputeOutcome::Escalated,
                    DisputeOutcomeRule {
                        remedy: DisputeRemedy::Escalate,
                        maximum_remedy_bps_of_disputed_value: 0,
                        bond_distribution: distribution(5_000, 4_000, 0, 0, 1_000, 0, 0),
                    },
                ),
            ]),
        }
    }

    fn case() -> DisputeCaseSnapshot {
        let profile = profile();
        DisputeCaseSnapshot {
            dispute_ref: "dispute://1".to_string(),
            dispute_rail_profile_ref: profile.profile_ref.clone(),
            dispute_rail_profile_version: profile.profile_version,
            dispute_rail_profile_body_hash: profile_body_hash(&profile).unwrap(),
            value_unit: profile.value_unit,
            challenged_ref: "delivery://1".to_string(),
            challenger_ref: "org://buyer".to_string(),
            respondent_ref: "org://seller".to_string(),
            opened_at_ms: 1_000,
            evidence_retained_until_ms: 1_300,
            disputed_value_units: 1_000,
            challenger_bond_hold_ref: Some("hold://challenger/1".to_string()),
            challenger_bond_held_units: 101,
            respondent_bond_hold_ref: Some("hold://respondent/1".to_string()),
            respondent_bond_held_units: 100,
            escrow_ref: Some("escrow://order/1".to_string()),
            collaboration_terms_ref: None,
            collaboration_terms_root: None,
            settlement_profile_ref: None,
            network_enrollment_ref: None,
            case_head_hash: hash('b'),
        }
    }

    fn request() -> DisputeResolutionRequest {
        let profile = profile();
        DisputeResolutionRequest {
            dispute_resolution_ref: "dispute-resolution://1".to_string(),
            dispute_ref: "dispute://1".to_string(),
            dispute_rail_profile_ref: profile.profile_ref.clone(),
            dispute_rail_profile_version: profile.profile_version,
            dispute_rail_profile_body_hash: profile_body_hash(&profile).unwrap(),
            value_unit: profile.value_unit,
            expected_case_head_hash: hash('b'),
            idempotency_key: "resolve:dispute://1:v1".to_string(),
            decided_at_ms: 1_150,
            requested_outcome: DisputeOutcome::ChallengerUpheld,
            requested_remedy: DisputeRemedy::Refund,
            requested_remedy_units: 1_000,
            evidence_available: true,
            response_received: true,
            evidence_refs: vec!["evidence://buyer/1".to_string()],
            response_refs: vec!["evidence://seller/1".to_string()],
            adjudicator_ref: "verifier://independent/1".to_string(),
            appeal_of_resolution_ref: None,
        }
    }

    #[test]
    fn profile_selected_outcome_conserves_bond_pool() {
        let profile = profile();
        let case = case();
        let decision = resolve_dispute(&profile, &case, &request(), None).unwrap();
        assert_eq!(decision.remedy_units, 1_000);
        assert_eq!(decision.bond_pool_units, 201);
        assert_eq!(decision.bond_allocation.total(), Some(201));
        assert_eq!(decision.outcome, DisputeOutcome::ChallengerUpheld);
        let bundle = export_dispute_rail_bundle(
            "dispute-bundle://marketplace/order-1/resolution-1",
            &profile,
            &case,
            &decision,
            1_200,
        )
        .expect("contract-valid dispute bundle");
        assert_eq!(bundle["assurance_status"], "deterministic_admission_only");
        assert_eq!(
            bundle["resolution"]["value_unit"]["unit_ref"],
            "denomination://usdc/base/micro"
        );
        let mut forged_execution = decision;
        forged_execution.resolution_state = DisputeResolutionState::Executed;
        let error = export_dispute_rail_bundle(
            "dispute-bundle://marketplace/order-1/forged-execution",
            &profile,
            &case,
            &forged_execution,
            1_200,
        )
        .expect_err("admission kernel cannot claim execution");
        assert_eq!(error.code, "dispute_bundle_binding_invalid");
    }

    #[test]
    fn exact_replay_is_idempotent_and_changed_body_conflicts() {
        let first = resolve_dispute(&profile(), &case(), &request(), None).unwrap();
        let prior = PriorDisputeResolution {
            idempotency_key: first.idempotency_key.clone(),
            request_hash: first.request_hash.clone(),
            decision: first.clone(),
        };
        let replay = resolve_dispute(&profile(), &case(), &request(), Some(&prior)).unwrap();
        assert_eq!(replay, first);

        let mut changed = request();
        changed.requested_remedy_units = 999;
        let error = resolve_dispute(&profile(), &case(), &changed, Some(&prior)).unwrap_err();
        assert_eq!(error.code, "dispute_idempotency_conflict");
    }

    #[test]
    fn unavailable_evidence_uses_declared_default_only_after_window() {
        let mut early = request();
        early.decided_at_ms = 1_050;
        early.evidence_available = false;
        early.evidence_refs.clear();
        early.requested_outcome = DisputeOutcome::Escalated;
        early.requested_remedy = DisputeRemedy::Escalate;
        early.requested_remedy_units = 0;
        let error = resolve_dispute(&profile(), &case(), &early, None).unwrap_err();
        assert_eq!(error.code, "dispute_evidence_window_open");

        early.decided_at_ms = 1_200;
        let decision = resolve_dispute(&profile(), &case(), &early, None).unwrap();
        assert_eq!(decision.outcome, DisputeOutcome::Escalated);
        assert!(decision.used_evidence_unavailable_default);
    }

    #[test]
    fn evidence_retention_must_cover_appeal() {
        let mut short = case();
        short.evidence_retained_until_ms = 1_299;
        let error = validate_dispute_case(&profile(), &short).unwrap_err();
        assert_eq!(error.code, "dispute_evidence_retention_too_short");
    }

    #[test]
    fn public_settlement_requires_enrollment_and_profile() {
        let mut public_profile = profile();
        public_profile.rail_kind = DisputeRailKind::PublicSettlement;
        let mut public_case = case();
        public_case.dispute_rail_profile_ref = public_profile.profile_ref.clone();
        public_case.dispute_rail_profile_version = public_profile.profile_version;
        public_case.dispute_rail_profile_body_hash =
            profile_body_hash(&public_profile).expect("profile hash");
        public_case.value_unit = public_profile.value_unit.clone();
        let error = validate_dispute_case(&public_profile, &public_case).unwrap_err();
        assert_eq!(error.code, "dispute_public_settlement_binding_missing");
    }

    #[test]
    fn asset_unit_substitution_is_rejected_at_case_and_resolution_boundaries() {
        let profile = profile();
        let mut substituted_case = case();
        substituted_case.value_unit.unit_ref = "denomination://usdc/base/whole-token".to_string();
        let error = validate_dispute_case(&profile, &substituted_case).unwrap_err();
        assert_eq!(error.code, "dispute_value_unit_mismatch");

        let mut substituted_request = request();
        substituted_request.value_unit.asset_ref = "asset://usd/fiat".to_string();
        let error = resolve_dispute(&profile, &case(), &substituted_request, None).unwrap_err();
        assert_eq!(error.code, "dispute_resolution_binding_invalid");
    }

    #[test]
    fn a_foreign_prior_decision_cannot_be_replayed_by_hash_and_key_alone() {
        let profile = profile();
        let case = case();
        let request = request();
        let first = resolve_dispute(&profile, &case, &request, None).unwrap();
        let mut foreign = first.clone();
        foreign.dispute_ref = "dispute://foreign".to_string();
        let prior = PriorDisputeResolution {
            idempotency_key: first.idempotency_key.clone(),
            request_hash: first.request_hash.clone(),
            decision: foreign,
        };
        let error = resolve_dispute(&profile, &case, &request, Some(&prior)).unwrap_err();
        assert_eq!(error.code, "dispute_prior_resolution_binding_invalid");
    }

    #[test]
    fn zero_bond_profiles_cannot_smuggle_hold_refs() {
        let mut internal_profile = profile();
        internal_profile.rail_kind = DisputeRailKind::InternalReview;
        internal_profile.challenger_bond_units = 0;
        internal_profile.respondent_bond_units = 0;
        let mut internal_case = case();
        internal_case.dispute_rail_profile_ref = internal_profile.profile_ref.clone();
        internal_case.dispute_rail_profile_version = internal_profile.profile_version;
        internal_case.dispute_rail_profile_body_hash =
            profile_body_hash(&internal_profile).expect("profile hash");
        internal_case.value_unit = internal_profile.value_unit.clone();
        internal_case.challenger_bond_held_units = 0;
        internal_case.respondent_bond_held_units = 0;
        let error = validate_dispute_case(&internal_profile, &internal_case).unwrap_err();
        assert_eq!(error.code, "dispute_bond_hold_mismatch");
    }

    #[test]
    fn non_value_remedies_and_portable_integer_ceiling_fail_closed() {
        let mut invalid_profile = profile();
        invalid_profile
            .outcome_rules
            .get_mut(&DisputeOutcome::Escalated)
            .expect("escalation rule")
            .maximum_remedy_bps_of_disputed_value = 1;
        let error = validate_profile(&invalid_profile).unwrap_err();
        assert_eq!(error.code, "dispute_outcome_rule_invalid");

        let mut oversized_profile = profile();
        oversized_profile.challenger_bond_units = MAX_SAFE_FIXED_POINT_UNITS + 1;
        let error = validate_profile(&oversized_profile).unwrap_err();
        assert_eq!(error.code, "dispute_fixed_point_overflow");
    }
}
