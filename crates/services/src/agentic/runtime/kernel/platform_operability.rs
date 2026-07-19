//! Deterministic cross-plane operability decisions.
//!
//! This kernel does not repair a plane or prove that an observation is true.
//! It consumes owner-produced plane observations and answers the narrower
//! question: which operation posture is still claimable, what must fail
//! closed, and which evidence/reconciliation duties survive degraded service.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const PLATFORM_FAULT_SCENARIO_SCHEMA: &str = "ioi.platform-fault-scenario.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformPlane {
    Daemon,
    Agentgres,
    Authority,
    Storage,
    Clock,
    Provider,
    NetworkFleet,
    Attestation,
    Billing,
    PublicSettlement,
}

impl PlatformPlane {
    fn as_slug(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Agentgres => "agentgres",
            Self::Authority => "authority",
            Self::Storage => "storage",
            Self::Clock => "clock",
            Self::Provider => "provider",
            Self::NetworkFleet => "network_fleet",
            Self::Attestation => "attestation",
            Self::Billing => "billing",
            Self::PublicSettlement => "public_settlement",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaneState {
    Healthy,
    Degraded,
    Stale,
    Unavailable,
    SplitBrainSuspected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformOperationClass {
    ProposalOnly,
    CachedRead,
    ConsistentRead,
    TruthMutation,
    ExternalEffect,
    PhysicalBoundedContinuation,
    PaidWorkStart,
    BillingFinalize,
    PortableAssuranceExport,
    PublicSettlement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssurancePosture {
    TrustedOperator,
    SoftwareOnly,
    MeasuredBoot,
    HardwareAttested,
}

impl AssurancePosture {
    fn rank(self) -> u8 {
        match self {
            Self::TrustedOperator => 0,
            Self::SoftwareOnly => 1,
            Self::MeasuredBoot => 2,
            Self::HardwareAttested => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperabilityDisposition {
    Available,
    Degraded,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaneObservation {
    pub plane: PlatformPlane,
    pub state: PlaneState,
    #[serde(default)]
    pub degraded_contract_ref: Option<String>,
    #[serde(default)]
    pub degraded_allowed_operations: Vec<PlatformOperationClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformOperabilityInput {
    pub operation: PlatformOperationClass,
    pub observations: Vec<PlaneObservation>,
    #[serde(default)]
    pub unknown_effect: bool,
    #[serde(default)]
    pub cached_state_age_ms: Option<u64>,
    #[serde(default)]
    pub maximum_cached_state_staleness_ms: Option<u64>,
    #[serde(default)]
    pub cached_state_source_head: Option<String>,
    #[serde(default)]
    pub provider_required: bool,
    #[serde(default)]
    pub storage_required: bool,
    #[serde(default)]
    pub cross_node_required: bool,
    #[serde(default)]
    pub local_supervisor_available: bool,
    pub asserted_assurance: AssurancePosture,
    pub fallback_assurance: AssurancePosture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformOperabilityDecision {
    pub disposition: OperabilityDisposition,
    pub reason_codes: Vec<String>,
    pub evidence_and_recovery_obligations: Vec<String>,
    pub effective_assurance: AssurancePosture,
    pub cached_state_usable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperabilityDenial {
    pub code: &'static str,
    pub message: String,
}

impl OperabilityDenial {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn required_planes(input: &PlatformOperabilityInput) -> BTreeSet<PlatformPlane> {
    use PlatformOperationClass as Operation;
    use PlatformPlane as Plane;

    let mut required = BTreeSet::new();
    match input.operation {
        Operation::ProposalOnly => {
            required.insert(Plane::Daemon);
        }
        Operation::CachedRead => {}
        Operation::ConsistentRead => {
            required.extend([Plane::Daemon, Plane::Agentgres, Plane::Clock]);
        }
        Operation::TruthMutation => {
            required.extend([
                Plane::Daemon,
                Plane::Agentgres,
                Plane::Authority,
                Plane::Clock,
            ]);
        }
        Operation::ExternalEffect => {
            required.extend([
                Plane::Daemon,
                Plane::Agentgres,
                Plane::Authority,
                Plane::Clock,
                Plane::NetworkFleet,
            ]);
        }
        Operation::PhysicalBoundedContinuation => {
            required.insert(Plane::Clock);
        }
        Operation::PaidWorkStart => {
            required.extend([
                Plane::Daemon,
                Plane::Agentgres,
                Plane::Authority,
                Plane::Clock,
                Plane::Billing,
            ]);
        }
        Operation::BillingFinalize => {
            required.extend([Plane::Daemon, Plane::Agentgres, Plane::Billing]);
        }
        Operation::PortableAssuranceExport => {
            required.extend([
                Plane::Daemon,
                Plane::Agentgres,
                Plane::Storage,
                Plane::Clock,
                Plane::Attestation,
            ]);
        }
        Operation::PublicSettlement => {
            required.extend([
                Plane::Daemon,
                Plane::Agentgres,
                Plane::Authority,
                Plane::Clock,
                Plane::NetworkFleet,
                Plane::PublicSettlement,
            ]);
        }
    }
    if input.provider_required {
        required.insert(Plane::Provider);
    }
    if input.storage_required {
        required.insert(Plane::Storage);
    }
    if input.cross_node_required {
        required.insert(Plane::NetworkFleet);
    }
    required
}

fn observation_map(
    observations: &[PlaneObservation],
) -> Result<BTreeMap<PlatformPlane, &PlaneObservation>, OperabilityDenial> {
    let mut by_plane = BTreeMap::new();
    for observation in observations {
        if by_plane.insert(observation.plane, observation).is_some() {
            return Err(OperabilityDenial::new(
                "platform_plane_observation_duplicated",
                format!(
                    "plane {:?} has more than one active observation",
                    observation.plane
                ),
            ));
        }
    }
    Ok(by_plane)
}

fn cached_state_usable(input: &PlatformOperabilityInput) -> bool {
    matches!(input.operation, PlatformOperationClass::CachedRead)
        && matches!(
            (input.cached_state_age_ms, input.maximum_cached_state_staleness_ms),
            (Some(age), Some(maximum)) if age <= maximum
        )
        && input
            .cached_state_source_head
            .as_deref()
            .is_some_and(|head| !head.trim().is_empty())
}

pub fn evaluate_platform_operability(
    input: &PlatformOperabilityInput,
) -> Result<PlatformOperabilityDecision, OperabilityDenial> {
    let observations = observation_map(&input.observations)?;
    if input.fallback_assurance.rank() > input.asserted_assurance.rank() {
        return Err(OperabilityDenial::new(
            "platform_assurance_fallback_widens_claim",
            "fallback assurance cannot be stronger than the asserted posture",
        ));
    }

    let mut reasons = BTreeSet::new();
    let mut obligations = BTreeSet::new();
    let mut disposition = OperabilityDisposition::Available;
    let cache_usable = cached_state_usable(input);

    if input.unknown_effect {
        reasons.insert("unknown_effect_requires_reconciliation".to_string());
        obligations.insert("preserve_attempt_and_effect_evidence".to_string());
        obligations.insert("reconcile_before_retry_compensation_or_success".to_string());
        disposition = OperabilityDisposition::FailClosed;
    }

    if input.operation == PlatformOperationClass::CachedRead {
        if input
            .cached_state_source_head
            .as_deref()
            .is_none_or(|head| head.trim().is_empty())
        {
            reasons.insert("cached_state_source_head_missing".to_string());
            obligations.insert("refresh_or_supply_exact_source_head".to_string());
            disposition = OperabilityDisposition::FailClosed;
        }
        if !matches!(
            (input.cached_state_age_ms, input.maximum_cached_state_staleness_ms),
            (Some(age), Some(maximum)) if age <= maximum
        ) {
            reasons.insert("cached_state_outside_declared_staleness".to_string());
            obligations.insert("refresh_or_fail_with_typed_unavailable".to_string());
            disposition = OperabilityDisposition::FailClosed;
        }
    }

    if input.operation == PlatformOperationClass::PhysicalBoundedContinuation
        && !input.local_supervisor_available
    {
        reasons.insert("local_supervisor_unavailable".to_string());
        obligations.insert("enter_declared_minimum_risk_or_safe_stop_state".to_string());
        disposition = OperabilityDisposition::FailClosed;
    }

    for plane in required_planes(input) {
        let plane_slug = plane.as_slug();
        match observations.get(&plane).copied() {
            None => {
                reasons.insert(format!("required_plane_missing:{plane_slug}"));
                obligations.insert(format!("obtain_current_plane_observation:{plane_slug}"));
                disposition = OperabilityDisposition::FailClosed;
            }
            Some(observation) if observation.state == PlaneState::Healthy => {}
            Some(observation) if observation.state == PlaneState::Degraded => {
                let contract_bound = observation
                    .degraded_contract_ref
                    .as_deref()
                    .is_some_and(|reference| !reference.trim().is_empty());
                let operation_allowed = observation
                    .degraded_allowed_operations
                    .contains(&input.operation);
                if !contract_bound || !operation_allowed {
                    reasons.insert(format!(
                        "required_plane_degraded_contract_excludes_operation:{plane_slug}"
                    ));
                    obligations.insert(format!(
                        "obtain_operation_specific_degraded_contract:{plane_slug}"
                    ));
                    disposition = OperabilityDisposition::FailClosed;
                } else {
                    reasons.insert(format!("required_plane_degraded:{plane_slug}"));
                    obligations.insert(format!("emit_degraded_operation_evidence:{plane_slug}"));
                    if disposition != OperabilityDisposition::FailClosed {
                        disposition = OperabilityDisposition::Degraded;
                    }
                }
            }
            Some(observation) if observation.state == PlaneState::Stale => {
                reasons.insert(format!("required_plane_stale:{plane_slug}"));
                obligations.insert(format!("refresh_required_plane:{plane_slug}"));
                disposition = OperabilityDisposition::FailClosed;
            }
            Some(observation) if observation.state == PlaneState::Unavailable => {
                reasons.insert(format!("required_plane_unavailable:{plane_slug}"));
                obligations.insert(format!("recover_or_route_around_plane:{plane_slug}"));
                disposition = OperabilityDisposition::FailClosed;
            }
            Some(observation) if observation.state == PlaneState::SplitBrainSuspected => {
                reasons.insert(format!("required_plane_split_brain:{plane_slug}"));
                obligations.insert(format!("fence_and_reconcile_plane:{plane_slug}"));
                disposition = OperabilityDisposition::FailClosed;
            }
            Some(_) => unreachable!("all plane states are matched"),
        }
    }

    // Non-required failures still produce explicit operational duties. They do
    // not silently become healthy, and they do not block unrelated local work.
    if observations
        .get(&PlatformPlane::PublicSettlement)
        .is_some_and(|observation| observation.state == PlaneState::Unavailable)
        && input.operation != PlatformOperationClass::PublicSettlement
    {
        reasons.insert("public_settlement_deferred".to_string());
        obligations.insert("retain_local_commitment_and_retry_settlement_later".to_string());
        if disposition == OperabilityDisposition::Available {
            disposition = OperabilityDisposition::Degraded;
        }
    }
    if observations
        .get(&PlatformPlane::Billing)
        .is_some_and(|observation| observation.state == PlaneState::Unavailable)
        && !matches!(
            input.operation,
            PlatformOperationClass::PaidWorkStart | PlatformOperationClass::BillingFinalize
        )
    {
        obligations.insert("do_not_start_new_paid_work_or_invent_cost_truth".to_string());
    }

    let attestation_state = observations
        .get(&PlatformPlane::Attestation)
        .map(|observation| observation.state)
        .unwrap_or(PlaneState::Unavailable);
    let mut effective_assurance = input.asserted_assurance;
    if !matches!(
        attestation_state,
        PlaneState::Healthy | PlaneState::Degraded
    ) && input.asserted_assurance.rank() > input.fallback_assurance.rank()
    {
        effective_assurance = input.fallback_assurance;
        reasons.insert("attestation_claim_narrowed".to_string());
        obligations.insert("emit_assurance_downgrade_and_reappraise".to_string());
        if input.operation == PlatformOperationClass::PortableAssuranceExport {
            disposition = OperabilityDisposition::FailClosed;
        } else if disposition == OperabilityDisposition::Available {
            disposition = OperabilityDisposition::Degraded;
        }
    }

    if cache_usable && disposition == OperabilityDisposition::Available {
        disposition = OperabilityDisposition::Degraded;
        reasons.insert("served_from_bounded_stale_cache".to_string());
        obligations.insert("record_cache_age_and_source_head".to_string());
    }

    Ok(PlatformOperabilityDecision {
        disposition,
        reason_codes: reasons.into_iter().collect(),
        evidence_and_recovery_obligations: obligations.into_iter().collect(),
        effective_assurance,
        cached_state_usable: cache_usable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct FaultMatrix {
        schema_version: String,
        scenarios: Vec<FaultScenario>,
    }

    #[derive(Debug, Deserialize)]
    struct FaultScenario {
        scenario_id: String,
        input: PlatformOperabilityInput,
        expected_disposition: OperabilityDisposition,
        expected_effective_assurance: AssurancePosture,
        required_reason_codes: Vec<String>,
        required_obligations: Vec<String>,
    }

    #[test]
    fn canonical_fault_matrix_has_deterministic_expected_states() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/conformance/hypervisor-core/platform-fault-matrix.v1.json");
        let bytes = std::fs::read(&path).expect("canonical platform fault matrix");
        let matrix: FaultMatrix = serde_json::from_slice(&bytes).expect("valid fault matrix");
        assert_eq!(matrix.schema_version, PLATFORM_FAULT_SCENARIO_SCHEMA);
        assert!(matrix.scenarios.len() >= 10);

        for scenario in matrix.scenarios {
            let decision = evaluate_platform_operability(&scenario.input)
                .unwrap_or_else(|error| panic!("{}: {}", scenario.scenario_id, error.message));
            assert_eq!(
                decision.disposition, scenario.expected_disposition,
                "{} disposition",
                scenario.scenario_id
            );
            assert_eq!(
                decision.effective_assurance, scenario.expected_effective_assurance,
                "{} assurance",
                scenario.scenario_id
            );
            for code in scenario.required_reason_codes {
                assert!(
                    decision.reason_codes.contains(&code),
                    "{} missing reason {} in {:?}",
                    scenario.scenario_id,
                    code,
                    decision.reason_codes
                );
            }
            for obligation in scenario.required_obligations {
                assert!(
                    decision
                        .evidence_and_recovery_obligations
                        .contains(&obligation),
                    "{} missing obligation {} in {:?}",
                    scenario.scenario_id,
                    obligation,
                    decision.evidence_and_recovery_obligations
                );
            }
        }
    }

    #[test]
    fn duplicate_plane_and_widening_fallback_are_rejected() {
        let duplicate = PlatformOperabilityInput {
            operation: PlatformOperationClass::ProposalOnly,
            observations: vec![
                PlaneObservation {
                    plane: PlatformPlane::Daemon,
                    state: PlaneState::Healthy,
                    degraded_contract_ref: None,
                    degraded_allowed_operations: Vec::new(),
                },
                PlaneObservation {
                    plane: PlatformPlane::Daemon,
                    state: PlaneState::Degraded,
                    degraded_contract_ref: Some("policy://platform/daemon-proposal-only".into()),
                    degraded_allowed_operations: vec![PlatformOperationClass::ProposalOnly],
                },
            ],
            unknown_effect: false,
            cached_state_age_ms: None,
            maximum_cached_state_staleness_ms: None,
            cached_state_source_head: None,
            provider_required: false,
            storage_required: false,
            cross_node_required: false,
            local_supervisor_available: false,
            asserted_assurance: AssurancePosture::SoftwareOnly,
            fallback_assurance: AssurancePosture::SoftwareOnly,
        };
        assert_eq!(
            evaluate_platform_operability(&duplicate).unwrap_err().code,
            "platform_plane_observation_duplicated"
        );

        let mut widening = duplicate;
        widening.observations.truncate(1);
        widening.asserted_assurance = AssurancePosture::TrustedOperator;
        widening.fallback_assurance = AssurancePosture::HardwareAttested;
        assert_eq!(
            evaluate_platform_operability(&widening).unwrap_err().code,
            "platform_assurance_fallback_widens_claim"
        );
    }
}
