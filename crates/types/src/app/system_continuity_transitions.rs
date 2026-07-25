//! Named continuity transitions for a live bounded System (M1.5d).
//!
//! Succession, migration, dissolution, and network enrollment are deliberately
//! not folded into the generic operational transition family. Each operation
//! has a distinct authority scope and compiles from the exact live predecessor,
//! active lifecycle profile, and caller-declared evidence/disposition inputs.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;
use crate::app::wallet_network::validate_principal_authority_ref;

use super::system_activation::{
    jcs_hash, namespace, required_string, UnverifiedCommittedSystemLifecycleStep,
};
use super::system_lifecycle_transitions::validate_activation_identity;

const LIFECYCLE_PROFILE_CONTRACT: &str = "schema://ioi/foundations/lifecycle-continuity-profile/v1";
const NETWORK_ENROLLMENT_CONTRACT: &str = "schema://ioi/foundations/ioi-network-enrollment/v1";
const MIGRATION_DESTINATION_ACK_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-migration-destination-acknowledgement/v1";
const SYSTEM_CHAIN_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-chain/v1";
const CONTINUITY_STATE_HASH_PROFILE: &str = "ioi.autonomous-system-lifecycle-state-jcs-sha256.v1";
const CONTINUITY_OPERATION_HASH_PROFILE: &str =
    "ioi.autonomous-system-continuity-operation-commitment-jcs-sha256.v1";

/// Named M1.5d operations. Enrollment is intentionally local-only at M1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityTransitionOp {
    /// Open governed succession without changing authority.
    InitiateSuccession,
    /// Complete succession with explicitly reissued authority.
    CompleteSuccession,
    /// Migrate while preserving System identity and verified state.
    Migrate,
    /// Open governed dissolution without terminating live effects.
    InitiateDissolution,
    /// Complete dissolution after every residual is disposed.
    CompleteDissolution,
    /// Admit a local-only, zero-assurance enrollment.
    EnrollLocal,
    /// Exit the current local-only enrollment.
    ExitLocalEnrollment,
}

impl ContinuityTransitionOp {
    /// Every M1.5d operation in stable order.
    pub const ALL: [Self; 7] = [
        Self::InitiateSuccession,
        Self::CompleteSuccession,
        Self::Migrate,
        Self::InitiateDissolution,
        Self::CompleteDissolution,
        Self::EnrollLocal,
        Self::ExitLocalEnrollment,
    ];

    /// Stable wire operation name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InitiateSuccession => "initiate_succession",
            Self::CompleteSuccession => "complete_succession",
            Self::Migrate => "migrate",
            Self::InitiateDissolution => "initiate_dissolution",
            Self::CompleteDissolution => "complete_dissolution",
            Self::EnrollLocal => "enroll_local",
            Self::ExitLocalEnrollment => "exit_local_enrollment",
        }
    }

    /// Parse a stable wire operation name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == value)
    }

    /// Exact one-operation wallet scope.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::InitiateSuccession => "scope:autonomous_system.continuity.initiate_succession",
            Self::CompleteSuccession => "scope:autonomous_system.continuity.complete_succession",
            Self::Migrate => "scope:autonomous_system.continuity.migrate",
            Self::InitiateDissolution => "scope:autonomous_system.continuity.initiate_dissolution",
            Self::CompleteDissolution => "scope:autonomous_system.continuity.complete_dissolution",
            Self::EnrollLocal => "scope:autonomous_system.network_enrollment.local.enroll",
            Self::ExitLocalEnrollment => "scope:autonomous_system.network_enrollment.local.exit",
        }
    }

    /// Canonical lifecycle transition kind, absent for enrollment operations.
    pub fn transition_kind(self) -> Option<&'static str> {
        match self {
            Self::InitiateSuccession => Some("initiate_succession"),
            Self::CompleteSuccession => Some("complete_succession"),
            Self::Migrate => Some("migrate"),
            Self::InitiateDissolution => Some("initiate_dissolution"),
            Self::CompleteDissolution => Some("complete_dissolution"),
            Self::EnrollLocal | Self::ExitLocalEnrollment => None,
        }
    }

    fn resulting_status(self, predecessor: &str) -> &'static str {
        match self {
            Self::InitiateSuccession => "succession_pending",
            Self::CompleteSuccession => "successor_governed",
            Self::InitiateDissolution => "dissolution_pending",
            Self::CompleteDissolution => "dissolved",
            Self::Migrate | Self::EnrollLocal | Self::ExitLocalEnrollment => match predecessor {
                "successor_governed" => "successor_governed",
                _ => "active",
            },
        }
    }

    fn admits_predecessor(self, predecessor: &str) -> bool {
        match self {
            Self::InitiateSuccession | Self::InitiateDissolution => {
                matches!(
                    predecessor,
                    "active" | "paused" | "suspended" | "successor_governed"
                )
            }
            Self::CompleteSuccession => predecessor == "succession_pending",
            Self::Migrate | Self::EnrollLocal | Self::ExitLocalEnrollment => {
                matches!(predecessor, "active" | "successor_governed")
            }
            Self::CompleteDissolution => predecessor == "dissolution_pending",
        }
    }
}

/// Closed caller declaration. Empty or irrelevant fields are rejected rather
/// than silently ignored so one operation cannot smuggle another operation's
/// authority or residual claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityTransitionDeclaration {
    /// Evidence that triggered the named transition.
    #[serde(default)]
    pub trigger_evidence_refs: Vec<String>,
    /// Governed successor candidate, where applicable.
    #[serde(default)]
    pub successor_candidate_ref: Option<String>,
    /// Reissued successor authority, only on completion.
    #[serde(default)]
    pub successor_authority_ref: Option<String>,
    /// Exact durable destination acknowledgement selected for migration.
    #[serde(default)]
    pub migration_destination_ack_ref: Option<String>,
    /// Content root of the exact durable destination acknowledgement.
    #[serde(default)]
    pub migration_destination_ack_root: Option<String>,
    /// Reserved for future externally owned disposition receipts. M1 derives
    /// residual closure from the exact live chain and rejects caller claims.
    #[serde(default)]
    pub residual_disposition_receipt_refs: Vec<String>,
    /// Live effects; this must always be empty at admission.
    #[serde(default)]
    pub live_effect_refs: Vec<String>,
    /// Exact local enrollment successor body.
    #[serde(default)]
    pub network_enrollment: Option<Value>,
}

/// Pure server-derived plan for one named continuity transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledContinuityTransitionPlan {
    /// Named operation.
    pub op: ContinuityTransitionOp,
    /// Monotonic committed sequence.
    pub sequence: u64,
    /// Exact predecessor status.
    pub predecessor_status: String,
    /// Derived resulting status.
    pub resulting_status: String,
    /// Exact unverified predecessor artifacts supplied by the durable loader.
    pub previous_step: UnverifiedCommittedSystemLifecycleStep,
    /// Semantic resulting state before evidence navigation is attached.
    pub semantic_state: Value,
    /// JCS root of the semantic resulting state.
    pub resulting_state_root: String,
    /// Closed effect authorized by wallet.network.
    pub authority_effect: Value,
    /// Validated enrollment body, if this is an enrollment operation.
    pub network_enrollment: Option<Value>,
}

fn canonical_ref(value: &str, prefixes: &[&str]) -> bool {
    !value.chars().any(char::is_whitespace)
        && value.len() <= 256
        && prefixes.iter().any(|prefix| value.starts_with(prefix))
}

fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn ensure_distinct(values: &[String], label: &str) -> Result<(), String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != values.len() {
        return Err(format!("{label} contains duplicate refs"));
    }
    Ok(())
}

fn validate_declaration(
    op: ContinuityTransitionOp,
    declaration: &ContinuityTransitionDeclaration,
) -> Result<(), String> {
    ensure_distinct(&declaration.trigger_evidence_refs, "trigger evidence")?;
    ensure_distinct(
        &declaration.residual_disposition_receipt_refs,
        "residual disposition",
    )?;
    ensure_distinct(&declaration.live_effect_refs, "live effects")?;
    if declaration
        .trigger_evidence_refs
        .iter()
        .any(|value| !canonical_ref(value, &["evidence://", "artifact://", "receipt://"]))
    {
        return Err("trigger evidence contains a non-canonical ref".to_owned());
    }
    if declaration
        .residual_disposition_receipt_refs
        .iter()
        .any(|value| !canonical_ref(value, &["receipt://"]))
    {
        return Err("residual disposition contains a non-receipt ref".to_owned());
    }
    if !declaration.live_effect_refs.is_empty() {
        return Err("dissolution or continuity cannot commit with live effects".to_owned());
    }

    let only = |allowed: &[&str]| {
        let present = [
            (
                "successor_candidate_ref",
                declaration.successor_candidate_ref.is_some(),
            ),
            (
                "successor_authority_ref",
                declaration.successor_authority_ref.is_some(),
            ),
            (
                "migration_destination_ack_ref",
                declaration.migration_destination_ack_ref.is_some(),
            ),
            (
                "migration_destination_ack_root",
                declaration.migration_destination_ack_root.is_some(),
            ),
            (
                "residual_disposition_receipt_refs",
                !declaration.residual_disposition_receipt_refs.is_empty(),
            ),
            (
                "network_enrollment",
                declaration.network_enrollment.is_some(),
            ),
        ];
        present
            .into_iter()
            .find(|(name, set)| *set && !allowed.contains(name))
            .map(|(name, _)| name)
    };
    let allowed = match op {
        ContinuityTransitionOp::InitiateSuccession => &["successor_candidate_ref"][..],
        ContinuityTransitionOp::CompleteSuccession => {
            &["successor_candidate_ref", "successor_authority_ref"][..]
        }
        ContinuityTransitionOp::Migrate => &[
            "migration_destination_ack_ref",
            "migration_destination_ack_root",
        ][..],
        ContinuityTransitionOp::InitiateDissolution => &[][..],
        ContinuityTransitionOp::CompleteDissolution => &[][..],
        ContinuityTransitionOp::EnrollLocal => &["network_enrollment"][..],
        ContinuityTransitionOp::ExitLocalEnrollment => &["network_enrollment"][..],
    };
    if let Some(field) = only(allowed) {
        return Err(format!("{field} is not admitted for {}", op.as_str()));
    }
    match op {
        ContinuityTransitionOp::InitiateSuccession => {
            if declaration
                .successor_candidate_ref
                .as_deref()
                .is_none_or(|value| {
                    !canonical_ref(
                        value,
                        &["principal://", "wallet://", "organization://", "org://"],
                    )
                })
            {
                return Err("succession requires one canonical successor candidate".to_owned());
            }
        }
        ContinuityTransitionOp::CompleteSuccession => {
            if declaration
                .successor_candidate_ref
                .as_deref()
                .is_none_or(|value| {
                    !canonical_ref(
                        value,
                        &["principal://", "wallet://", "organization://", "org://"],
                    )
                })
                || declaration
                    .successor_authority_ref
                    .as_deref()
                    .is_none_or(|value| validate_principal_authority_ref(value).is_err())
            {
                return Err(
                    "completed succession requires candidate and reissued authority refs"
                        .to_owned(),
                );
            }
        }
        ContinuityTransitionOp::Migrate => {
            if declaration
                .migration_destination_ack_ref
                .as_deref()
                .is_none_or(|value| {
                    !canonical_ref(value, &["migration-destination-acknowledgement://"])
                })
                || declaration
                    .migration_destination_ack_root
                    .as_deref()
                    .is_none_or(|value| !canonical_hash(value))
            {
                return Err(
                    "migration requires an exact durable destination acknowledgement".to_owned(),
                );
            }
        }
        ContinuityTransitionOp::CompleteDissolution => {}
        ContinuityTransitionOp::EnrollLocal | ContinuityTransitionOp::ExitLocalEnrollment => {
            if declaration.network_enrollment.is_none() {
                return Err(
                    "network enrollment operation requires the exact enrollment body".to_owned(),
                );
            }
        }
        ContinuityTransitionOp::InitiateDissolution => {}
    }
    Ok(())
}

fn validate_profile(
    profile: &Value,
    system_id: &str,
    _constitution_ref: &str,
    op: ContinuityTransitionOp,
) -> Result<(), String> {
    validate_architecture_contract(LIFECYCLE_PROFILE_CONTRACT, profile)
        .map_err(|error| format!("lifecycle profile is invalid: {error}"))?;
    if profile.get("system_id").and_then(Value::as_str) != Some(system_id) {
        return Err("lifecycle profile does not belong to this System".to_owned());
    }
    match op {
        ContinuityTransitionOp::InitiateSuccession | ContinuityTransitionOp::CompleteSuccession => {
            if profile
                .pointer("/succession/enabled")
                .and_then(Value::as_bool)
                != Some(true)
                || profile
                    .pointer("/succession/constitution_must_be_preserved")
                    .and_then(Value::as_bool)
                    != Some(true)
                || profile
                    .pointer("/succession/authority_handoff")
                    .and_then(Value::as_str)
                    != Some("rotate_and_reissue")
            {
                return Err("active lifecycle profile does not admit bounded succession".to_owned());
            }
        }
        ContinuityTransitionOp::Migrate => {
            if profile
                .pointer("/migration/allowed")
                .and_then(Value::as_bool)
                != Some(true)
                || profile
                    .pointer("/migration/identity_continuity_required")
                    .and_then(Value::as_bool)
                    != Some(true)
                || profile
                    .pointer("/migration/state_root_verification_required")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return Err(
                    "active lifecycle profile does not admit identity-preserving migration"
                        .to_owned(),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_local_enrollment(
    op: ContinuityTransitionOp,
    enrollment: &Value,
    system_id: &str,
    constitution_ref: &str,
    current_enrollment: Option<&Value>,
    sequence: u64,
) -> Result<(), String> {
    validate_architecture_contract(NETWORK_ENROLLMENT_CONTRACT, enrollment)
        .map_err(|error| format!("network enrollment is invalid: {error}"))?;
    let expected_decision_ref = format!(
        "decision://{}/continuity/sequence/{sequence}",
        namespace(system_id)?
    );
    if enrollment.get("system_id").and_then(Value::as_str) != Some(system_id)
        || enrollment.get("constitution_ref").and_then(Value::as_str) != Some(constitution_ref)
        || enrollment.get("profile").and_then(Value::as_str) != Some("ioi_compatible")
        || enrollment
            .pointer("/connection/network_ref")
            .is_some_and(|value| !value.is_null())
        || enrollment
            .get("selected_network_services")
            .and_then(Value::as_array)
            .is_none_or(|values| !values.is_empty())
        || enrollment.get("assurance_claim").and_then(Value::as_str) != Some("none")
    {
        return Err(
            "M1 admits only zero-service, zero-assurance ioi_compatible enrollment".to_owned(),
        );
    }
    let current_enrollment_ref = current_enrollment
        .and_then(|value| value.get("network_enrollment_id"))
        .and_then(Value::as_str);
    let status = enrollment.get("status").and_then(Value::as_str);
    let predecessor = enrollment
        .get("predecessor_enrollment_ref")
        .and_then(Value::as_str);
    match op {
        ContinuityTransitionOp::EnrollLocal => {
            if status != Some("local_only")
                || predecessor != current_enrollment_ref
                || enrollment
                    .get("governing_decision_ref")
                    .and_then(Value::as_str)
                    != Some(expected_decision_ref.as_str())
            {
                return Err(
                    "local enrollment must compare-and-swap the exact predecessor".to_owned(),
                );
            }
        }
        ContinuityTransitionOp::ExitLocalEnrollment => {
            if status != Some("local_only")
                || enrollment
                    .get("network_enrollment_id")
                    .and_then(Value::as_str)
                    != current_enrollment_ref
                || current_enrollment_ref.is_none()
                || current_enrollment != Some(enrollment)
            {
                return Err(
                    "local enrollment exit must cite the byte-exact current local enrollment"
                        .to_owned(),
                );
            }
        }
        _ => return Err("enrollment body supplied to a non-enrollment operation".to_owned()),
    }
    Ok(())
}

/// Compile one named continuity operation from exact durable owner inputs.
#[allow(clippy::too_many_arguments)]
pub fn compile_continuity_transition_plan(
    op: ContinuityTransitionOp,
    activation_effect: &Value,
    previous_step: &UnverifiedCommittedSystemLifecycleStep,
    chain_head: &Value,
    constitution_ref: &str,
    lifecycle_profile: &Value,
    current_enrollment: Option<&Value>,
    declaration: &ContinuityTransitionDeclaration,
    trusted_successor_authority_binding: Option<&Value>,
    trusted_migration_destination_ack: Option<&Value>,
) -> Result<CompiledContinuityTransitionPlan, String> {
    validate_activation_identity(activation_effect)?;
    validate_architecture_contract(SYSTEM_CHAIN_CONTRACT, chain_head)
        .map_err(|error| format!("live chain is invalid: {error}"))?;
    let chain_head_root = required_string(chain_head, "/chain_root")?;
    if !canonical_hash(chain_head_root) {
        return Err("predecessor chain head root is not canonical".to_owned());
    }
    validate_declaration(op, declaration)?;
    let system_id = required_string(activation_effect, "/system_id")?;
    namespace(system_id)?;
    validate_profile(lifecycle_profile, system_id, constitution_ref, op)?;
    if matches!(
        op,
        ContinuityTransitionOp::InitiateSuccession | ContinuityTransitionOp::CompleteSuccession
    ) {
        let candidate = declaration
            .successor_candidate_ref
            .as_deref()
            .ok_or("succession candidate is absent")?;
        if lifecycle_profile
            .pointer("/succession/successor_candidate_refs")
            .and_then(Value::as_array)
            .is_none_or(|values| !values.iter().any(|value| value.as_str() == Some(candidate)))
        {
            return Err("successor candidate is outside the active lifecycle profile".to_owned());
        }
    }

    let (state_ref_key, activation_state) =
        if previous_step.state.get("activation_state_ref").is_some() {
            ("activation_state_ref", true)
        } else if previous_step.state.get("lifecycle_state_ref").is_some() {
            ("lifecycle_state_ref", false)
        } else {
            return Err("predecessor state carries no canonical state ref".to_owned());
        };
    let predecessor_state_ref =
        required_string(&previous_step.state, &format!("/{state_ref_key}"))?.to_owned();
    let predecessor_sequence = previous_step
        .state
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or("predecessor state lacks a canonical sequence")?;
    if (activation_state && predecessor_sequence != 2)
        || (!activation_state && predecessor_sequence < 3)
    {
        return Err("predecessor state carries an illegal sequence".to_owned());
    }
    let predecessor_status = required_string(&previous_step.state, "/status")?.to_owned();
    if required_string(&previous_step.state, "/system_id")? != system_id {
        return Err("predecessor state detaches from the identity System".to_owned());
    }
    if !op.admits_predecessor(&predecessor_status) {
        return Err(format!(
            "{} cannot lawfully leave {predecessor_status}",
            op.as_str()
        ));
    }
    let sequence = predecessor_sequence
        .checked_add(1)
        .ok_or("sequence overflow")?;
    let resulting_status = op.resulting_status(&predecessor_status).to_owned();
    let active_profile_set_ref = required_string(&previous_step.state, "/active_profile_set_ref")?;
    let active_profile_set_root =
        required_string(&previous_step.state, "/active_profile_set_root")?;

    let chain_governing_authority_ref = chain_head
        .get("governance_owner_refs")
        .and_then(Value::as_array)
        .filter(|owners| owners.len() == 1)
        .and_then(|owners| owners[0].as_str())
        .ok_or("live chain must identify exactly one governing authority")?;
    if previous_step
        .state
        .get("governing_authority_ref")
        .and_then(Value::as_str)
        .is_some_and(|authority| authority != chain_governing_authority_ref)
    {
        return Err("predecessor state and live chain disagree on governing authority".to_owned());
    }
    let current_governing_authority_ref = chain_governing_authority_ref;
    validate_principal_authority_ref(current_governing_authority_ref)
        .map_err(|error| format!("live governing authority is invalid ({error})"))?;

    if op == ContinuityTransitionOp::CompleteSuccession {
        let pending_candidate = previous_step
            .state
            .get("pending_successor_candidate_ref")
            .and_then(Value::as_str)
            .ok_or("succession completion lacks a committed pending candidate")?;
        if declaration.successor_candidate_ref.as_deref() != Some(pending_candidate) {
            return Err(
                "succession completion candidate differs from the initiated candidate".to_owned(),
            );
        }
        if declaration.successor_authority_ref.as_deref() == Some(current_governing_authority_ref) {
            return Err("succession must rotate to a distinct governing authority".to_owned());
        }
        let expected_reissued_authority = format!("{pending_candidate}-authority");
        if declaration.successor_authority_ref.as_deref()
            != Some(expected_reissued_authority.as_str())
        {
            return Err(
                "successor authority must be the candidate's canonical reissued principal"
                    .to_owned(),
            );
        }
        let binding = trusted_successor_authority_binding
            .ok_or("succession completion lacks a verified successor authority binding")?;
        if binding.get("principal_ref").and_then(Value::as_str)
            != declaration.successor_authority_ref.as_deref()
            || binding
                .pointer("/approval_authority/revoked")
                .and_then(Value::as_bool)
                != Some(false)
            || binding
                .pointer("/approval_authority/scope_allowlist")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            return Err(
                "verified successor authority binding does not bind the declared live principal"
                    .to_owned(),
            );
        }
    } else if trusted_successor_authority_binding.is_some() {
        return Err(
            "successor authority binding supplied to a non-completion operation".to_owned(),
        );
    }

    let migration_ack = if op == ContinuityTransitionOp::Migrate {
        let acknowledgement = trusted_migration_destination_ack
            .ok_or("migration lacks its trusted destination acknowledgement")?;
        validate_architecture_contract(MIGRATION_DESTINATION_ACK_CONTRACT, acknowledgement)
            .map_err(|error| {
                format!("migration destination acknowledgement is invalid: {error}")
            })?;
        if acknowledgement
            .get("acknowledgement_ref")
            .and_then(Value::as_str)
            != declaration.migration_destination_ack_ref.as_deref()
            || acknowledgement
                .get("acknowledgement_root")
                .and_then(Value::as_str)
                != declaration.migration_destination_ack_root.as_deref()
            || acknowledgement.get("system_id").and_then(Value::as_str) != Some(system_id)
            || acknowledgement
                .get("predecessor_state_ref")
                .and_then(Value::as_str)
                != Some(predecessor_state_ref.as_str())
            || acknowledgement
                .get("predecessor_state_root")
                .and_then(Value::as_str)
                != Some(previous_step.state_root.as_str())
            || acknowledgement
                .get("predecessor_chain_head_root")
                .and_then(Value::as_str)
                != Some(chain_head_root)
            || acknowledgement
                .get("source_deployment_profile_ref")
                .and_then(Value::as_str)
                != chain_head
                    .get("deployment_profile_ref")
                    .and_then(Value::as_str)
            || acknowledgement
                .pointer("/authority_effect_material/source_governing_authority_ref")
                .and_then(Value::as_str)
                != Some(current_governing_authority_ref)
            || acknowledgement
                .get("acknowledged_state_root")
                .and_then(Value::as_str)
                != Some(previous_step.state_root.as_str())
            || acknowledgement.get("destination_ref")
                == acknowledgement.get("source_deployment_profile_ref")
            || acknowledgement.get("status").and_then(Value::as_str) != Some("committed")
        {
            return Err(
                "migration destination acknowledgement detaches from the exact live predecessor"
                    .to_owned(),
            );
        }
        Some(acknowledgement)
    } else {
        if trusted_migration_destination_ack.is_some() {
            return Err(
                "migration destination acknowledgement supplied to a non-migration operation"
                    .to_owned(),
            );
        }
        None
    };

    let current_enrollment_ref = chain_head
        .get("network_enrollment_ref")
        .and_then(Value::as_str);
    if current_enrollment_ref
        != current_enrollment
            .and_then(|value| value.get("network_enrollment_id"))
            .and_then(Value::as_str)
    {
        return Err("live enrollment reference lacks its byte-exact committed body".to_owned());
    }

    if let Some(enrollment) = declaration.network_enrollment.as_ref() {
        validate_local_enrollment(
            op,
            enrollment,
            system_id,
            constitution_ref,
            current_enrollment,
            sequence,
        )?;
    }
    let resulting_enrollment_ref = match op {
        ContinuityTransitionOp::EnrollLocal => declaration
            .network_enrollment
            .as_ref()
            .and_then(|value| value.get("network_enrollment_id"))
            .cloned()
            .unwrap_or(Value::Null),
        ContinuityTransitionOp::ExitLocalEnrollment => Value::Null,
        _ => current_enrollment_ref.map_or(Value::Null, |value| json!(value)),
    };
    let current_enrollment_root = current_enrollment
        .map(|value| {
            jcs_hash(&json!({
                "domain":"ioi.autonomous-system-network-enrollment-artifact-jcs-sha256.v1",
                "artifact":value,
            }))
        })
        .transpose()?;
    let resulting_enrollment_root = match op {
        ContinuityTransitionOp::EnrollLocal => declaration
            .network_enrollment
            .as_ref()
            .map(|value| {
                jcs_hash(&json!({
                    "domain":"ioi.autonomous-system-network-enrollment-artifact-jcs-sha256.v1",
                    "artifact":value,
                }))
            })
            .transpose()?,
        ContinuityTransitionOp::ExitLocalEnrollment => None,
        _ => current_enrollment_root.clone(),
    };
    let resulting_governing_authority_ref = if op == ContinuityTransitionOp::CompleteSuccession {
        declaration
            .successor_authority_ref
            .as_deref()
            .ok_or("completed succession lacks successor authority")?
    } else {
        current_governing_authority_ref
    };
    let pending_successor_candidate_ref = match op {
        ContinuityTransitionOp::InitiateSuccession => declaration.successor_candidate_ref.clone(),
        ContinuityTransitionOp::CompleteSuccession => None,
        _ => previous_step
            .state
            .get("pending_successor_candidate_ref")
            .cloned()
            .filter(|value| !value.is_null())
            .and_then(|value| value.as_str().map(str::to_owned)),
    };
    let migration_destination_ref = if let Some(acknowledgement) = migration_ack {
        Some(required_string(acknowledgement, "/destination_ref")?.to_owned())
    } else {
        previous_step
            .state
            .get("migration_destination_ref")
            .cloned()
            .filter(|value| !value.is_null())
            .and_then(|value| value.as_str().map(str::to_owned))
    };
    let residual_disposition = if op == ContinuityTransitionOp::CompleteDissolution {
        let empty_array = |pointer: &str| {
            chain_head
                .pointer(pointer)
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        };
        if !empty_array("/node_membership_refs")
            || !empty_array("/worker_instance_refs")
            || !empty_array("/workflow_refs")
            || !empty_array("/pending_proposal_refs")
            || current_enrollment_ref.is_some()
        {
            return Err(
                "named transition cannot close while durable live residuals remain".to_owned(),
            );
        }
        json!({
            "source":"server_derived_live_chain",
            "predecessor_chain_head_root":chain_head_root,
            "node_membership_refs":chain_head["node_membership_refs"],
            "worker_instance_refs":chain_head["worker_instance_refs"],
            "workflow_refs":chain_head["workflow_refs"],
            "pending_proposal_refs":chain_head["pending_proposal_refs"],
            "network_enrollment_ref":current_enrollment_ref,
            "closed":true,
        })
    } else {
        Value::Null
    };

    let lifecycle_state_ref = format!(
        "system-lifecycle-state://{}/sequence/{sequence}",
        namespace(system_id)?
    );
    let state_material = json!({
        "domain": CONTINUITY_STATE_HASH_PROFILE,
        "lifecycle_state_ref": lifecycle_state_ref,
        "system_id": system_id,
        "sequence": sequence,
        "status": resulting_status,
        "predecessor_state_root": previous_step.state_root,
        "active_profile_set_ref": active_profile_set_ref,
        "active_profile_set_root": active_profile_set_root,
        "governing_authority_ref": resulting_governing_authority_ref,
        "pending_successor_candidate_ref": pending_successor_candidate_ref,
        "network_enrollment_ref": resulting_enrollment_ref,
        "network_enrollment_root": resulting_enrollment_root,
        "migration_destination_ref": migration_destination_ref,
    });
    let resulting_state_root = jcs_hash(&state_material)?;
    let semantic_state = json!({
        "schema_version": "ioi.autonomous-system-continuity-state.v1",
        "lifecycle_state_ref": lifecycle_state_ref,
        "lifecycle_state_root": resulting_state_root,
        "system_id": system_id,
        "sequence": sequence,
        "status": resulting_status,
        "predecessor_state_root": previous_step.state_root,
        "transition_ref": Value::Null,
        "transition_root": Value::Null,
        "transition_receipt_ref": Value::Null,
        "transition_receipt_root": Value::Null,
        "active_profile_set_ref": active_profile_set_ref,
        "active_profile_set_root": active_profile_set_root,
        "governing_authority_ref": resulting_governing_authority_ref,
        "pending_successor_candidate_ref": pending_successor_candidate_ref,
        "network_enrollment_ref": resulting_enrollment_ref,
        "network_enrollment_root": resulting_enrollment_root,
        "migration_destination_ref": migration_destination_ref,
        "chain_ref": required_string(activation_effect, "/chain_ref")?,
        "created_at": Value::Null,
    });
    let mut authority_effect = json!({
        "schema_version": "ioi.autonomous-system-continuity-authority-effect.v1",
        "op": op.as_str(),
        "transition_kind": op.transition_kind(),
        "required_scope": op.required_scope(),
        "sequence": sequence,
        "system_id": system_id,
        "genesis_ref": required_string(activation_effect, "/genesis_ref")?,
        "source_governing_authority_ref": current_governing_authority_ref,
        "resulting_governing_authority_ref": resulting_governing_authority_ref,
        "predecessor_status": predecessor_status,
        "predecessor_state_ref": predecessor_state_ref,
        "predecessor_state_root": previous_step.state_root,
        "predecessor_chain_head_root": chain_head_root,
        "resulting_status": resulting_status,
        "resulting_state_ref": semantic_state["lifecycle_state_ref"],
        "resulting_state_root": resulting_state_root,
        "constitution_ref": constitution_ref,
        "lifecycle_profile_ref": lifecycle_profile["lifecycle_profile_id"],
        "active_profile_set_ref": active_profile_set_ref,
        "active_profile_set_root": active_profile_set_root,
        "chain_ref": required_string(activation_effect, "/chain_ref")?,
        "current_network_enrollment_ref": current_enrollment_ref,
        "current_network_enrollment_root": current_enrollment_root,
        "resulting_network_enrollment_ref": resulting_enrollment_ref,
        "resulting_network_enrollment_root": resulting_enrollment_root,
        "trigger_evidence_refs": declaration.trigger_evidence_refs,
        "successor_candidate_ref": declaration.successor_candidate_ref,
        "successor_authority_ref": declaration.successor_authority_ref,
        "successor_authority_binding": trusted_successor_authority_binding,
        "migration_destination_ack_ref": declaration.migration_destination_ack_ref,
        "migration_destination_ack_root": declaration.migration_destination_ack_root,
        "migration_destination_ref": migration_destination_ref,
        "verified_migration_state_root": migration_ack.and_then(|value| value.get("acknowledged_state_root")),
        "residual_disposition": residual_disposition,
        "live_effect_refs": declaration.live_effect_refs,
        "identity_preserved": true,
        "authority_widened": false,
        "network_assurance_admitted": false,
        "runtime_effect_admitted": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": CONTINUITY_OPERATION_HASH_PROFILE,
        "effect": authority_effect,
    }))?;
    authority_effect["operation_commitment"] = json!(operation_commitment);

    Ok(CompiledContinuityTransitionPlan {
        op,
        sequence,
        predecessor_status,
        resulting_status,
        previous_step: previous_step.clone(),
        semantic_state,
        resulting_state_root,
        authority_effect,
        network_enrollment: declaration.network_enrollment.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }
    fn fixture(path: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path),
        )
        .expect(path)
    }
    fn activation() -> Value {
        json!({
            "schema_version":"ioi.autonomous-system-lifecycle-authority-effect.v1","operation":"activate","sequence":2,
            "system_id":"system://acme/system-alpha","genesis_ref":"genesis://acme/system-alpha",
            "source_governing_authority_ref":"wallet://acme/governing","home_domain_ref":"home-domain://acme/alpha",
            "home_domain_commitment":h(1),"home_domain_binding_ref":"system-home-domain-binding://acme/alpha",
            "home_domain_binding_root":h(2),"policy_root":h(3),"module_registry_root":h(4),
            "upgrade_policy_ref":"policy://acme/upgrade","deployment_profile_ref":"deployment-profile://acme/system-alpha/revision/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "deployment_profile_root":h(5),"active_profile_set_ref":"active-profile-set://acme/alpha","active_profile_set_root":h(6),
            "chain_ref":"autonomous-system-chain://acme/alpha","live_chain_created":true,"node_membership_created":false,
            "runtime_effect_admitted":false,"network_effect_admitted":false
        })
    }
    fn step(sequence: u64, status: &str) -> UnverifiedCommittedSystemLifecycleStep {
        UnverifiedCommittedSystemLifecycleStep {
            proposal: json!({}),
            decision: json!({}),
            transition: json!({}),
            receipt: json!({"receipt_ref":"receipt://prior"}),
            state: json!({"lifecycle_state_ref":format!("system-lifecycle-state://acme/system-alpha/sequence/{sequence}"),
                "system_id":"system://acme/system-alpha","sequence":sequence,"status":status,
                "active_profile_set_ref":"active-profile-set://acme/alpha","active_profile_set_root":h(6)}),
            state_root: h(7),
            proposal_root: h(8),
            decision_root: h(9),
            transition_root: h(10),
            receipt_root: h(11),
        }
    }
    fn empty() -> ContinuityTransitionDeclaration {
        ContinuityTransitionDeclaration {
            trigger_evidence_refs: vec!["evidence://trigger/1".into()],
            successor_candidate_ref: None,
            successor_authority_ref: None,
            migration_destination_ack_ref: None,
            migration_destination_ack_root: None,
            residual_disposition_receipt_refs: vec![],
            live_effect_refs: vec![],
            network_enrollment: None,
        }
    }
    fn migration_ack() -> Value {
        let mut acknowledgement = fixture(
            "autonomous-system-migration-destination-acknowledgement-v1/positive-acknowledged.json",
        );
        let chain = fixture("autonomous-system-chain-v1/positive-active-sequence-two.json");
        let acknowledgement_ref =
            "migration-destination-acknowledgement://acme/system-alpha/sequence/4";
        let predecessor_state_ref = "system-lifecycle-state://acme/system-alpha/sequence/3";
        let predecessor_state_root = h(7);
        let predecessor_chain_head_root = chain["chain_root"].clone();
        let source_deployment_profile_ref = chain["deployment_profile_ref"].clone();
        let destination_ref = "deployment-profile://acme/system-alpha/migrated";
        let effect = json!({
            "schema_version":"ioi.autonomous-system-migration-destination-acknowledgement-effect.v1",
            "op":"acknowledge_migration_destination",
            "required_scope":"scope:autonomous_system.continuity.migration_destination_acknowledge",
            "sequence":4,
            "system_id":"system://acme/system-alpha",
            "genesis_ref":"genesis://acme/system-alpha",
            "source_governing_authority_ref":"org://acme/research",
            "predecessor_state_ref":predecessor_state_ref,
            "predecessor_state_root":predecessor_state_root,
            "predecessor_chain_head_root":predecessor_chain_head_root,
            "source_deployment_profile_ref":source_deployment_profile_ref,
            "destination_ref":destination_ref,
            "acknowledged_state_root":predecessor_state_root,
            "identity_preserved":true,
            "operation_commitment":Value::Null,
        });
        let operation_commitment = jcs_hash(&json!({
            "domain":"ioi.autonomous-system-migration-destination-acknowledgement-operation-jcs-sha256.v1",
            "effect":effect,
        })).expect("operation commitment");
        acknowledgement["acknowledgement_ref"] = json!(acknowledgement_ref);
        acknowledgement["system_id"] = json!("system://acme/system-alpha");
        acknowledgement["predecessor_state_ref"] = json!(predecessor_state_ref);
        acknowledgement["predecessor_state_root"] = json!(predecessor_state_root);
        acknowledgement["predecessor_chain_head_root"] = predecessor_chain_head_root;
        acknowledgement["source_deployment_profile_ref"] = source_deployment_profile_ref;
        acknowledgement["destination_ref"] = json!(destination_ref);
        acknowledgement["acknowledged_state_root"] = json!(predecessor_state_root);
        acknowledgement["operation_commitment"] = json!(operation_commitment);
        acknowledgement["authority_effect_material"] = effect;
        acknowledgement["acknowledgement_root"] = json!(jcs_hash(&json!({
            "domain":"ioi.autonomous-system-migration-destination-acknowledgement-jcs-sha256.v1",
            "acknowledgement_ref":acknowledgement_ref,
            "system_id":"system://acme/system-alpha",
            "predecessor_state_ref":predecessor_state_ref,
            "predecessor_state_root":predecessor_state_root,
            "predecessor_chain_head_root":acknowledgement["predecessor_chain_head_root"],
            "source_deployment_profile_ref":acknowledgement["source_deployment_profile_ref"],
            "destination_ref":destination_ref,
            "acknowledged_state_root":predecessor_state_root,
            "required_scope":"scope:autonomous_system.continuity.migration_destination_acknowledge",
            "operation_commitment":operation_commitment,
        }))
        .expect("acknowledgement root"));
        acknowledgement
    }
    fn compile(
        op: ContinuityTransitionOp,
        status: &str,
        declaration: &ContinuityTransitionDeclaration,
    ) -> Result<CompiledContinuityTransitionPlan, String> {
        let mut previous = step(3, status);
        if status == "succession_pending" {
            previous.state["pending_successor_candidate_ref"] = json!("org://acme/successor");
            previous.state["governing_authority_ref"] = json!("org://acme/research");
        }
        let chain = fixture("autonomous-system-chain-v1/positive-active-sequence-two.json");
        let successor_binding = json!({
            "principal_ref":"org://acme/successor-authority",
            "approval_authority":{"revoked":false,"scope_allowlist":["scope:autonomous_system.lifecycle.*"]}
        });
        let migration_acknowledgement = (op == ContinuityTransitionOp::Migrate).then(migration_ack);
        compile_continuity_transition_plan(
            op,
            &activation(),
            &previous,
            &chain,
            "constitution://acme/system-alpha/v1",
            &fixture("lifecycle-continuity-profile-v1/positive-successor-governed.json"),
            None,
            declaration,
            if op == ContinuityTransitionOp::CompleteSuccession {
                Some(&successor_binding)
            } else {
                None
            },
            migration_acknowledgement.as_ref(),
        )
    }

    #[test]
    fn succession_requires_candidate_then_reissued_authority_and_preserves_bounds() {
        let mut declaration = empty();
        declaration.successor_candidate_ref = Some("org://acme/successor".into());
        let first = compile(
            ContinuityTransitionOp::InitiateSuccession,
            "active",
            &declaration,
        )
        .expect("initiate");
        assert_eq!(first.resulting_status, "succession_pending");
        assert_eq!(first.authority_effect["authority_widened"], false);
        declaration.successor_authority_ref = Some("org://acme/successor-authority".into());
        let second = compile(
            ContinuityTransitionOp::CompleteSuccession,
            "succession_pending",
            &declaration,
        )
        .expect("complete");
        assert_eq!(second.resulting_status, "successor_governed");
    }

    #[test]
    fn migration_requires_verified_root_and_keeps_identity() {
        let mut declaration = empty();
        assert!(compile(ContinuityTransitionOp::Migrate, "active", &declaration).is_err());
        let acknowledgement = migration_ack();
        declaration.migration_destination_ack_ref = acknowledgement["acknowledgement_ref"]
            .as_str()
            .map(str::to_owned);
        declaration.migration_destination_ack_root = acknowledgement["acknowledgement_root"]
            .as_str()
            .map(str::to_owned);
        let plan =
            compile(ContinuityTransitionOp::Migrate, "active", &declaration).expect("migration");
        assert_eq!(plan.authority_effect["identity_preserved"], true);
        assert_eq!(
            plan.authority_effect["migration_destination_ref"],
            "deployment-profile://acme/system-alpha/migrated"
        );
    }

    #[test]
    fn dissolution_refuses_live_effects_and_caller_authored_residuals() {
        let mut declaration = empty();
        declaration.live_effect_refs = vec!["effect://still-live".into()];
        assert!(compile(
            ContinuityTransitionOp::InitiateDissolution,
            "active",
            &declaration
        )
        .unwrap_err()
        .contains("live effects"));
        let mut declaration = empty();
        declaration.residual_disposition_receipt_refs = vec!["receipt://residual/closed".into()];
        assert!(compile(
            ContinuityTransitionOp::CompleteDissolution,
            "dissolution_pending",
            &declaration,
        )
        .unwrap_err()
        .contains("not admitted"));
        let declaration = empty();
        let plan = compile(
            ContinuityTransitionOp::CompleteDissolution,
            "dissolution_pending",
            &declaration,
        )
        .expect("dissolve");
        assert_eq!(plan.resulting_status, "dissolved");
    }

    #[test]
    fn scopes_are_distinct_and_not_generic_lifecycle_scopes() {
        let mut scopes: Vec<_> = ContinuityTransitionOp::ALL
            .into_iter()
            .map(ContinuityTransitionOp::required_scope)
            .collect();
        scopes.sort();
        scopes.dedup();
        assert_eq!(scopes.len(), ContinuityTransitionOp::ALL.len());
        assert!(scopes
            .iter()
            .all(|scope| !scope.starts_with("scope:autonomous_system.lifecycle.")));
    }

    #[test]
    fn enrollment_exit_requires_the_exact_committed_body() {
        let mut committed = fixture("ioi-network-enrollment-v1/positive-local-only.json");
        committed["system_id"] = json!("system://acme/system-alpha");
        committed["constitution_ref"] = json!("constitution://acme/system-alpha/v1");
        let mut substituted = committed.clone();
        substituted["version"] = json!("substituted");
        assert!(validate_local_enrollment(
            ContinuityTransitionOp::ExitLocalEnrollment,
            &substituted,
            "system://acme/system-alpha",
            "constitution://acme/system-alpha/v1",
            Some(&committed),
            4,
        )
        .unwrap_err()
        .contains("byte-exact"));
    }
}
