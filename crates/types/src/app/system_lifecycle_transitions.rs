//! Generic protected operational lifecycle transitions (M1.5 m1-5b).
//!
//! This family is deliberately separate from [`super::system_activation`]:
//! the bootstrap `SystemLifecycleOperation` is closed at sequences one and
//! two by canon, while these ops run at sequence three or later over the
//! live chain. The op-by-predecessor legality table here is the normative
//! machine form of the table in
//! `docs/architecture/foundations/common-objects-and-envelopes.md`
//! (`AutonomousSystemProtectedTransitionProposalEnvelope`); the unit tests
//! pin the two against each other. Constitutional amendment,
//! migration/succession, dissolution, and network enrollment retain their
//! named owner families and are intentionally absent.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::system_activation::{
    jcs_hash, namespace, required_string, UnverifiedCommittedSystemLifecycleStep,
};

/// JCS domain for the semantic lifecycle-state root.
const LIFECYCLE_STATE_HASH_PROFILE: &str =
    "ioi.autonomous-system-lifecycle-state-jcs-sha256.v1";
/// JCS domain for the protected-transition operation commitment.
const PROTECTED_OPERATION_COMMITMENT_HASH_PROFILE: &str =
    "ioi.autonomous-system-protected-transition-operation-commitment-jcs-sha256.v1";
/// Wire schema of the closed protected-transition authority effect.
const PROTECTED_AUTHORITY_EFFECT_SCHEMA: &str =
    "ioi.autonomous-system-protected-transition-authority-effect.v1";

/// Observable lifecycle statuses reachable by the generic protected ops.
///
/// `Degraded` is an observed posture only: it may be a legal predecessor but
/// no proposal may target it, so it never appears as a resulting status.
/// Succession, dissolution, and enrollment statuses belong to their named
/// owner families and are not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedLifecycleStatus {
    /// Fully operational.
    Active,
    /// Observed impaired posture; never an op target.
    Degraded,
    /// Deliberately paused; trivially resumable.
    Paused,
    /// Protected hold pending reinstatement.
    Suspended,
    /// Long-term intentional sleep.
    Dormant,
    /// Under governed recovery.
    Recovering,
    /// Isolated pending investigation or release.
    Quarantined,
    /// Withdrawn from service; evidence retained.
    Retired,
    /// Immutable end-of-life archive.
    Archived,
    /// Authority-revoked; only decommission remains.
    Revoked,
    /// Terminal: no further transition exists.
    Decommissioned,
}

impl ProtectedLifecycleStatus {
    /// Canonical status name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Suspended => "suspended",
            Self::Dormant => "dormant",
            Self::Recovering => "recovering",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
            Self::Archived => "archived",
            Self::Revoked => "revoked",
            Self::Decommissioned => "decommissioned",
        }
    }

    /// Parse a canonical status name.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "active" => Self::Active,
            "degraded" => Self::Degraded,
            "paused" => Self::Paused,
            "suspended" => Self::Suspended,
            "dormant" => Self::Dormant,
            "recovering" => Self::Recovering,
            "quarantined" => Self::Quarantined,
            "retired" => Self::Retired,
            "archived" => Self::Archived,
            "revoked" => Self::Revoked,
            "decommissioned" => Self::Decommissioned,
            _ => return None,
        })
    }
}

/// Declared reversibility class of a protected transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionIrreversibility {
    /// A declared inverse op exists.
    Reversible,
    /// No inverse op; later arcs may still continue end-of-life.
    OneWay,
    /// No further transition of any kind.
    Terminal,
}

impl TransitionIrreversibility {
    /// Canonical name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::OneWay => "one_way",
            Self::Terminal => "terminal",
        }
    }
}

/// The fourteen generic protected operational transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedTransitionOp {
    /// `active | degraded -> paused`.
    Pause,
    /// `paused -> active`.
    Resume,
    /// `active | degraded | paused -> suspended`.
    Suspend,
    /// `suspended -> active`.
    Reinstate,
    /// `active | paused -> dormant`.
    EnterDormancy,
    /// `dormant -> active`.
    Wake,
    /// `degraded | suspended | quarantined -> recovering`.
    BeginRecovery,
    /// `recovering -> active`.
    CompleteRecovery,
    /// `active | degraded | paused | recovering -> quarantined`.
    Quarantine,
    /// `quarantined -> active`.
    ReleaseQuarantine,
    /// `active | paused | suspended | dormant -> retired` (one-way).
    Retire,
    /// `retired -> archived` (one-way).
    Archive,
    /// any non-terminal `-> revoked` (one-way, protected).
    Revoke,
    /// `retired | archived | revoked -> decommissioned` (terminal).
    Decommission,
}

impl ProtectedTransitionOp {
    /// Every op, in canonical table order.
    pub const ALL: [Self; 14] = [
        Self::Pause,
        Self::Resume,
        Self::Suspend,
        Self::Reinstate,
        Self::EnterDormancy,
        Self::Wake,
        Self::BeginRecovery,
        Self::CompleteRecovery,
        Self::Quarantine,
        Self::ReleaseQuarantine,
        Self::Retire,
        Self::Archive,
        Self::Revoke,
        Self::Decommission,
    ];

    /// Canonical op name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Suspend => "suspend",
            Self::Reinstate => "reinstate",
            Self::EnterDormancy => "enter_dormancy",
            Self::Wake => "wake",
            Self::BeginRecovery => "begin_recovery",
            Self::CompleteRecovery => "complete_recovery",
            Self::Quarantine => "quarantine",
            Self::ReleaseQuarantine => "release_quarantine",
            Self::Retire => "retire",
            Self::Archive => "archive",
            Self::Revoke => "revoke",
            Self::Decommission => "decommission",
        }
    }

    /// Parse a canonical op name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == value)
    }

    /// Exact wallet.network operation scope. Authority for one transition
    /// kind is never authority for another.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::Pause => "scope:autonomous_system.lifecycle.pause",
            Self::Resume => "scope:autonomous_system.lifecycle.resume",
            Self::Suspend => "scope:autonomous_system.lifecycle.suspend",
            Self::Reinstate => "scope:autonomous_system.lifecycle.reinstate",
            Self::EnterDormancy => "scope:autonomous_system.lifecycle.enter_dormancy",
            Self::Wake => "scope:autonomous_system.lifecycle.wake",
            Self::BeginRecovery => "scope:autonomous_system.lifecycle.begin_recovery",
            Self::CompleteRecovery => "scope:autonomous_system.lifecycle.complete_recovery",
            Self::Quarantine => "scope:autonomous_system.lifecycle.quarantine",
            Self::ReleaseQuarantine => "scope:autonomous_system.lifecycle.release_quarantine",
            Self::Retire => "scope:autonomous_system.lifecycle.retire",
            Self::Archive => "scope:autonomous_system.lifecycle.archive",
            Self::Revoke => "scope:autonomous_system.lifecycle.revoke",
            Self::Decommission => "scope:autonomous_system.lifecycle.decommission",
        }
    }

    /// Declared reversibility class.
    pub fn irreversibility(self) -> TransitionIrreversibility {
        match self {
            Self::Retire | Self::Archive | Self::Revoke => TransitionIrreversibility::OneWay,
            Self::Decommission => TransitionIrreversibility::Terminal,
            _ => TransitionIrreversibility::Reversible,
        }
    }

    /// Legal predecessor statuses, exactly mirroring the canon table.
    pub fn legal_predecessors(self) -> &'static [ProtectedLifecycleStatus] {
        use ProtectedLifecycleStatus as S;
        match self {
            Self::Pause => &[S::Active, S::Degraded],
            Self::Resume => &[S::Paused],
            Self::Suspend => &[S::Active, S::Degraded, S::Paused],
            Self::Reinstate => &[S::Suspended],
            Self::EnterDormancy => &[S::Active, S::Paused],
            Self::Wake => &[S::Dormant],
            Self::BeginRecovery => &[S::Degraded, S::Suspended, S::Quarantined],
            Self::CompleteRecovery => &[S::Recovering],
            Self::Quarantine => &[S::Active, S::Degraded, S::Paused, S::Recovering],
            Self::ReleaseQuarantine => &[S::Quarantined],
            Self::Retire => &[S::Active, S::Paused, S::Suspended, S::Dormant],
            Self::Archive => &[S::Retired],
            Self::Revoke => &[
                S::Active,
                S::Degraded,
                S::Paused,
                S::Suspended,
                S::Dormant,
                S::Recovering,
                S::Quarantined,
                S::Retired,
                S::Archived,
            ],
            Self::Decommission => &[S::Retired, S::Archived, S::Revoked],
        }
    }

    /// Resulting status, exactly mirroring the canon table.
    pub fn resulting_status(self) -> ProtectedLifecycleStatus {
        use ProtectedLifecycleStatus as S;
        match self {
            Self::Pause => S::Paused,
            Self::Resume | Self::Reinstate | Self::Wake | Self::CompleteRecovery
            | Self::ReleaseQuarantine => S::Active,
            Self::Suspend => S::Suspended,
            Self::EnterDormancy => S::Dormant,
            Self::BeginRecovery => S::Recovering,
            Self::Quarantine => S::Quarantined,
            Self::Retire => S::Retired,
            Self::Archive => S::Archived,
            Self::Revoke => S::Revoked,
            Self::Decommission => S::Decommissioned,
        }
    }

    /// Whether this op may lawfully leave `predecessor`.
    pub fn admits_predecessor(self, predecessor: ProtectedLifecycleStatus) -> bool {
        self.legal_predecessors().contains(&predecessor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_op_round_trips_its_canonical_name_and_scope() {
        for op in ProtectedTransitionOp::ALL {
            assert_eq!(ProtectedTransitionOp::parse(op.as_str()), Some(op));
            assert_eq!(
                op.required_scope(),
                format!("scope:autonomous_system.lifecycle.{}", op.as_str()),
            );
        }
    }

    #[test]
    fn scopes_are_distinct_per_op_and_disjoint_from_bootstrap() {
        let mut scopes: Vec<&str> = ProtectedTransitionOp::ALL
            .into_iter()
            .map(ProtectedTransitionOp::required_scope)
            .collect();
        scopes.sort_unstable();
        scopes.dedup();
        assert_eq!(scopes.len(), 14, "every op owns a distinct scope");
        assert!(!scopes.contains(&"scope:autonomous_system.lifecycle.initialize"));
        assert!(!scopes.contains(&"scope:autonomous_system.lifecycle.activate"));
    }

    #[test]
    fn degraded_is_observed_only_and_never_a_result() {
        for op in ProtectedTransitionOp::ALL {
            assert_ne!(
                op.resulting_status(),
                ProtectedLifecycleStatus::Degraded,
                "{} must not target the observed degraded posture",
                op.as_str(),
            );
        }
    }

    #[test]
    fn irreversibility_classes_match_canon() {
        use ProtectedTransitionOp as O;
        use TransitionIrreversibility as I;
        for op in O::ALL {
            let expected = match op {
                O::Retire | O::Archive | O::Revoke => I::OneWay,
                O::Decommission => I::Terminal,
                _ => I::Reversible,
            };
            assert_eq!(op.irreversibility(), expected, "{}", op.as_str());
        }
    }

    #[test]
    fn terminal_states_admit_no_further_ops_except_the_canon_end_of_life_arcs() {
        use ProtectedLifecycleStatus as S;
        for op in ProtectedTransitionOp::ALL {
            assert!(
                !op.admits_predecessor(S::Decommissioned),
                "decommissioned is terminal; {} must not leave it",
                op.as_str(),
            );
        }
        // archived and revoked continue only into decommission.
        for op in ProtectedTransitionOp::ALL {
            if op != ProtectedTransitionOp::Decommission {
                assert!(
                    !op.admits_predecessor(S::Archived) || op == ProtectedTransitionOp::Revoke,
                    "archived continues only into revoke or decommission, not {}",
                    op.as_str(),
                );
                assert!(
                    !op.admits_predecessor(S::Revoked),
                    "revoked continues only into decommission, not {}",
                    op.as_str(),
                );
            }
        }
    }

    #[test]
    fn legality_matrix_matches_the_canon_table_exactly() {
        // One row per canon table line; any drift here must be a deliberate
        // canon change first.
        let canon: &[(&str, &[&str], &str)] = &[
            ("pause", &["active", "degraded"], "paused"),
            ("resume", &["paused"], "active"),
            ("suspend", &["active", "degraded", "paused"], "suspended"),
            ("reinstate", &["suspended"], "active"),
            ("enter_dormancy", &["active", "paused"], "dormant"),
            ("wake", &["dormant"], "active"),
            (
                "begin_recovery",
                &["degraded", "suspended", "quarantined"],
                "recovering",
            ),
            ("complete_recovery", &["recovering"], "active"),
            (
                "quarantine",
                &["active", "degraded", "paused", "recovering"],
                "quarantined",
            ),
            ("release_quarantine", &["quarantined"], "active"),
            (
                "retire",
                &["active", "paused", "suspended", "dormant"],
                "retired",
            ),
            ("archive", &["retired"], "archived"),
            (
                "revoke",
                &[
                    "active",
                    "degraded",
                    "paused",
                    "suspended",
                    "dormant",
                    "recovering",
                    "quarantined",
                    "retired",
                    "archived",
                ],
                "revoked",
            ),
            ("decommission", &["retired", "archived", "revoked"], "decommissioned"),
        ];
        assert_eq!(canon.len(), ProtectedTransitionOp::ALL.len());
        for (name, predecessors, result) in canon {
            let op = ProtectedTransitionOp::parse(name).expect(name);
            let actual: Vec<&str> = op
                .legal_predecessors()
                .iter()
                .map(|status| status.as_str())
                .collect();
            assert_eq!(&actual, predecessors, "{name} predecessors");
            assert_eq!(op.resulting_status().as_str(), *result, "{name} result");
        }
    }
}

/// Server-derived plan for one generic protected transition, produced before
/// wallet authorization. Mirrors `CompiledSystemLifecyclePlan` for the
/// bootstrap family; nothing here grants authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledProtectedTransitionPlan {
    /// The protected op.
    pub op: ProtectedTransitionOp,
    /// Committed sequence (predecessor sequence plus one; always >= 3).
    pub sequence: u64,
    /// Validated predecessor status the op lawfully leaves.
    pub predecessor_status: ProtectedLifecycleStatus,
    /// Explicitly unverified predecessor step artifacts (sequence n-1).
    pub previous_step: UnverifiedCommittedSystemLifecycleStep,
    /// Semantic resulting lifecycle-state projection (downstream slots empty).
    pub semantic_state: Value,
    /// Exact resulting lifecycle-state root.
    pub resulting_state_root: String,
    /// Closed server-derived authority effect.
    pub authority_effect: Value,
}

fn required_effect_string<'a>(effect: &'a Value, name: &str) -> Result<&'a str, String> {
    effect
        .get(name)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("activation identity effect lacks {name}"))
}

/// Validate the committed sequence-two activation effect as the identity
/// carrier for a live System and refuse anything that is not exactly the
/// admitted live posture.
fn validate_activation_identity(effect: &Value) -> Result<(), String> {
    if required_effect_string(effect, "schema_version")?
        != "ioi.autonomous-system-lifecycle-authority-effect.v1"
    {
        return Err("identity effect is not the committed lifecycle authority effect".to_owned());
    }
    if required_effect_string(effect, "operation")? != "activate"
        || effect.get("sequence").and_then(Value::as_u64) != Some(2)
        || effect.get("live_chain_created").and_then(Value::as_bool) != Some(true)
    {
        return Err("identity effect is not the committed sequence-two activation".to_owned());
    }
    for claim in [
        "node_membership_created",
        "runtime_effect_admitted",
        "network_effect_admitted",
    ] {
        if effect.get(claim).and_then(Value::as_bool) != Some(false) {
            return Err(format!("identity effect overclaims {claim}"));
        }
    }
    Ok(())
}

/// Read the predecessor step's registered state envelope: the sequence-two
/// activation state or a prior protected lifecycle state. Returns the state
/// ref, sequence, and status; the bootstrap statuses `draft`/`initialized`
/// refuse because only activation may leave them.
fn predecessor_state_facts(
    state: &Value,
) -> Result<(String, u64, ProtectedLifecycleStatus), String> {
    let (ref_key, is_activation) = if state.get("activation_state_ref").is_some() {
        ("activation_state_ref", true)
    } else if state.get("lifecycle_state_ref").is_some() {
        ("lifecycle_state_ref", false)
    } else {
        return Err("predecessor state carries no canonical state ref".to_owned());
    };
    let state_ref = required_string(state, &format!("/{ref_key}"))?.to_owned();
    let sequence = state
        .get("sequence")
        .and_then(Value::as_u64)
        .ok_or("predecessor state lacks a canonical sequence")?;
    if is_activation && sequence != 2 {
        return Err("activation predecessor state must be sequence two".to_owned());
    }
    if !is_activation && sequence < 3 {
        return Err("protected predecessor state must be sequence three or later".to_owned());
    }
    let status_text = required_string(state, "/status")?;
    let status = ProtectedLifecycleStatus::parse(status_text)
        .ok_or_else(|| format!("predecessor status {status_text} is outside the generic family"))?;
    Ok((state_ref, sequence, status))
}

/// Compile one generic protected transition over the live chain. The caller
/// supplies the committed sequence-two activation effect as the identity
/// carrier, the exact predecessor step (activation or a prior protected
/// step), and the exact predecessor chain head root; everything else is
/// derived server-side and nothing is trusted from the caller.
pub fn compile_protected_transition_plan(
    op: ProtectedTransitionOp,
    activation_effect: &Value,
    previous_step: &UnverifiedCommittedSystemLifecycleStep,
    chain_head_root: &str,
) -> Result<CompiledProtectedTransitionPlan, String> {
    validate_activation_identity(activation_effect)?;
    if chain_head_root.strip_prefix("sha256:").map(str::len) != Some(64) {
        return Err("predecessor chain head root is not a canonical hash".to_owned());
    }
    let system_id = required_effect_string(activation_effect, "system_id")?;
    namespace(system_id)?;
    let (predecessor_state_ref, predecessor_sequence, predecessor_status) =
        predecessor_state_facts(&previous_step.state)?;
    if required_string(&previous_step.state, "/system_id")? != system_id {
        return Err("predecessor state detaches from the identity System".to_owned());
    }
    if !op.admits_predecessor(predecessor_status) {
        return Err(format!(
            "{} cannot lawfully leave {}",
            op.as_str(),
            predecessor_status.as_str(),
        ));
    }
    let sequence = predecessor_sequence
        .checked_add(1)
        .filter(|next| *next >= 3)
        .ok_or("resulting sequence is not three or later")?;
    let active_profile_set_ref =
        required_effect_string(activation_effect, "active_profile_set_ref")?;
    let active_profile_set_root =
        required_effect_string(activation_effect, "active_profile_set_root")?;
    let chain_ref = required_effect_string(activation_effect, "chain_ref")?;
    let resulting_status = op.resulting_status();

    let lifecycle_state_ref = format!(
        "system-lifecycle-state://{}/sequence/{}",
        namespace(system_id)?,
        sequence,
    );
    // Flat JCS material with the domain inline, mirroring the activation
    // state so the portable invariant can recompute the root field-for-field.
    let state_material = json!({
        "domain": LIFECYCLE_STATE_HASH_PROFILE,
        "lifecycle_state_ref": lifecycle_state_ref,
        "system_id": system_id,
        "sequence": sequence,
        "status": resulting_status.as_str(),
        "predecessor_state_root": previous_step.state_root,
        "active_profile_set_ref": active_profile_set_ref,
        "active_profile_set_root": active_profile_set_root,
    });
    let resulting_state_root = jcs_hash(&state_material)?;
    let semantic_state = json!({
        "schema_version": "ioi.autonomous-system-lifecycle-state.v1",
        "lifecycle_state_ref": lifecycle_state_ref,
        "lifecycle_state_root": resulting_state_root,
        "system_id": system_id,
        "sequence": sequence,
        "status": resulting_status.as_str(),
        "predecessor_state_root": previous_step.state_root,
        "transition_ref": Value::Null,
        "transition_root": Value::Null,
        "transition_receipt_ref": Value::Null,
        "transition_receipt_root": Value::Null,
        "active_profile_set_ref": active_profile_set_ref,
        "active_profile_set_root": active_profile_set_root,
        "chain_ref": chain_ref,
        "created_at": Value::Null,
    });

    let mut effect = json!({
        "schema_version": PROTECTED_AUTHORITY_EFFECT_SCHEMA,
        "op": op.as_str(),
        "required_scope": op.required_scope(),
        "sequence": sequence,
        "irreversibility": op.irreversibility().as_str(),
        "system_id": system_id,
        "genesis_ref": required_effect_string(activation_effect, "genesis_ref")?,
        "home_domain_ref": required_effect_string(activation_effect, "home_domain_ref")?,
        "home_domain_commitment":
            required_effect_string(activation_effect, "home_domain_commitment")?,
        "home_domain_binding_ref":
            required_effect_string(activation_effect, "home_domain_binding_ref")?,
        "home_domain_binding_root":
            required_effect_string(activation_effect, "home_domain_binding_root")?,
        "policy_root": required_effect_string(activation_effect, "policy_root")?,
        "module_registry_root":
            required_effect_string(activation_effect, "module_registry_root")?,
        "upgrade_policy_ref": required_effect_string(activation_effect, "upgrade_policy_ref")?,
        "deployment_profile_ref":
            required_effect_string(activation_effect, "deployment_profile_ref")?,
        "deployment_profile_root":
            required_effect_string(activation_effect, "deployment_profile_root")?,
        "predecessor_status": predecessor_status.as_str(),
        "predecessor_state_ref": predecessor_state_ref,
        "predecessor_state_root": previous_step.state_root,
        "predecessor_proposal_root": previous_step.proposal_root,
        "predecessor_decision_root": previous_step.decision_root,
        "predecessor_transition_root": previous_step.transition_root,
        "predecessor_receipt_root": previous_step.receipt_root,
        "predecessor_chain_head_root": chain_head_root,
        "resulting_status": resulting_status.as_str(),
        "resulting_state_ref": semantic_state["lifecycle_state_ref"],
        "resulting_state_root": resulting_state_root,
        "active_profile_set_ref": active_profile_set_ref,
        "active_profile_set_root": active_profile_set_root,
        "chain_ref": chain_ref,
        "live_chain_created": false,
        "node_membership_created": false,
        "runtime_effect_admitted": false,
        "network_effect_admitted": false,
        "constitution_changed": false,
        "profile_set_changed": false,
        "operation_commitment": Value::Null,
    });
    effect["operation_commitment"] =
        Value::String(protected_operation_commitment(&effect)?);

    Ok(CompiledProtectedTransitionPlan {
        op,
        sequence,
        predecessor_status,
        previous_step: previous_step.clone(),
        semantic_state,
        resulting_state_root,
        authority_effect: effect,
    })
}

fn protected_operation_commitment(effect: &Value) -> Result<String, String> {
    let field = |name: &str| {
        effect
            .get(name)
            .cloned()
            .ok_or_else(|| format!("protected authority effect lacks {name}"))
    };
    jcs_hash(&json!({
        "domain": PROTECTED_OPERATION_COMMITMENT_HASH_PROFILE,
        "op": field("op")?,
        "required_scope": field("required_scope")?,
        "sequence": field("sequence")?,
        "irreversibility": field("irreversibility")?,
        "system_id": field("system_id")?,
        "genesis_ref": field("genesis_ref")?,
        "home_domain_ref": field("home_domain_ref")?,
        "home_domain_commitment": field("home_domain_commitment")?,
        "policy_root": field("policy_root")?,
        "module_registry_root": field("module_registry_root")?,
        "predecessor_status": field("predecessor_status")?,
        "predecessor_state_root": field("predecessor_state_root")?,
        "predecessor_chain_head_root": field("predecessor_chain_head_root")?,
        "resulting_status": field("resulting_status")?,
        "resulting_state_ref": field("resulting_state_ref")?,
        "resulting_state_root": field("resulting_state_root")?,
        "active_profile_set_ref": field("active_profile_set_ref")?,
        "active_profile_set_root": field("active_profile_set_root")?,
        "chain_ref": field("chain_ref")?,
    }))
}

#[cfg(test)]
mod compile_tests {
    use super::*;

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    fn activation_effect() -> Value {
        json!({
            "schema_version": "ioi.autonomous-system-lifecycle-authority-effect.v1",
            "operation": "activate",
            "sequence": 2,
            "system_id": "system://fixture/alpha",
            "genesis_ref": "genesis://fixture/alpha",
            "home_domain_ref": "home-domain://fixture/alpha",
            "home_domain_commitment": h(0x11),
            "home_domain_binding_ref": "system-home-domain-binding://fixture/alpha",
            "home_domain_binding_root": h(0x12),
            "policy_root": h(0x13),
            "module_registry_root": h(0x14),
            "upgrade_policy_ref": "policy://fixture/upgrade",
            "deployment_profile_ref": "deployment-profile://fixture/alpha",
            "deployment_profile_root": h(0x15),
            "active_profile_set_ref": "active-profile-set://fixture/alpha",
            "active_profile_set_root": h(0x16),
            "chain_ref": "autonomous-system-chain://fixture/alpha",
            "live_chain_created": true,
            "node_membership_created": false,
            "runtime_effect_admitted": false,
            "network_effect_admitted": false,
        })
    }

    fn step(sequence: u64, status: &str) -> UnverifiedCommittedSystemLifecycleStep {
        let state = if sequence == 2 {
            json!({
                "activation_state_ref": "system-activation-state://fixture/alpha/2",
                "system_id": "system://fixture/alpha",
                "sequence": 2,
                "status": status,
            })
        } else {
            json!({
                "lifecycle_state_ref":
                    format!("system-lifecycle-state://fixture/alpha/{sequence}"),
                "system_id": "system://fixture/alpha",
                "sequence": sequence,
                "status": status,
            })
        };
        UnverifiedCommittedSystemLifecycleStep {
            proposal: json!({}),
            decision: json!({}),
            state,
            transition: json!({}),
            receipt: json!({}),
            state_root: h(0x21),
            proposal_root: h(0x22),
            decision_root: h(0x23),
            transition_root: h(0x24),
            receipt_root: h(0x25),
        }
    }

    #[test]
    fn every_legal_matrix_row_compiles_and_every_illegal_row_refuses() {
        use ProtectedLifecycleStatus as S;
        let all = [
            S::Active, S::Degraded, S::Paused, S::Suspended, S::Dormant,
            S::Recovering, S::Quarantined, S::Retired, S::Archived,
            S::Revoked, S::Decommissioned,
        ];
        for op in ProtectedTransitionOp::ALL {
            for predecessor in all {
                let outcome = compile_protected_transition_plan(
                    op,
                    &activation_effect(),
                    &step(7, predecessor.as_str()),
                    &h(0x31),
                );
                if op.admits_predecessor(predecessor) {
                    let plan = outcome.unwrap_or_else(|error| {
                        panic!("{} over {} refused: {error}", op.as_str(), predecessor.as_str())
                    });
                    assert_eq!(plan.sequence, 8);
                    assert_eq!(
                        plan.authority_effect["resulting_status"],
                        op.resulting_status().as_str(),
                    );
                    assert_eq!(
                        plan.authority_effect["required_scope"],
                        op.required_scope(),
                    );
                    assert_eq!(
                        plan.authority_effect["irreversibility"],
                        op.irreversibility().as_str(),
                    );
                } else {
                    let error = outcome.expect_err("illegal row must refuse");
                    assert!(
                        error.contains("cannot lawfully leave"),
                        "{}: {error}",
                        op.as_str(),
                    );
                }
            }
        }
    }

    #[test]
    fn activation_predecessor_compiles_at_sequence_three() {
        let plan = compile_protected_transition_plan(
            ProtectedTransitionOp::Pause,
            &activation_effect(),
            &step(2, "active"),
            &h(0x31),
        )
        .expect("pause over the activation step");
        assert_eq!(plan.sequence, 3);
        assert_eq!(
            plan.semantic_state["predecessor_state_root"],
            h(0x21),
        );
    }

    #[test]
    fn bootstrap_and_reserved_statuses_refuse() {
        for status in ["initialized", "draft", "succession_pending", "dissolving"] {
            let error = compile_protected_transition_plan(
                ProtectedTransitionOp::Pause,
                &activation_effect(),
                &step(2, status),
                &h(0x31),
            )
            .expect_err(status);
            assert!(
                error.contains("outside the generic family"),
                "{status}: {error}",
            );
        }
    }

    #[test]
    fn identity_detachment_and_overclaims_refuse() {
        let mut foreign = step(4, "active");
        foreign.state["system_id"] = json!("system://fixture/beta");
        assert!(compile_protected_transition_plan(
            ProtectedTransitionOp::Pause,
            &activation_effect(),
            &foreign,
            &h(0x31),
        )
        .expect_err("foreign system")
        .contains("detaches"));

        let mut not_live = activation_effect();
        not_live["live_chain_created"] = json!(false);
        assert!(compile_protected_transition_plan(
            ProtectedTransitionOp::Pause,
            &not_live,
            &step(4, "active"),
            &h(0x31),
        )
        .is_err());

        let mut overclaimed = activation_effect();
        overclaimed["runtime_effect_admitted"] = json!(true);
        assert!(compile_protected_transition_plan(
            ProtectedTransitionOp::Pause,
            &overclaimed,
            &step(4, "active"),
            &h(0x31),
        )
        .expect_err("overclaim")
        .contains("overclaims"));
    }

    #[test]
    fn commitments_are_deterministic_and_tamper_sensitive() {
        let build = |chain: &str| {
            compile_protected_transition_plan(
                ProtectedTransitionOp::Suspend,
                &activation_effect(),
                &step(5, "paused"),
                chain,
            )
            .expect("suspend over paused")
        };
        let first = build(&h(0x31));
        let second = build(&h(0x31));
        assert_eq!(first, second, "identical inputs produce identical plans");
        let moved = build(&h(0x32));
        assert_ne!(
            first.authority_effect["operation_commitment"],
            moved.authority_effect["operation_commitment"],
            "chain head movement must move the commitment",
        );
        assert_eq!(
            first.authority_effect["operation_commitment"],
            Value::String(
                protected_operation_commitment(&first.authority_effect).unwrap()
            ),
            "commitment recomputes from the closed effect",
        );
    }

    #[test]
    fn every_negative_claim_stays_false_in_the_derived_effect() {
        let plan = compile_protected_transition_plan(
            ProtectedTransitionOp::Retire,
            &activation_effect(),
            &step(6, "dormant"),
            &h(0x31),
        )
        .expect("retire over dormant");
        for claim in [
            "live_chain_created",
            "node_membership_created",
            "runtime_effect_admitted",
            "network_effect_admitted",
            "constitution_changed",
            "profile_set_changed",
        ] {
            assert_eq!(
                plan.authority_effect[claim],
                json!(false),
                "{claim} must stay false",
            );
        }
    }
}
