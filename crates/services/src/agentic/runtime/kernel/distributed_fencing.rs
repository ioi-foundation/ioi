//! Per-System writer continuity and consequential-effect fencing.
//!
//! `agentgres::mux::MuxEngine::current_epoch` is a storage-writer epoch. It
//! deliberately does not appear here: this module owns the higher-level,
//! per-autonomous-System epoch that binds membership, authority, state, read
//! posture, and resource effects. A storage epoch can support durability for a
//! transition record; it cannot authorize a System effect.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const WRITER_TRANSITION_SCHEMA: &str = "ioi.autonomous-system-writer-epoch-transition.v1";
pub const ACTIVE_FENCE_SCHEMA: &str = "ioi.autonomous-system-active-fence.v1";
pub const EFFECT_FENCE_CONTEXT_SCHEMA: &str = "ioi.consequential-effect-fence-context.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadConsistency {
    CachedProjection,
    ProjectionConsistent,
    SnapshotConsistent,
    StateRootConsistent,
    LinearizedDomain,
    SerializableDomain,
}

impl ReadConsistency {
    fn rank(self) -> u8 {
        match self {
            Self::CachedProjection => 0,
            Self::ProjectionConsistent => 1,
            Self::SnapshotConsistent => 2,
            Self::StateRootConsistent => 3,
            Self::LinearizedDomain => 4,
            Self::SerializableDomain => 5,
        }
    }

    pub fn satisfies(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterMembership {
    pub node_id: String,
    pub membership_epoch: u64,
    pub membership_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionTimingEvidence {
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
    pub effects_not_before_ms: i64,
    pub displaced_writer_leases_expire_at_ms: i64,
    pub revocation_propagation_complete_at_ms: i64,
    pub max_clock_uncertainty_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityCasProof {
    pub mechanism: String,
    pub substrate_ref: String,
    pub expected_head: Option<String>,
    pub resulting_head: String,
    pub proof_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequentialResourceFence {
    pub resource_id: String,
    pub allowed_effects: Vec<String>,
    pub minimum_read_consistency: ReadConsistency,
    pub read_watermark: String,
}

/// Immutable, append-only transition admitted by a durable compare-and-swap.
/// `transition_hash` commits to every field except itself and
/// `continuity_cas.resulting_head`; the latter must equal that commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutonomousSystemWriterEpochTransition {
    pub schema_version: String,
    #[serde(rename = "writer_epoch_transition_id")]
    pub transition_id: String,
    #[serde(rename = "writer_epoch_transition_hash")]
    pub transition_hash: String,
    pub transition_kind: String,
    pub system_id: String,
    pub deployment_profile_ref: String,
    pub deployment_profile_root: String,
    pub failover_profile_ref: String,
    pub failover_profile_root: String,
    pub ordering_profile_ref: String,
    pub ordering_profile_root: String,
    pub predecessor_transition_ref: Option<String>,
    pub predecessor_transition_hash: Option<String>,
    pub prior_writer_epoch: u64,
    pub new_writer_epoch: u64,
    pub prior_writer: Option<WriterMembership>,
    pub successor_writer: WriterMembership,
    pub verified_state_root: String,
    pub catchup_receipt_ref: String,
    pub state_root_verification_ref: String,
    pub authority_grant_refs: Vec<String>,
    pub authority_revocation_snapshot_ref: String,
    pub authority_revocation_epoch: u64,
    pub displaced_writer_fence_receipt_refs: Vec<String>,
    pub timing_evidence: TransitionTimingEvidence,
    pub continuity_cas: ContinuityCasProof,
    pub resource_fences: Vec<ConsequentialResourceFence>,
    pub lost_suffix_record_ref: Option<String>,
    pub committed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSystemFence {
    pub schema_version: String,
    pub system_id: String,
    pub transition_id: String,
    pub transition_hash: String,
    pub writer_epoch: u64,
    pub deployment_profile_ref: String,
    pub deployment_profile_root: String,
    pub failover_profile_ref: String,
    pub failover_profile_root: String,
    pub ordering_profile_ref: String,
    pub ordering_profile_root: String,
    pub writer: WriterMembership,
    pub verified_state_root: String,
    pub authority_grant_refs: Vec<String>,
    pub authority_revocation_snapshot_ref: String,
    pub authority_revocation_epoch: u64,
    pub effects_not_before_ms: i64,
    pub timing_evidence_expires_at_ms: i64,
    pub resource_fences: Vec<ConsequentialResourceFence>,
}

/// Generated, embedded evidence evaluated immediately before an effect. It is
/// evidence presented to a PEP, never a freestanding authority grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequentialEffectFenceContext {
    pub schema_version: String,
    pub system_id: String,
    pub executing_node_id: String,
    pub resource_id: String,
    pub effect_kind: String,
    pub exact_payload_hash: String,
    pub deployment_profile_root: String,
    pub node_membership_epoch: u64,
    pub node_membership_root: String,
    #[serde(rename = "writer_epoch_transition_ref")]
    pub writer_transition_ref: String,
    #[serde(rename = "writer_epoch_transition_hash")]
    pub writer_transition_hash: String,
    pub writer_epoch: u64,
    pub writer_lease_expires_at_ms: i64,
    pub authority_grant_ref: String,
    pub authority_revocation_snapshot_ref: String,
    pub authority_revocation_epoch: u64,
    pub read_consistency: ReadConsistency,
    pub read_watermark: String,
    pub read_state_root: String,
    pub idempotency_key: String,
    pub evaluated_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Owner-derived facts supplied by a concrete PEP. None of these values may
/// be defaulted from or omitted by the caller's fence context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectOwnerBinding<'a> {
    pub system_id: &'a str,
    pub executing_node_id: &'a str,
    pub resource_id: &'a str,
    pub effect_kind: &'a str,
    pub exact_payload_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceDenial {
    pub code: &'static str,
    pub message: String,
}

impl FenceDenial {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

pub fn sha256_value(value: &Value) -> Result<String, FenceDenial> {
    let encoded = serde_jcs::to_vec(value).map_err(|error| {
        FenceDenial::new(
            "system_fence_canonicalization_failed",
            format!("value could not be canonically encoded: {error}"),
        )
    })?;
    let mut hash = Sha256::new();
    hash.update(encoded);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

pub fn transition_content_hash(
    transition: &AutonomousSystemWriterEpochTransition,
) -> Result<String, FenceDenial> {
    let mut value = serde_json::to_value(transition).map_err(|error| {
        FenceDenial::new(
            "system_transition_encoding_failed",
            format!("writer transition could not be encoded: {error}"),
        )
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        FenceDenial::new(
            "system_transition_encoding_failed",
            "writer transition did not encode as an object",
        )
    })?;
    object.remove("writer_epoch_transition_hash");
    object
        .get_mut("continuity_cas")
        .and_then(Value::as_object_mut)
        .map(|cas| cas.remove("resulting_head"));
    sha256_value(&value)
}

fn validate_nonempty_transition_fields(
    transition: &AutonomousSystemWriterEpochTransition,
) -> Result<(), FenceDenial> {
    let required = [
        ("transition_id", transition.transition_id.as_str()),
        ("system_id", transition.system_id.as_str()),
        (
            "deployment_profile_ref",
            transition.deployment_profile_ref.as_str(),
        ),
        (
            "deployment_profile_root",
            transition.deployment_profile_root.as_str(),
        ),
        (
            "failover_profile_ref",
            transition.failover_profile_ref.as_str(),
        ),
        (
            "failover_profile_root",
            transition.failover_profile_root.as_str(),
        ),
        (
            "ordering_profile_ref",
            transition.ordering_profile_ref.as_str(),
        ),
        (
            "ordering_profile_root",
            transition.ordering_profile_root.as_str(),
        ),
        (
            "successor_writer.node_id",
            transition.successor_writer.node_id.as_str(),
        ),
        (
            "successor_writer.membership_root",
            transition.successor_writer.membership_root.as_str(),
        ),
        (
            "verified_state_root",
            transition.verified_state_root.as_str(),
        ),
        (
            "catchup_receipt_ref",
            transition.catchup_receipt_ref.as_str(),
        ),
        (
            "state_root_verification_ref",
            transition.state_root_verification_ref.as_str(),
        ),
        (
            "authority_revocation_snapshot_ref",
            transition.authority_revocation_snapshot_ref.as_str(),
        ),
        (
            "continuity_cas.mechanism",
            transition.continuity_cas.mechanism.as_str(),
        ),
        (
            "continuity_cas.substrate_ref",
            transition.continuity_cas.substrate_ref.as_str(),
        ),
        (
            "continuity_cas.proof_ref",
            transition.continuity_cas.proof_ref.as_str(),
        ),
    ];
    if let Some((field, _)) = required.into_iter().find(|(_, value)| !nonempty(value)) {
        return Err(FenceDenial::new(
            "system_transition_required_field_missing",
            format!("writer transition field {field} is empty"),
        ));
    }
    Ok(())
}

/// Validate a transition against the currently durable active projection and
/// return the exact next projection. Persistence/CAS remains the caller's job.
pub fn admit_writer_epoch_transition(
    current: Option<&ActiveSystemFence>,
    transition: &AutonomousSystemWriterEpochTransition,
    now_ms: i64,
) -> Result<ActiveSystemFence, FenceDenial> {
    if transition.schema_version != WRITER_TRANSITION_SCHEMA {
        return Err(FenceDenial::new(
            "system_transition_schema_invalid",
            "writer transition schema version is missing or unsupported",
        ));
    }
    validate_nonempty_transition_fields(transition)?;
    let computed_hash = transition_content_hash(transition)?;
    if transition.transition_hash != computed_hash
        || transition.continuity_cas.resulting_head != computed_hash
    {
        return Err(FenceDenial::new(
            "system_transition_hash_mismatch",
            "transition hash and continuity-CAS resulting head must equal the exact content commitment",
        ));
    }
    if transition.timing_evidence.observed_at_ms > transition.committed_at_ms
        || transition.committed_at_ms > transition.timing_evidence.expires_at_ms
        || transition.committed_at_ms > now_ms
        || transition.timing_evidence.observed_at_ms > now_ms
        || transition.timing_evidence.expires_at_ms < now_ms
        || transition.timing_evidence.effects_not_before_ms
            > transition.timing_evidence.expires_at_ms
    {
        return Err(FenceDenial::new(
            "system_transition_timing_invalid",
            "transition timing evidence must be observed before commit, remain fresh through commit/effect activation, and not be future-dated or expired",
        ));
    }
    let uncertainty =
        i64::try_from(transition.timing_evidence.max_clock_uncertainty_ms).unwrap_or(i64::MAX);
    let safe_after = transition
        .timing_evidence
        .displaced_writer_leases_expire_at_ms
        .max(
            transition
                .timing_evidence
                .revocation_propagation_complete_at_ms,
        )
        .saturating_add(uncertainty);
    if transition.timing_evidence.effects_not_before_ms < safe_after {
        return Err(FenceDenial::new(
            "system_transition_waitout_insufficient",
            "effects-not-before does not cover displaced leases, revocation propagation, and clock uncertainty",
        ));
    }
    let mut authority_grants = BTreeSet::new();
    if transition.authority_grant_refs.is_empty()
        || transition
            .authority_grant_refs
            .iter()
            .any(|grant| !nonempty(grant) || !authority_grants.insert(grant.as_str()))
    {
        return Err(FenceDenial::new(
            "system_transition_authority_invalid",
            "writer transition requires a nonempty unique set of exact authority grants",
        ));
    }

    match current {
        None => {
            if transition.transition_kind != "genesis"
                || transition.prior_writer_epoch != 0
                || transition.new_writer_epoch != 1
                || transition.predecessor_transition_ref.is_some()
                || transition.predecessor_transition_hash.is_some()
                || transition.prior_writer.is_some()
                || transition.continuity_cas.expected_head.is_some()
            {
                return Err(FenceDenial::new(
                    "system_transition_genesis_invalid",
                    "first writer transition must be genesis epoch 1 with no predecessor or expected CAS head",
                ));
            }
        }
        Some(active) => {
            let exact_profile_match = transition.system_id == active.system_id
                && transition.deployment_profile_ref == active.deployment_profile_ref
                && transition.deployment_profile_root == active.deployment_profile_root
                && transition.failover_profile_ref == active.failover_profile_ref
                && transition.failover_profile_root == active.failover_profile_root
                && transition.ordering_profile_ref == active.ordering_profile_ref
                && transition.ordering_profile_root == active.ordering_profile_root;
            if !exact_profile_match {
                return Err(FenceDenial::new(
                    "system_transition_profile_mismatch",
                    "transition does not bind the active System and exact deployment/failover/ordering profile roots",
                ));
            }
            if transition.predecessor_transition_ref.as_deref()
                != Some(active.transition_id.as_str())
                || transition.predecessor_transition_hash.as_deref()
                    != Some(active.transition_hash.as_str())
                || transition.continuity_cas.expected_head.as_deref()
                    != Some(active.transition_hash.as_str())
                || transition.prior_writer_epoch != active.writer_epoch
                || transition.new_writer_epoch != active.writer_epoch.saturating_add(1)
                || transition.prior_writer.as_ref() != Some(&active.writer)
            {
                return Err(FenceDenial::new(
                    "system_transition_stale_cas",
                    "transition predecessor, writer epoch, or expected continuity-CAS head is stale",
                ));
            }
            if transition.displaced_writer_fence_receipt_refs.is_empty() {
                return Err(FenceDenial::new(
                    "system_transition_displaced_writer_unfenced",
                    "non-genesis transition requires durable displaced-writer fence evidence",
                ));
            }
        }
    }

    if transition.successor_writer.membership_epoch == 0 {
        return Err(FenceDenial::new(
            "system_transition_membership_invalid",
            "successor membership epoch must be nonzero",
        ));
    }
    if transition.resource_fences.is_empty() {
        return Err(FenceDenial::new(
            "system_transition_resource_fences_missing",
            "writer transition must enumerate at least one consequential resource fence",
        ));
    }
    let mut resources = BTreeSet::new();
    for resource in &transition.resource_fences {
        if !nonempty(&resource.resource_id)
            || !nonempty(&resource.read_watermark)
            || resource.allowed_effects.is_empty()
            || resource
                .allowed_effects
                .iter()
                .any(|effect| !nonempty(effect))
            || !resources.insert(resource.resource_id.as_str())
        {
            return Err(FenceDenial::new(
                "system_transition_resource_fence_invalid",
                "resource fences require unique identities, allowed effects, and an exact read watermark",
            ));
        }
    }

    Ok(ActiveSystemFence {
        schema_version: ACTIVE_FENCE_SCHEMA.to_string(),
        system_id: transition.system_id.clone(),
        transition_id: transition.transition_id.clone(),
        transition_hash: transition.transition_hash.clone(),
        writer_epoch: transition.new_writer_epoch,
        deployment_profile_ref: transition.deployment_profile_ref.clone(),
        deployment_profile_root: transition.deployment_profile_root.clone(),
        failover_profile_ref: transition.failover_profile_ref.clone(),
        failover_profile_root: transition.failover_profile_root.clone(),
        ordering_profile_ref: transition.ordering_profile_ref.clone(),
        ordering_profile_root: transition.ordering_profile_root.clone(),
        writer: transition.successor_writer.clone(),
        verified_state_root: transition.verified_state_root.clone(),
        authority_grant_refs: transition.authority_grant_refs.clone(),
        authority_revocation_snapshot_ref: transition.authority_revocation_snapshot_ref.clone(),
        authority_revocation_epoch: transition.authority_revocation_epoch,
        effects_not_before_ms: transition.timing_evidence.effects_not_before_ms,
        timing_evidence_expires_at_ms: transition.timing_evidence.expires_at_ms,
        resource_fences: transition.resource_fences.clone(),
    })
}

/// Fail-closed validation immediately before a System-scoped consequential
/// effect. The owner binding wins over every caller-presented identity.
pub fn admit_consequential_effect(
    active: &ActiveSystemFence,
    context: &ConsequentialEffectFenceContext,
    owner: &EffectOwnerBinding<'_>,
    now_ms: i64,
) -> Result<(), FenceDenial> {
    if active.schema_version != ACTIVE_FENCE_SCHEMA
        || context.schema_version != EFFECT_FENCE_CONTEXT_SCHEMA
    {
        return Err(FenceDenial::new(
            "system_effect_fence_schema_invalid",
            "active fence or embedded effect context schema is unsupported",
        ));
    }
    if context.system_id != owner.system_id
        || context.executing_node_id != owner.executing_node_id
        || context.resource_id != owner.resource_id
        || context.effect_kind != owner.effect_kind
        || context.exact_payload_hash != owner.exact_payload_hash
        || active.system_id != owner.system_id
    {
        return Err(FenceDenial::new(
            "system_effect_owner_binding_mismatch",
            "effect context does not equal the System, executing node, resource, effect, and payload derived from trusted owner/runtime truth",
        ));
    }
    if active.writer.node_id != owner.executing_node_id {
        return Err(FenceDenial::new(
            "system_effect_executing_node_deposed",
            "the executing daemon node is not the active System writer",
        ));
    }
    if now_ms < active.effects_not_before_ms
        || now_ms > active.timing_evidence_expires_at_ms
        || context.evaluated_at_ms > now_ms
        || context.expires_at_ms < now_ms
        || context.expires_at_ms > active.timing_evidence_expires_at_ms
        || context.writer_lease_expires_at_ms < now_ms
        || context.writer_lease_expires_at_ms > active.timing_evidence_expires_at_ms
    {
        return Err(FenceDenial::new(
            "system_effect_timing_invalid",
            "effect is before the safe activation boundary or relies on future, expired, or overlong evidence",
        ));
    }
    if context.deployment_profile_root != active.deployment_profile_root
        || context.node_membership_epoch != active.writer.membership_epoch
        || context.node_membership_root != active.writer.membership_root
        || context.writer_transition_ref != active.transition_id
        || context.writer_transition_hash != active.transition_hash
        || context.writer_epoch != active.writer_epoch
    {
        return Err(FenceDenial::new(
            "system_effect_writer_fence_stale",
            "effect context does not bind the active deployment, membership, transition, and writer epoch",
        ));
    }
    if context.authority_revocation_snapshot_ref != active.authority_revocation_snapshot_ref
        || context.authority_revocation_epoch != active.authority_revocation_epoch
        || !active
            .authority_grant_refs
            .iter()
            .any(|grant| grant == &context.authority_grant_ref)
    {
        return Err(FenceDenial::new(
            "system_effect_authority_stale",
            "effect context authority or revocation snapshot is not active",
        ));
    }
    let resource = active
        .resource_fences
        .iter()
        .find(|resource| resource.resource_id == owner.resource_id)
        .ok_or_else(|| {
            FenceDenial::new(
                "system_effect_resource_unfenced",
                "owner-derived resource is absent from the active transition fence",
            )
        })?;
    if !resource
        .allowed_effects
        .iter()
        .any(|effect| effect == owner.effect_kind)
    {
        return Err(FenceDenial::new(
            "system_effect_kind_not_allowed",
            "owner-derived effect is not allowed by the active resource fence",
        ));
    }
    if !context
        .read_consistency
        .satisfies(resource.minimum_read_consistency)
        || context.read_watermark != resource.read_watermark
        || context.read_state_root != active.verified_state_root
    {
        return Err(FenceDenial::new(
            "system_effect_read_posture_stale",
            "effect does not bind the required read consistency, watermark, and active state root",
        ));
    }
    if !nonempty(&context.idempotency_key) {
        return Err(FenceDenial::new(
            "system_effect_idempotency_missing",
            "consequential System effect requires an idempotency key",
        ));
    }
    Ok(())
}

pub fn invoke_after_system_fence<T>(
    active: &ActiveSystemFence,
    context: &ConsequentialEffectFenceContext,
    owner: &EffectOwnerBinding<'_>,
    now_ms: i64,
    invoke: impl FnOnce() -> T,
) -> Result<T, FenceDenial> {
    admit_consequential_effect(active, context, owner, now_ms)?;
    Ok(invoke())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: i64 = 10_000;

    fn resource() -> ConsequentialResourceFence {
        ConsequentialResourceFence {
            resource_id: "agentgres://orders/order-1".into(),
            allowed_effects: vec!["agentgres.domain_mutation".into()],
            minimum_read_consistency: ReadConsistency::LinearizedDomain,
            read_watermark: "seq:41".into(),
        }
    }

    fn transition() -> AutonomousSystemWriterEpochTransition {
        let mut transition = AutonomousSystemWriterEpochTransition {
            schema_version: WRITER_TRANSITION_SCHEMA.into(),
            transition_id: "writer-transition://system-a/1".into(),
            transition_hash: String::new(),
            transition_kind: "genesis".into(),
            system_id: "system://a".into(),
            deployment_profile_ref: "deployment-profile://a/v1".into(),
            deployment_profile_root: "sha256:deployment".into(),
            failover_profile_ref: "failover-profile://a/v1".into(),
            failover_profile_root: "sha256:failover".into(),
            ordering_profile_ref: "ordering-profile://a/v1".into(),
            ordering_profile_root: "sha256:ordering".into(),
            predecessor_transition_ref: None,
            predecessor_transition_hash: None,
            prior_writer_epoch: 0,
            new_writer_epoch: 1,
            prior_writer: None,
            successor_writer: WriterMembership {
                node_id: "node://one".into(),
                membership_epoch: 7,
                membership_root: "sha256:members".into(),
            },
            verified_state_root: "sha256:state".into(),
            catchup_receipt_ref: "receipt://catchup/1".into(),
            state_root_verification_ref: "verification://root/1".into(),
            authority_grant_refs: vec!["authority-grant://one".into()],
            authority_revocation_snapshot_ref: "revocation-snapshot://9".into(),
            authority_revocation_epoch: 9,
            displaced_writer_fence_receipt_refs: vec![],
            timing_evidence: TransitionTimingEvidence {
                observed_at_ms: 9_000,
                expires_at_ms: 20_000,
                effects_not_before_ms: 9_500,
                displaced_writer_leases_expire_at_ms: 9_000,
                revocation_propagation_complete_at_ms: 9_250,
                max_clock_uncertainty_ms: 250,
            },
            continuity_cas: ContinuityCasProof {
                mechanism: "witness_quorum_cas".into(),
                substrate_ref: "continuity://a".into(),
                expected_head: None,
                resulting_head: String::new(),
                proof_ref: "cas-proof://one".into(),
            },
            resource_fences: vec![resource()],
            lost_suffix_record_ref: None,
            committed_at_ms: 9_500,
        };
        let hash = transition_content_hash(&transition).unwrap();
        transition.transition_hash = hash.clone();
        transition.continuity_cas.resulting_head = hash;
        transition
    }

    fn context(active: &ActiveSystemFence) -> ConsequentialEffectFenceContext {
        ConsequentialEffectFenceContext {
            schema_version: EFFECT_FENCE_CONTEXT_SCHEMA.into(),
            system_id: active.system_id.clone(),
            executing_node_id: active.writer.node_id.clone(),
            resource_id: active.resource_fences[0].resource_id.clone(),
            effect_kind: "agentgres.domain_mutation".into(),
            exact_payload_hash: "sha256:payload".into(),
            deployment_profile_root: active.deployment_profile_root.clone(),
            node_membership_epoch: active.writer.membership_epoch,
            node_membership_root: active.writer.membership_root.clone(),
            writer_transition_ref: active.transition_id.clone(),
            writer_transition_hash: active.transition_hash.clone(),
            writer_epoch: active.writer_epoch,
            writer_lease_expires_at_ms: 15_000,
            authority_grant_ref: active.authority_grant_refs[0].clone(),
            authority_revocation_snapshot_ref: active.authority_revocation_snapshot_ref.clone(),
            authority_revocation_epoch: active.authority_revocation_epoch,
            read_consistency: ReadConsistency::LinearizedDomain,
            read_watermark: active.resource_fences[0].read_watermark.clone(),
            read_state_root: active.verified_state_root.clone(),
            idempotency_key: "idem-1".into(),
            evaluated_at_ms: NOW,
            expires_at_ms: 12_000,
        }
    }

    fn reseal(transition: &mut AutonomousSystemWriterEpochTransition) {
        transition.transition_hash.clear();
        transition.continuity_cas.resulting_head.clear();
        let hash = transition_content_hash(transition).unwrap();
        transition.transition_hash = hash.clone();
        transition.continuity_cas.resulting_head = hash;
    }

    fn owner<'a>(context: &'a ConsequentialEffectFenceContext) -> EffectOwnerBinding<'a> {
        EffectOwnerBinding {
            system_id: "system://a",
            executing_node_id: "node://one",
            resource_id: "agentgres://orders/order-1",
            effect_kind: "agentgres.domain_mutation",
            exact_payload_hash: &context.exact_payload_hash,
        }
    }

    #[test]
    fn genesis_transition_and_exact_effect_are_admitted() {
        let active = admit_writer_epoch_transition(None, &transition(), NOW).unwrap();
        let context = context(&active);
        let calls = AtomicUsize::new(0);
        let result = invoke_after_system_fence(&active, &context, &owner(&context), NOW, || {
            calls.fetch_add(1, Ordering::SeqCst);
            42
        })
        .unwrap();
        assert_eq!(result, 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn transition_timing_and_authority_evidence_are_ordered_and_unique() {
        let mut late_observation = transition();
        late_observation.timing_evidence.observed_at_ms =
            late_observation.committed_at_ms.saturating_add(1);
        reseal(&mut late_observation);
        assert_eq!(
            admit_writer_epoch_transition(None, &late_observation, NOW)
                .unwrap_err()
                .code,
            "system_transition_timing_invalid"
        );

        let mut duplicate_grant = transition();
        duplicate_grant
            .authority_grant_refs
            .push(duplicate_grant.authority_grant_refs[0].clone());
        reseal(&mut duplicate_grant);
        assert_eq!(
            admit_writer_epoch_transition(None, &duplicate_grant, NOW)
                .unwrap_err()
                .code,
            "system_transition_authority_invalid"
        );

        let mut empty_grant = transition();
        empty_grant.authority_grant_refs = vec![" ".into()];
        reseal(&mut empty_grant);
        assert_eq!(
            admit_writer_epoch_transition(None, &empty_grant, NOW)
                .unwrap_err()
                .code,
            "system_transition_authority_invalid"
        );
    }

    #[test]
    fn stale_cas_and_epoch_cannot_advance_projection() {
        let first = transition();
        let active = admit_writer_epoch_transition(None, &first, NOW).unwrap();
        let mut next = first.clone();
        next.transition_id = "writer-transition://system-a/2".into();
        next.transition_kind = "promotion".into();
        next.predecessor_transition_ref = Some(active.transition_id.clone());
        next.predecessor_transition_hash = Some(active.transition_hash.clone());
        next.prior_writer = Some(active.writer.clone());
        next.prior_writer_epoch = 1;
        next.new_writer_epoch = 2;
        next.continuity_cas.expected_head = Some("sha256:stale".into());
        next.displaced_writer_fence_receipt_refs = vec!["receipt://fence/one".into()];
        let hash = transition_content_hash(&next).unwrap();
        next.transition_hash = hash.clone();
        next.continuity_cas.resulting_head = hash;
        let denial = admit_writer_epoch_transition(Some(&active), &next, NOW).unwrap_err();
        assert_eq!(denial.code, "system_transition_stale_cas");
    }

    #[test]
    fn adversarial_effect_bindings_make_zero_invocations() {
        let active = admit_writer_epoch_transition(None, &transition(), NOW).unwrap();
        let base = context(&active);
        let cases: Vec<ConsequentialEffectFenceContext> = vec![
            {
                let mut value = base.clone();
                value.writer_epoch = 0;
                value
            },
            {
                let mut value = base.clone();
                value.executing_node_id = "node://deposed".into();
                value
            },
            {
                let mut value = base.clone();
                value.node_membership_root = "sha256:foreign".into();
                value
            },
            {
                let mut value = base.clone();
                value.deployment_profile_root = "sha256:foreign".into();
                value
            },
            {
                let mut value = base.clone();
                value.resource_id = "agentgres://orders/order-2".into();
                value
            },
            {
                let mut value = base.clone();
                value.effect_kind = "wallet.transfer".into();
                value
            },
            {
                let mut value = base.clone();
                value.expires_at_ms = NOW - 1;
                value
            },
            {
                let mut value = base.clone();
                value.read_consistency = ReadConsistency::CachedProjection;
                value
            },
            {
                let mut value = base.clone();
                value.read_state_root = "sha256:stale".into();
                value
            },
        ];
        let calls = AtomicUsize::new(0);
        for value in cases {
            let result = invoke_after_system_fence(&active, &value, &owner(&base), NOW, || {
                calls.fetch_add(1, Ordering::SeqCst);
            });
            assert!(result.is_err());
        }
        let mut copied = base.clone();
        copied.executing_node_id = "node://deposed".into();
        let deposed_owner = EffectOwnerBinding {
            system_id: "system://a",
            executing_node_id: "node://deposed",
            resource_id: "agentgres://orders/order-1",
            effect_kind: "agentgres.domain_mutation",
            exact_payload_hash: &copied.exact_payload_hash,
        };
        let result = invoke_after_system_fence(&active, &copied, &deposed_owner, NOW, || {
            calls.fetch_add(1, Ordering::SeqCst)
        });
        assert_eq!(
            result.unwrap_err().code,
            "system_effect_executing_node_deposed"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
