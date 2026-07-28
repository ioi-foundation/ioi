//! M2 writer-fence plane: active-writer epoch, final-invoker fence,
//! ambiguous-outcome custody, and lost-suffix reconciliation.
//!
//! This is the ONLY family that admits writer authority for a bounded System:
//! the membership plane structurally refuses `admission_writer` and defers
//! here. One immutable writer-epoch transition advances the single active
//! writer through strict compare-and-swap over the durable transition log;
//! the epoch is strictly monotonic (+1, genesis = 1) and exactly one writer
//! is active per System. The consequential-effect fence is a TOTAL evaluation:
//! for every presented context it returns an admit/refuse verdict with a named
//! refusal dimension, and every caller-authored, stale, foreign, deposed, or
//! mismatched membership/epoch/resource/grant/root/effect state reaches zero
//! selected final invokers (INV-24, INV-37, Final-Invoker Invariants). The
//! suffix of operations acknowledged under a deposed epoch but excluded from
//! the authoritative history is RETAINED as a lost-suffix record bound to
//! both epochs with per-entry custody — never silently dropped, never
//! silently replayed.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;

use super::hypervisoros_node_attestation::{
    HYPERVISOROS_NODE_CONTRACT, TEMPORAL_EVALUATION_CONTRACT, TEMPORAL_PROFILE_CONTRACT,
};
use super::system_activation::{jcs_hash, namespace, required_string};
use super::system_membership_transitions::{membership_record_root, NODE_MEMBERSHIP_CONTRACT};

/// Registered writer-epoch transition contract (the writer-authority owner).
pub const WRITER_TRANSITION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-writer-epoch-transition/v1";
/// Registered per-invocation consequential-effect fence tuple contract.
pub const FENCE_CONTEXT_CONTRACT: &str =
    "schema://ioi/foundations/consequential-effect-fence-context/v1";
/// Registered non-single-writer ordering/finality recovery contract.
pub const ORDERING_RECOVERY_CONTRACT: &str =
    "schema://ioi/foundations/ordering-finality-recovery/v1";
/// Registered lost-suffix custody record contract.
pub const LOST_SUFFIX_CONTRACT: &str = "schema://ioi/foundations/lost-suffix-record/v1";

/// Content-commitment domain of one immutable writer-epoch transition. The
/// commitment covers every field except `writer_epoch_transition_hash` and
/// `continuity_cas.resulting_head`; both excluded fields must then equal it.
pub const WRITER_TRANSITION_COMMITMENT_PROFILE: &str =
    "ioi.autonomous-system-writer-epoch-transition-commitment-jcs-sha256.v1";
/// Commitment domain of one policy-enforcement-point fence context.
pub const FENCE_COMMITMENT_PROFILE: &str =
    "ioi.consequential-effect-fence-context-commitment-jcs-sha256.v1";
/// Content root domain of one owner-declared failover profile record.
pub const FAILOVER_PROFILE_HASH_PROFILE: &str =
    "ioi.autonomous-system-failover-profile-jcs-sha256.v1";
/// Timeless content root domain of one lost-suffix record revision.
pub const LOST_SUFFIX_RECORD_HASH_PROFILE: &str = "ioi.lost-suffix-record-revision-jcs-sha256.v1";

/// Governed failover-profile declaration operation (routes-level op name).
pub const DECLARE_FAILOVER_PROFILE_OP: &str = "declare_failover_profile";
/// Owner scope of the failover-profile declaration.
pub const DECLARE_FAILOVER_PROFILE_SCOPE: &str =
    "scope:autonomous_system.writer.declare_failover_profile";
/// Governed per-entry lost-suffix resolution operation.
pub const RESOLVE_LOST_SUFFIX_OP: &str = "resolve_lost_suffix";
/// Owner scope of the lost-suffix resolution.
pub const RESOLVE_LOST_SUFFIX_SCOPE: &str = "scope:autonomous_system.writer.resolve_lost_suffix";

/// Named refusal dimensions of the consequential-effect fence. Every refusal
/// names exactly one dimension and selects zero final invokers.
pub const FENCE_REFUSAL_DIMENSIONS: [&str; 10] = [
    "caller_authored",
    "stale",
    "foreign",
    "deposed",
    "membership",
    "epoch",
    "resource",
    "grant",
    "root",
    "effect_state",
];

/// Named M2 writer-epoch transition kinds (the canon envelope enum). The
/// brief's claim/renew/depose/handover ladder maps onto these: claim =
/// `genesis`, renew = `same_node_restore`, depose = `replacement_restore`,
/// handover = `promotion`; a lease renewal that advances no epoch is not a
/// transition in this family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriterEpochTransitionKind {
    /// Claim the first writer epoch of a System (epoch 1).
    Genesis,
    /// The same admitted node re-establishes writer authority (epoch +1).
    SameNodeRestore,
    /// A governed replacement deposes the prior writer (epoch +1).
    ReplacementRestore,
    /// A caught-up hot standby is promoted; the old writer is fenced.
    Promotion,
}

impl WriterEpochTransitionKind {
    /// Every transition kind in stable order.
    pub const ALL: [Self; 4] = [
        Self::Genesis,
        Self::SameNodeRestore,
        Self::ReplacementRestore,
        Self::Promotion,
    ];

    /// Stable wire kind name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::SameNodeRestore => "same_node_restore",
            Self::ReplacementRestore => "replacement_restore",
            Self::Promotion => "promotion",
        }
    }

    /// Parse a stable wire kind name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Exact one-operation wallet scope, disjoint from every prior family.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::Genesis => "scope:autonomous_system.writer.genesis",
            Self::SameNodeRestore => "scope:autonomous_system.writer.same_node_restore",
            Self::ReplacementRestore => "scope:autonomous_system.writer.replacement_restore",
            Self::Promotion => "scope:autonomous_system.writer.promotion",
        }
    }
}

/// Exact durable identity coordinates resolved by the server, never the
/// caller (INV-37).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WriterIdentityBinding {
    /// Canonical System identity.
    pub system_id: String,
    /// Admitted genesis ref.
    pub genesis_ref: String,
    /// Live governing authority.
    pub source_governing_authority_ref: String,
    /// Live admitted deployment-profile revision ref.
    pub deployment_profile_ref: String,
    /// Live admitted deployment-profile revision root.
    pub deployment_profile_root: String,
    /// Live admitted ordering profile ref.
    pub ordering_profile_ref: String,
    /// Live admitted ordering profile root.
    pub ordering_profile_root: String,
    /// Current authority revocation snapshot resolved from durable truth.
    pub authority_revocation_snapshot_ref: String,
    /// Current authority revocation epoch resolved from durable truth.
    pub authority_revocation_epoch: u64,
}

/// Durable writer-fence head replayed from committed transitions only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WriterFenceHead {
    /// Latest committed writer epoch; zero before genesis.
    pub active_epoch: u64,
    /// The exact latest committed transition, absent before genesis.
    pub active_transition: Option<Value>,
}

/// One declared per-resource fence observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceFenceDeclaration {
    /// Exact resource identity.
    pub resource_id: String,
    /// Closed effect kinds this fence admits.
    pub allowed_effect_kinds: Vec<String>,
    /// Minimum read consistency a fence context must present.
    pub minimum_read_consistency: String,
    /// Advanced read watermark observed for this resource.
    pub read_watermark: String,
}

/// Closed caller declaration for one writer-epoch transition. Any field this
/// plane resolves from durable truth (epochs, roots, readiness, revocation)
/// is deliberately absent: a caller-authored value is refused by the closed
/// shape itself before compile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterTransitionDeclaration {
    /// Successor candidate node identity inside the System namespace.
    pub candidate_node_id: String,
    /// Caller's compare-and-swap view of the active transition hash.
    #[serde(default)]
    pub expected_predecessor_transition_hash: Option<String>,
    /// Caller's compare-and-swap view of the current membership set root.
    pub expected_membership_root: String,
    /// Fresh writer lease for the successor epoch.
    pub writer_lease_ref: String,
    /// Ref of the server-resolved catch-up receipt.
    pub catchup_receipt_ref: String,
    /// Ref of the state-root verification evidence.
    pub state_root_verification_ref: String,
    /// Ref of the server-resolved verified-ready node attestation record.
    pub attested_node_ref: String,
    /// Ref of the server-resolved temporal validity evaluation.
    pub temporal_validity_evaluation_ref: String,
    /// Declared per-resource fences (must cover the predecessor's resources).
    #[serde(default)]
    pub resource_fences: Vec<ResourceFenceDeclaration>,
    /// Per-transition evidence refs.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

/// Server-resolved displaced-writer fencing observation for a non-genesis
/// transition: fence receipts when the prior writer was actively fenced, or
/// the wait-out horizon covering its latest possible lease and revocation
/// propagation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplacedWriterObservation {
    /// Receipts proving the prior writer was fenced.
    pub writer_fence_receipt_refs: Vec<String>,
    /// Receipts proving displaced effect leases were fenced.
    pub effect_lease_fence_receipt_refs: Vec<String>,
    /// Latest possible expiry of any displaced writer/effect lease.
    pub displaced_writer_leases_expire_at: String,
    /// Instant by which revocation propagation completed.
    pub revocation_propagation_complete_at: String,
    /// Declared clock/witness uncertainty bound.
    pub maximum_clock_skew_or_uncertainty_ms: u64,
    /// Independent witness evidence, when the evidence mode requires it.
    pub witness_evidence_refs: Vec<String>,
}

/// How the prior writer acknowledged its excluded suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuffixAcknowledgementCertainty {
    /// Written but never acknowledged to any caller.
    Unacknowledged,
    /// Acknowledged below the declared required durability.
    AckedBelowRequiredDurability,
    /// Acknowledgement state cannot be established.
    Ambiguous,
}

/// Server-resolved observation of the deposed writer's log tail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriorWriterLogObservation {
    /// Last operation offset common to both histories.
    pub last_common_offset: u64,
    /// State root at the last common offset.
    pub last_common_state_root: String,
    /// Highest offset the deposed writer acknowledged.
    pub acknowledged_offset: u64,
    /// Authoritative head offset of the successor history.
    pub authoritative_head_offset: u64,
    /// Authoritative head state root of the successor history.
    pub authoritative_head_state_root: String,
    /// Per-offset operation commitment refs of the excluded suffix.
    pub entry_commitment_refs: Vec<(u64, String)>,
    /// Custody artifacts retaining the excluded bytes.
    pub custody_artifact_refs: Vec<String>,
    /// How the suffix was acknowledged.
    pub acknowledgement_certainty: SuffixAcknowledgementCertainty,
    /// Reconciliation policy governing custody resolution.
    pub reconciliation_policy_ref: String,
}

/// Pure server-derived plan for one writer-epoch transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledWriterTransitionPlan {
    /// Named transition kind.
    pub kind: WriterEpochTransitionKind,
    /// Successor writer epoch (strictly the active epoch plus one).
    pub writer_epoch: u64,
    /// Transition identity.
    pub writer_epoch_transition_ref: String,
    /// Predecessor transition hash, absent only at genesis.
    pub predecessor_transition_hash: Option<String>,
    /// Successor node identity.
    pub successor_node_id: String,
    /// Bound membership set root.
    pub membership_root: String,
    /// Unstamped transition material (hash, CAS head, grant refs, and
    /// committed_at are placeholders until build time).
    pub transition_material: Value,
    /// Unstamped lost-suffix record, present when a suffix was excluded.
    pub lost_suffix: Option<Value>,
    /// Closed effect authorized by wallet.network.
    pub authority_effect: Value,
}

/// Fully built transition artifacts, every envelope contract-validated.
#[derive(Debug, Clone, PartialEq)]
pub struct WriterTransitionArtifacts {
    /// The immutable committed transition.
    pub transition: Value,
    /// The content commitment (also the CAS resulting head).
    pub transition_hash: String,
    /// Stamped lost-suffix record and its timeless revision root.
    pub lost_suffix: Option<(Value, String)>,
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

const READ_CONSISTENCY_ORDER: [&str; 6] = [
    "cached_projection",
    "projection_consistent",
    "snapshot_consistent",
    "state_root_consistent",
    "linearized_domain",
    "serializable_domain",
];

fn read_consistency_rank(value: &str) -> Option<usize> {
    READ_CONSISTENCY_ORDER
        .iter()
        .position(|candidate| *candidate == value)
}

/// The exact content commitment of one writer-epoch transition: computed over
/// every field except `writer_epoch_transition_hash` and
/// `continuity_cas.resulting_head`, mirroring the registered portable
/// invariant field-for-field.
pub fn writer_transition_commitment(transition: &Value) -> Result<String, String> {
    let mut material = serde_json::Map::new();
    material.insert(
        "domain".to_owned(),
        json!(WRITER_TRANSITION_COMMITMENT_PROFILE),
    );
    for field in [
        "schema_version",
        "writer_epoch_transition_id",
        "transition_kind",
        "system_id",
        "deployment_profile_ref",
        "deployment_profile_root",
        "failover_profile_ref",
        "failover_profile_root",
        "ordering_profile_ref",
        "ordering_profile_root",
        "predecessor_transition_ref",
        "predecessor_transition_hash",
        "expected_membership_root",
        "resulting_membership_root",
        "prior_writer",
        "successor_writer",
        "continuity",
        "authority",
        "displaced_writer_fencing",
        "timing_evidence",
        "resource_fences",
        "lost_suffix_record_ref",
        "admission_receipt_ref",
        "committed_at",
    ] {
        material.insert(
            field.to_owned(),
            transition
                .get(field)
                .cloned()
                .ok_or_else(|| format!("transition lacks its '{field}' commitment material"))?,
        );
    }
    for (name, pointer) in [
        ("continuity_cas_mechanism", "/continuity_cas/mechanism"),
        (
            "continuity_cas_substrate_ref",
            "/continuity_cas/substrate_ref",
        ),
        (
            "continuity_cas_expected_head",
            "/continuity_cas/expected_head",
        ),
        ("continuity_cas_proof_ref", "/continuity_cas/proof_ref"),
    ] {
        material.insert(
            name.to_owned(),
            transition
                .pointer(pointer)
                .cloned()
                .ok_or_else(|| format!("transition lacks its '{pointer}' commitment material"))?,
        );
    }
    jcs_hash(&Value::Object(material))
}

/// The recomputable commitment of one fence context (every field except
/// `fence_commitment`).
pub fn fence_context_commitment(context: &Value) -> Result<String, String> {
    let object = context
        .as_object()
        .ok_or("fence context is not an object")?;
    let mut material = serde_json::Map::new();
    material.insert("domain".to_owned(), json!(FENCE_COMMITMENT_PROFILE));
    for (key, value) in object {
        if key != "fence_commitment" {
            material.insert(key.clone(), value.clone());
        }
    }
    jcs_hash(&Value::Object(material))
}

/// Content root of one owner-declared failover profile record.
pub fn failover_profile_root(profile: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": FAILOVER_PROFILE_HASH_PROFILE,
        "profile": profile,
    }))
}

/// Timeless content root of one lost-suffix record revision: the volatile
/// `recorded_at` stamp is outside the identity so any stored revision
/// recomputes byte-exactly.
pub fn lost_suffix_record_root(record: &Value) -> Result<String, String> {
    let mut timeless = record.clone();
    timeless["recorded_at"] = Value::Null;
    jcs_hash(&json!({
        "domain": LOST_SUFFIX_RECORD_HASH_PROFILE,
        "record": timeless,
    }))
}

/// Structurally validate one owner-declared failover profile against the
/// identity binding and extract the facts this plane consumes. This is a
/// declared DESIRED record: it can never assert an observed writer, health,
/// or fencing fact, and every recovery mechanism admits only its own kinds.
pub fn validate_failover_profile(
    profile: &Value,
    binding: &WriterIdentityBinding,
) -> Result<String, String> {
    if profile.get("schema_version").and_then(Value::as_str)
        != Some("ioi.autonomous-system-failover-profile.v1")
    {
        return Err("failover profile schema version is not admitted".to_owned());
    }
    if profile.get("system_id").and_then(Value::as_str) != Some(binding.system_id.as_str()) {
        return Err("failover profile does not belong to this System".to_owned());
    }
    if profile.get("status").and_then(Value::as_str) != Some("active") {
        return Err("failover profile is not the active declaration".to_owned());
    }
    if profile
        .get("failover_profile_id")
        .and_then(Value::as_str)
        .is_none_or(|value| !canonical_ref(value, &["failover-profile://"]))
    {
        return Err("failover profile lacks a canonical identity".to_owned());
    }
    if profile
        .get("ambiguous_partition_response")
        .and_then(Value::as_str)
        != Some("fail_closed")
    {
        return Err("an ambiguous partition must fail closed".to_owned());
    }
    if profile
        .pointer("/durable_continuity_cas/unavailable_or_ambiguous_response")
        .and_then(Value::as_str)
        != Some("fail_closed")
    {
        return Err("an unavailable or ambiguous continuity CAS must fail closed".to_owned());
    }
    let ttl = profile
        .pointer("/deployment_timing_assumptions/writer_lease_ttl_ms")
        .and_then(Value::as_u64)
        .ok_or("failover profile lacks its writer lease ttl")?;
    let margin = profile
        .pointer("/deployment_timing_assumptions/writer_lease_renewal_margin_ms")
        .and_then(Value::as_u64)
        .ok_or("failover profile lacks its writer lease renewal margin")?;
    if margin >= ttl {
        return Err("the renewal margin must be shorter than the writer-lease ttl".to_owned());
    }
    let heartbeat = profile
        .pointer("/deployment_timing_assumptions/heartbeat_interval_ms")
        .and_then(Value::as_u64)
        .ok_or("failover profile lacks its heartbeat interval")?;
    let heartbeat_expiry = profile
        .pointer("/deployment_timing_assumptions/heartbeat_evidence_expires_after_ms")
        .and_then(Value::as_u64)
        .ok_or("failover profile lacks its heartbeat evidence expiry")?;
    if heartbeat_expiry <= heartbeat {
        return Err("heartbeat evidence must expire after its declared interval".to_owned());
    }
    if profile
        .pointer("/deployment_timing_assumptions/temporal_verification_profile_ref")
        .and_then(Value::as_str)
        .is_none_or(|value| !canonical_ref(value, &["policy://"]))
    {
        return Err("failover profile lacks its temporal verification profile binding".to_owned());
    }
    let mechanism = profile
        .get("recovery_mechanism")
        .and_then(Value::as_str)
        .ok_or("failover profile lacks its recovery mechanism")?;
    let restore_present = profile
        .get("single_writer_restore")
        .is_some_and(|value| !value.is_null());
    let promotion_present = profile
        .get("single_writer_promotion")
        .is_some_and(|value| !value.is_null());
    let ordering_present = profile
        .get("ordering_profile_recovery")
        .is_some_and(|value| !value.is_null());
    let admitted = match mechanism {
        "unavailable_fail_closed" => !restore_present && !promotion_present && !ordering_present,
        "single_writer_restore" => restore_present && !promotion_present && !ordering_present,
        "single_writer_promotion" => promotion_present && !restore_present && !ordering_present,
        "ordering_profile_native" => ordering_present && !restore_present && !promotion_present,
        _ => return Err("failover recovery mechanism is not a declared member".to_owned()),
    };
    if !admitted {
        return Err(
            "failover recovery objects contradict the declared recovery mechanism".to_owned(),
        );
    }
    failover_profile_root(profile)
}

/// Pure replay of the committed writer-epoch transition log: the restart
/// path. Epochs are contiguous from 1, exactly one genesis exists, every
/// predecessor ref/hash chains, every content commitment recomputes, and the
/// commit time never regresses. A fork, gap, regression, or tampered
/// commitment refuses instead of guessing.
pub fn replay_writer_epoch_transitions(
    system_id: &str,
    transitions: &[Value],
) -> Result<WriterFenceHead, String> {
    let mut ordered: Vec<&Value> = transitions
        .iter()
        .filter(|value| value.get("system_id").and_then(Value::as_str) == Some(system_id))
        .collect();
    ordered.sort_by_key(|value| {
        value
            .pointer("/successor_writer/writer_epoch")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    });
    let mut head = WriterFenceHead {
        active_epoch: 0,
        active_transition: None,
    };
    for transition in ordered {
        validate_architecture_contract(WRITER_TRANSITION_CONTRACT, transition)
            .map_err(|error| format!("committed writer transition is invalid: {error}"))?;
        let epoch = transition
            .pointer("/successor_writer/writer_epoch")
            .and_then(Value::as_u64)
            .ok_or("committed writer transition lacks its successor epoch")?;
        if epoch != head.active_epoch + 1 {
            return Err(if epoch <= head.active_epoch {
                "the writer log forks: two transitions claim the same epoch".to_owned()
            } else {
                "the writer log has a gap: the epoch never skips".to_owned()
            });
        }
        let kind = required_string(transition, "/transition_kind")?;
        let commitment = writer_transition_commitment(transition)?;
        if transition
            .get("writer_epoch_transition_hash")
            .and_then(Value::as_str)
            != Some(commitment.as_str())
            || transition
                .pointer("/continuity_cas/resulting_head")
                .and_then(Value::as_str)
                != Some(commitment.as_str())
        {
            return Err("committed writer transition carries a tampered commitment".to_owned());
        }
        if transition
            .pointer("/prior_writer/writer_epoch")
            .and_then(Value::as_u64)
            != Some(head.active_epoch)
        {
            return Err("committed writer transition detaches from the prior epoch".to_owned());
        }
        match &head.active_transition {
            None => {
                if kind != "genesis" {
                    return Err("the first writer transition must be the genesis claim".to_owned());
                }
            }
            Some(active) => {
                if kind == "genesis" {
                    return Err("a duplicate genesis claim is refused".to_owned());
                }
                let active_hash = required_string(active, "/writer_epoch_transition_hash")?;
                let active_ref = required_string(active, "/writer_epoch_transition_id")?;
                if transition
                    .get("predecessor_transition_hash")
                    .and_then(Value::as_str)
                    != Some(active_hash)
                    || transition
                        .get("predecessor_transition_ref")
                        .and_then(Value::as_str)
                        != Some(active_ref)
                {
                    return Err(
                        "committed writer transition breaks its predecessor chain".to_owned()
                    );
                }
                if transition
                    .pointer("/continuity_cas/expected_head")
                    .and_then(Value::as_str)
                    != Some(active_hash)
                {
                    return Err(
                        "committed writer transition breaks its continuity CAS chain".to_owned(),
                    );
                }
                if transition
                    .pointer("/prior_writer/node_id")
                    .and_then(Value::as_str)
                    != active
                        .pointer("/successor_writer/node_id")
                        .and_then(Value::as_str)
                {
                    return Err(
                        "committed writer transition names a prior writer durable truth does not"
                            .to_owned(),
                    );
                }
                if required_string(transition, "/committed_at")?
                    < required_string(active, "/committed_at")?
                {
                    return Err("committed writer transition regresses commit time".to_owned());
                }
            }
        }
        head.active_epoch = epoch;
        head.active_transition = Some(transition.clone());
    }
    Ok(head)
}

fn validate_declaration(declaration: &WriterTransitionDeclaration) -> Result<(), String> {
    ensure_distinct(&declaration.evidence_refs, "transition evidence")?;
    let evidence_prefixes = &["evidence://", "receipt://", "artifact://", "attestation://"][..];
    if declaration
        .evidence_refs
        .iter()
        .any(|value| !canonical_ref(value, evidence_prefixes))
    {
        return Err("transition evidence contains a non-canonical ref".to_owned());
    }
    if !canonical_hash(&declaration.expected_membership_root) {
        return Err("expected membership root is not canonical".to_owned());
    }
    if let Some(hash) = declaration.expected_predecessor_transition_hash.as_deref() {
        if !canonical_hash(hash) {
            return Err("expected predecessor transition hash is not canonical".to_owned());
        }
    }
    if !canonical_ref(&declaration.writer_lease_ref, &["lease://"]) {
        return Err("writer lease ref is not canonical".to_owned());
    }
    if !canonical_ref(&declaration.catchup_receipt_ref, &["receipt://"]) {
        return Err("catch-up receipt ref is not canonical".to_owned());
    }
    if !canonical_ref(
        &declaration.state_root_verification_ref,
        &["verification://"],
    ) {
        return Err("state-root verification ref is not canonical".to_owned());
    }
    if !canonical_ref(&declaration.attested_node_ref, &["hypervisoros-node://"]) {
        return Err("attested node ref is not canonical".to_owned());
    }
    if !canonical_ref(
        &declaration.temporal_validity_evaluation_ref,
        &["temporal-evaluation://", "evidence://", "receipt://"],
    ) {
        return Err("temporal evaluation ref is not canonical".to_owned());
    }
    let mut resource_ids: Vec<String> = declaration
        .resource_fences
        .iter()
        .map(|fence| fence.resource_id.clone())
        .collect();
    let declared = resource_ids.len();
    resource_ids.sort();
    resource_ids.dedup();
    if resource_ids.len() != declared {
        return Err("resource fences declare a resource twice".to_owned());
    }
    for fence in &declaration.resource_fences {
        if fence.resource_id.is_empty()
            || fence.resource_id.len() > 128
            || fence.allowed_effect_kinds.is_empty()
            || fence.read_watermark.is_empty()
        {
            return Err("a declared resource fence is structurally incomplete".to_owned());
        }
        if read_consistency_rank(&fence.minimum_read_consistency).is_none() {
            return Err("a declared resource fence names an unknown read consistency".to_owned());
        }
        ensure_distinct(&fence.allowed_effect_kinds, "allowed effect kinds")?;
    }
    Ok(())
}

fn validate_temporal_binding(
    profile: &Value,
    evaluation: &Value,
    declared_evaluation_ref: &str,
    subject_ref: &str,
    subject_hash: &str,
) -> Result<(String, String, String, String), String> {
    validate_architecture_contract(TEMPORAL_PROFILE_CONTRACT, profile)
        .map_err(|error| format!("temporal verification profile is invalid: {error}"))?;
    validate_architecture_contract(TEMPORAL_EVALUATION_CONTRACT, evaluation)
        .map_err(|error| format!("temporal validity evaluation is invalid: {error}"))?;
    if required_string(evaluation, "/evaluation_id")? != declared_evaluation_ref {
        return Err(
            "resolved temporal evaluation does not match the declared evaluation ref".to_owned(),
        );
    }
    if required_string(evaluation, "/profile_ref")? != required_string(profile, "/profile_ref")?
        || required_string(evaluation, "/profile_hash")?
            != required_string(profile, "/profile_hash")?
    {
        return Err("temporal evaluation is not bound to the declared temporal profile".to_owned());
    }
    if required_string(evaluation, "/subject_ref")? != subject_ref
        || required_string(evaluation, "/subject_hash")? != subject_hash
    {
        return Err("temporal evaluation is not bound to this exact writer candidate".to_owned());
    }
    if required_string(evaluation, "/temporal_posture")? != "online_fresh" {
        return Err(
            "temporal posture is not online_fresh; stale evidence cannot advance a writer epoch"
                .to_owned(),
        );
    }
    let required_claims: Vec<&str> = profile
        .pointer("/declaration/required_claims")
        .and_then(Value::as_array)
        .map(|claims| claims.iter().filter_map(Value::as_str).collect())
        .ok_or("temporal profile lacks its required claims")?;
    let claims = evaluation
        .get("claims")
        .and_then(Value::as_array)
        .ok_or("temporal evaluation lacks its claims")?;
    for required in required_claims {
        let status = claims
            .iter()
            .find(|claim| claim.get("kind").and_then(Value::as_str) == Some(required))
            .and_then(|claim| claim.get("status"))
            .and_then(Value::as_str);
        if status != Some("established") {
            return Err(format!(
                "required temporal claim '{required}' is not established ({})",
                status.unwrap_or("absent")
            ));
        }
    }
    let observed_at = evaluation
        .pointer("/evidence_horizon/valid_from")
        .and_then(Value::as_str)
        .ok_or("temporal evaluation lacks its evidence horizon start")?;
    let expires_at = evaluation
        .pointer("/evidence_horizon/valid_until")
        .and_then(Value::as_str)
        .ok_or("temporal evaluation lacks its evidence horizon end")?;
    Ok((
        required_string(profile, "/profile_ref")?.to_owned(),
        required_string(evaluation, "/evaluation_hash")?.to_owned(),
        observed_at.to_owned(),
        expires_at.to_owned(),
    ))
}

fn node_record<'a>(records: &'a [Value], node_id: &str) -> Option<&'a Value> {
    records
        .iter()
        .find(|record| record.get("node_id").and_then(Value::as_str) == Some(node_id))
}

fn build_lost_suffix(
    system_id: &str,
    ns: &str,
    writer_epoch_transition_ref: &str,
    prior_epoch: u64,
    successor_epoch: u64,
    observation: &PriorWriterLogObservation,
) -> Result<Option<Value>, String> {
    if observation.acknowledged_offset <= observation.last_common_offset {
        return Ok(None);
    }
    let first = observation.last_common_offset + 1;
    let last = observation.acknowledged_offset;
    let count = last - first + 1;
    if count > 256 {
        return Err("the excluded suffix exceeds the custody row bound".to_owned());
    }
    let mut offsets: Vec<u64> = observation
        .entry_commitment_refs
        .iter()
        .map(|(offset, _)| *offset)
        .collect();
    offsets.sort_unstable();
    let expected: Vec<u64> = (first..=last).collect();
    if offsets != expected {
        return Err(
            "the excluded suffix custody rows do not cover exactly the acknowledged range"
                .to_owned(),
        );
    }
    let mut sorted_refs = observation.entry_commitment_refs.clone();
    sorted_refs.sort_by_key(|(offset, _)| *offset);
    let entries: Vec<Value> = sorted_refs
        .iter()
        .map(|(offset, commitment_ref)| {
            json!({
                "operation_offset": offset,
                "operation_commitment_ref": commitment_ref,
                "custody_status": "retained_ambiguous",
                "resolution_receipt_ref": Value::Null,
                "resolution_evidence_refs": [],
            })
        })
        .collect();
    let commitment_refs: Vec<Value> = sorted_refs
        .iter()
        .map(|(_, commitment_ref)| json!(commitment_ref))
        .collect();
    let (classification, disposition) = match observation.acknowledgement_certainty {
        SuffixAcknowledgementCertainty::Unacknowledged => {
            ("lost_unacknowledged", "retained_for_forensics")
        }
        SuffixAcknowledgementCertainty::AckedBelowRequiredDurability => (
            "orphaned_acknowledged_below_required_durability",
            "compensating_transition_required",
        ),
        SuffixAcknowledgementCertainty::Ambiguous => ("ambiguous", "adjudication_required"),
    };
    Ok(Some(json!({
        "schema_version": "ioi.lost-suffix-record.v1",
        "lost_suffix_record_id": format!("lost-suffix://{ns}/epoch-{successor_epoch}"),
        "system_id": system_id,
        "writer_epoch_transition_ref": writer_epoch_transition_ref,
        "prior_writer_epoch": prior_epoch,
        "successor_writer_epoch": successor_epoch,
        "last_common": {
            "operation_offset": observation.last_common_offset,
            "state_root": observation.last_common_state_root,
        },
        "authoritative_head": {
            "operation_offset": observation.authoritative_head_offset,
            "state_root": observation.authoritative_head_state_root,
        },
        "excluded_suffix": {
            "first_offset": first,
            "last_offset": last,
            "operation_count": count,
            "commitment_refs": commitment_refs,
            "custody_artifact_refs": observation.custody_artifact_refs,
            "entries": entries,
        },
        "classification": classification,
        "reconciliation_policy_ref": observation.reconciliation_policy_ref,
        "disposition": disposition,
        "disposition_receipt_refs": [],
        "predecessor_record_root": Value::Null,
        "status": "open",
        "recorded_at": Value::Null,
    })))
}

/// Compile one writer-epoch transition from exact durable owner inputs. Every
/// admission input is resolved, never asserted (INV-37): the membership set,
/// fence head, failover profile, attested-node record, catch-up receipt,
/// temporal profile/evaluation, and displaced-writer observation all arrive
/// as server-resolved trusted inputs, and the closed declaration carries only
/// refs and compare-and-swap views.
#[allow(clippy::too_many_arguments)]
pub fn compile_writer_epoch_transition_plan(
    kind: WriterEpochTransitionKind,
    binding: &WriterIdentityBinding,
    failover_profile: &Value,
    membership_records: &[Value],
    membership_root: &str,
    head: &WriterFenceHead,
    declaration: &WriterTransitionDeclaration,
    trusted_attested_node: &Value,
    trusted_catchup_receipt: &Value,
    trusted_temporal_profile: &Value,
    trusted_temporal_evaluation: &Value,
    displaced_observation: Option<&DisplacedWriterObservation>,
    prior_log: Option<&PriorWriterLogObservation>,
) -> Result<CompiledWriterTransitionPlan, String> {
    let ns = namespace(&binding.system_id)?;
    validate_declaration(declaration)?;
    let failover_root = validate_failover_profile(failover_profile, binding)?;
    let failover_ref = required_string(failover_profile, "/failover_profile_id")?;
    let mechanism = required_string(failover_profile, "/recovery_mechanism")?;

    // Dimension: foreign — a node identity outside the System namespace is
    // not compilable.
    let node_prefix = format!("node://{ns}/");
    if !declaration
        .candidate_node_id
        .starts_with(node_prefix.as_str())
    {
        return Err("candidate node identity is outside the System namespace".to_owned());
    }

    // Dimension: membership — strict CAS over the derived durable set root.
    if declaration.expected_membership_root != membership_root {
        return Err("stale predecessor membership root".to_owned());
    }

    // Dimension: stale/epoch — strict CAS over the active transition hash.
    let active = head.active_transition.as_ref();
    let active_hash = active
        .map(|transition| required_string(transition, "/writer_epoch_transition_hash"))
        .transpose()?
        .map(str::to_owned);
    if declaration.expected_predecessor_transition_hash != active_hash {
        return Err("stale predecessor writer-epoch transition".to_owned());
    }
    match kind {
        WriterEpochTransitionKind::Genesis => {
            if active.is_some() {
                return Err("the System already has an active writer; genesis is spent".to_owned());
            }
            if prior_log.is_some() || displaced_observation.is_some() {
                return Err("genesis cannot carry displaced-writer evidence".to_owned());
            }
        }
        _ => {
            if active.is_none() {
                return Err("no active writer exists to restore, replace, or hand over".to_owned());
            }
        }
    }

    // Recovery mechanism gate: only the declared recovery objects admit each
    // non-genesis kind.
    match kind {
        WriterEpochTransitionKind::Genesis => {}
        WriterEpochTransitionKind::SameNodeRestore
        | WriterEpochTransitionKind::ReplacementRestore => {
            if mechanism != "single_writer_restore" {
                return Err(
                    "the declared recovery mechanism does not admit a single-writer restore"
                        .to_owned(),
                );
            }
            let target = failover_profile
                .pointer("/single_writer_restore/recovery_target")
                .and_then(Value::as_str);
            let required = if kind == WriterEpochTransitionKind::SameNodeRestore {
                "same_admitted_node"
            } else {
                "governed_replacement"
            };
            if target != Some(required) {
                return Err(format!(
                    "the declared restore target does not admit '{}'",
                    kind.as_str()
                ));
            }
        }
        WriterEpochTransitionKind::Promotion => {
            if mechanism != "single_writer_promotion" {
                return Err(
                    "the declared recovery mechanism does not admit a standby promotion".to_owned(),
                );
            }
        }
    }

    let active_node = active
        .map(|transition| required_string(transition, "/successor_writer/node_id"))
        .transpose()?;
    match kind {
        WriterEpochTransitionKind::SameNodeRestore => {
            // Dimension: deposed — only the exact active writer node may
            // restore itself; any other node is deposed or foreign here.
            if active_node != Some(declaration.candidate_node_id.as_str()) {
                return Err(
                    "a deposed or foreign node cannot restore the active writer epoch".to_owned(),
                );
            }
        }
        WriterEpochTransitionKind::ReplacementRestore | WriterEpochTransitionKind::Promotion => {
            if active_node == Some(declaration.candidate_node_id.as_str()) {
                return Err(
                    "the active writer cannot depose or hand over to itself; use a same-node \
                     restore"
                        .to_owned(),
                );
            }
        }
        WriterEpochTransitionKind::Genesis => {}
    }

    // Dimension: grant — authority revocation evidence never regresses.
    if let Some(transition) = active {
        let prior_revocation = transition
            .pointer("/authority/authority_revocation_epoch")
            .and_then(Value::as_u64)
            .ok_or("active transition lacks its revocation epoch")?;
        if binding.authority_revocation_epoch < prior_revocation {
            return Err("authority revocation evidence regresses".to_owned());
        }
    }

    // Candidate membership truth: admitted, active, observed ready.
    for record in membership_records {
        validate_architecture_contract(NODE_MEMBERSHIP_CONTRACT, record)
            .map_err(|error| format!("durable membership record is invalid: {error}"))?;
    }
    let candidate = node_record(membership_records, &declaration.candidate_node_id)
        .ok_or("candidate is not an admitted member node")?;
    if required_string(candidate, "/status")? != "active" {
        return Err("candidate membership status is not active".to_owned());
    }
    if candidate
        .pointer("/observation/readiness")
        .and_then(Value::as_str)
        != Some("ready")
    {
        return Err("candidate observed readiness is not ready".to_owned());
    }
    if kind == WriterEpochTransitionKind::Promotion {
        let candidate_role = failover_profile
            .pointer("/single_writer_promotion/candidate_role")
            .and_then(Value::as_str)
            .ok_or("failover promotion lacks its candidate role")?;
        let holds_role = candidate
            .get("role_assignments")
            .and_then(Value::as_array)
            .is_some_and(|assignments| {
                assignments.iter().any(|assignment| {
                    assignment.get("role").and_then(Value::as_str) == Some(candidate_role)
                })
            });
        if !holds_role {
            return Err(format!(
                "promotion requires the candidate to hold the declared '{candidate_role}' role"
            ));
        }
    }
    let candidate_membership_epoch = candidate
        .get("membership_epoch")
        .and_then(Value::as_u64)
        .ok_or("candidate membership record lacks its epoch")?;
    let candidate_membership_ref = required_string(candidate, "/node_membership_id")?.to_owned();
    let candidate_record_root = membership_record_root(candidate)?;

    // Attested node state from the plane below: verified-ready only.
    validate_architecture_contract(HYPERVISOROS_NODE_CONTRACT, trusted_attested_node)
        .map_err(|error| format!("attested node record is invalid: {error}"))?;
    if required_string(trusted_attested_node, "/node_record_id")? != declaration.attested_node_ref {
        return Err(
            "resolved attested node does not match the declared attested-node ref".to_owned(),
        );
    }
    if required_string(trusted_attested_node, "/status")? != "ready" {
        return Err("candidate node attestation state is not verified-ready".to_owned());
    }

    // Dimension: root — catch-up receipt bound to the candidate and its
    // exact verified state root.
    if trusted_catchup_receipt
        .get("receipt_ref")
        .and_then(Value::as_str)
        != Some(declaration.catchup_receipt_ref.as_str())
    {
        return Err("resolved catch-up receipt does not match the declared receipt ref".to_owned());
    }
    if trusted_catchup_receipt
        .get("node_id")
        .and_then(Value::as_str)
        != Some(declaration.candidate_node_id.as_str())
    {
        return Err("catch-up receipt is not bound to the candidate node".to_owned());
    }
    let receipt_offset = trusted_catchup_receipt
        .get("operation_offset")
        .and_then(Value::as_u64)
        .ok_or("catch-up receipt carries no watermark")?;
    let receipt_root = trusted_catchup_receipt
        .get("verified_state_root")
        .and_then(Value::as_str)
        .filter(|value| canonical_hash(value))
        .ok_or("catch-up receipt carries no canonical verified state root")?;
    let membership_offset = candidate
        .pointer("/synchronization/operation_offset")
        .and_then(Value::as_u64)
        .ok_or("candidate membership record lacks its catch-up watermark")?;
    if receipt_offset < membership_offset {
        return Err("catch-up watermark cannot regress".to_owned());
    }
    let membership_verified_root = candidate
        .pointer("/synchronization/verified_state_root")
        .and_then(Value::as_str);
    if membership_verified_root != Some(receipt_root) {
        return Err(
            "catch-up receipt root contradicts the candidate's verified membership root".to_owned(),
        );
    }

    // Timing evidence: the bound temporal evaluation must establish every
    // required claim for this exact candidate under the exact profile.
    let (temporal_profile_ref, evaluation_hash, observed_at, expires_at) =
        validate_temporal_binding(
            trusted_temporal_profile,
            trusted_temporal_evaluation,
            &declaration.temporal_validity_evaluation_ref,
            &declaration.candidate_node_id,
            &candidate_record_root,
        )?;

    // Dimension: resource — the declared fences must cover every resource the
    // predecessor fenced; a dropped fence would silently unfence a resource.
    if let Some(transition) = active {
        let predecessor_fences = transition
            .get("resource_fences")
            .and_then(Value::as_array)
            .ok_or("active transition lacks its resource fences")?;
        for fence in predecessor_fences {
            let resource_id = required_string(fence, "/resource_id")?;
            if !declaration
                .resource_fences
                .iter()
                .any(|declared| declared.resource_id == resource_id)
            {
                return Err(format!(
                    "resource fence coverage is incomplete: '{resource_id}' is not advanced"
                ));
            }
        }
    }

    // Displaced-writer fencing or safe wait-out for every non-genesis kind.
    let (displaced, effects_admissible_not_before) = match kind {
        WriterEpochTransitionKind::Genesis => (
            json!({
                "writer_fence_receipt_refs": [],
                "effect_lease_fence_receipt_refs": [],
            }),
            observed_at.clone(),
        ),
        _ => {
            let observation = displaced_observation
                .ok_or("displaced-writer fencing evidence is not resolvable")?;
            ensure_distinct(
                &observation.writer_fence_receipt_refs,
                "writer fence receipts",
            )?;
            ensure_distinct(
                &observation.effect_lease_fence_receipt_refs,
                "effect lease fence receipts",
            )?;
            let fenced = !observation.writer_fence_receipt_refs.is_empty();
            let wait_out = observation
                .displaced_writer_leases_expire_at
                .as_str()
                .max(observation.revocation_propagation_complete_at.as_str())
                .to_owned();
            if !fenced && wait_out > expires_at {
                return Err(
                    "the displaced-writer wait-out exceeds the bound timing-evidence horizon"
                        .to_owned(),
                );
            }
            let not_before = if fenced {
                observed_at.clone().max(wait_out)
            } else {
                wait_out
            };
            (
                json!({
                    "writer_fence_receipt_refs": observation.writer_fence_receipt_refs,
                    "effect_lease_fence_receipt_refs": observation.effect_lease_fence_receipt_refs,
                }),
                not_before,
            )
        }
    };

    let writer_epoch = head.active_epoch + 1;
    let transition_ref = format!("writer-transition://{ns}/epoch/{writer_epoch}");
    let prior_writer = match active {
        None => json!({
            "node_membership_ref": Value::Null,
            "node_id": Value::Null,
            "membership_epoch": Value::Null,
            "writer_epoch": 0,
        }),
        Some(transition) => json!({
            "node_membership_ref": transition.pointer("/successor_writer/node_membership_ref"),
            "node_id": transition.pointer("/successor_writer/node_id"),
            "membership_epoch": transition.pointer("/successor_writer/membership_epoch"),
            "writer_epoch": head.active_epoch,
        }),
    };
    let resource_fences: Vec<Value> = declaration
        .resource_fences
        .iter()
        .map(|fence| {
            json!({
                "resource_id": fence.resource_id,
                "allowed_effect_kinds": fence.allowed_effect_kinds,
                "minimum_read_consistency": fence.minimum_read_consistency,
                "read_watermark": fence.read_watermark,
            })
        })
        .collect();

    let lost_suffix = match (kind, prior_log) {
        (WriterEpochTransitionKind::Genesis, _) => None,
        (_, None) => None,
        (_, Some(observation)) => build_lost_suffix(
            &binding.system_id,
            ns,
            &transition_ref,
            head.active_epoch,
            writer_epoch,
            observation,
        )?,
    };
    let lost_suffix_record_ref = lost_suffix
        .as_ref()
        .map(|record| required_string(record, "/lost_suffix_record_id").map(str::to_owned))
        .transpose()?;

    let skew = displaced_observation
        .map(|observation| observation.maximum_clock_skew_or_uncertainty_ms)
        .unwrap_or(0);
    let witness_refs = displaced_observation
        .map(|observation| observation.witness_evidence_refs.clone())
        .unwrap_or_default();
    let (leases_expire_at, revocation_complete_at) = match displaced_observation {
        Some(observation) => (
            observation.displaced_writer_leases_expire_at.clone(),
            observation.revocation_propagation_complete_at.clone(),
        ),
        None => (observed_at.clone(), observed_at.clone()),
    };

    let transition_material = json!({
        "schema_version": "ioi.autonomous-system-writer-epoch-transition.v1",
        "writer_epoch_transition_id": transition_ref,
        "writer_epoch_transition_hash": Value::Null,
        "transition_kind": kind.as_str(),
        "system_id": binding.system_id,
        "deployment_profile_ref": binding.deployment_profile_ref,
        "deployment_profile_root": binding.deployment_profile_root,
        "failover_profile_ref": failover_ref,
        "failover_profile_root": failover_root,
        "ordering_profile_ref": binding.ordering_profile_ref,
        "ordering_profile_root": binding.ordering_profile_root,
        "predecessor_transition_ref": active
            .map(|transition| transition.get("writer_epoch_transition_id").cloned())
            .unwrap_or(Some(Value::Null)),
        "predecessor_transition_hash": active_hash,
        "expected_membership_root": membership_root,
        "resulting_membership_root": membership_root,
        "prior_writer": prior_writer,
        "successor_writer": {
            "node_membership_ref": candidate_membership_ref,
            "node_id": declaration.candidate_node_id,
            "membership_epoch": candidate_membership_epoch,
            "writer_epoch": writer_epoch,
            "writer_lease_ref": declaration.writer_lease_ref,
        },
        "continuity": {
            "verified_state_root": receipt_root,
            "checkpoint_ref": trusted_catchup_receipt.get("checkpoint_ref").cloned().unwrap_or(Value::Null),
            "operation_offset": receipt_offset,
            "catchup_receipt_ref": declaration.catchup_receipt_ref,
            "state_root_verification_ref": declaration.state_root_verification_ref,
        },
        "continuity_cas": {
            "mechanism": "wallet_epoch_authority",
            "substrate_ref": format!("wallet://wallet.network/{ns}"),
            "expected_head": active_hash,
            "resulting_head": Value::Null,
            "proof_ref": format!("receipt://{ns}/writer/cas/epoch-{writer_epoch}"),
        },
        "authority": {
            "authority_grant_refs": [],
            "authority_revocation_snapshot_ref": binding.authority_revocation_snapshot_ref,
            "authority_revocation_epoch": binding.authority_revocation_epoch,
        },
        "displaced_writer_fencing": {
            "writer_fence_receipt_refs": displaced["writer_fence_receipt_refs"],
            "effect_lease_fence_receipt_refs": displaced["effect_lease_fence_receipt_refs"],
            "effects_admissible_not_before": effects_admissible_not_before,
        },
        "timing_evidence": {
            "temporal_verification_profile_ref": temporal_profile_ref,
            "temporal_validity_evaluation_ref": declaration.temporal_validity_evaluation_ref,
            "temporal_validity_evaluation_hash": evaluation_hash,
            "observed_at": observed_at,
            "expires_at": expires_at,
            "displaced_writer_leases_expire_at": leases_expire_at,
            "revocation_propagation_complete_at": revocation_complete_at,
            "maximum_clock_skew_or_uncertainty_ms": skew,
            "witness_evidence_refs": witness_refs,
        },
        "resource_fences": resource_fences,
        "lost_suffix_record_ref": lost_suffix_record_ref,
        "admission_receipt_ref": format!("receipt://{ns}/writer/epoch/{writer_epoch}"),
        "committed_at": Value::Null,
    });

    let mut authority_effect = json!({
        "schema_version": "ioi.autonomous-system-writer-authority-effect.v1",
        "op": kind.as_str(),
        "required_scope": kind.required_scope(),
        "system_id": binding.system_id,
        "genesis_ref": binding.genesis_ref,
        "source_governing_authority_ref": binding.source_governing_authority_ref,
        "writer_epoch_transition_ref": transition_ref,
        "writer_epoch": writer_epoch,
        "predecessor_transition_hash": declaration.expected_predecessor_transition_hash,
        "successor_node_id": declaration.candidate_node_id,
        "successor_node_membership_ref": transition_material["successor_writer"]["node_membership_ref"],
        "membership_root": membership_root,
        "deployment_profile_root": binding.deployment_profile_root,
        "failover_profile_root": transition_material["failover_profile_root"],
        "ordering_profile_root": binding.ordering_profile_root,
        "verified_state_root": transition_material["continuity"]["verified_state_root"],
        "operation_offset": transition_material["continuity"]["operation_offset"],
        "lost_suffix_record_ref": transition_material["lost_suffix_record_ref"],
        "evidence_refs": declaration.evidence_refs,
        "writer_authority_admitted": true,
        "authority_widened": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": "ioi.autonomous-system-writer-operation-commitment-jcs-sha256.v1",
        "effect": authority_effect,
    }))?;
    authority_effect["operation_commitment"] = json!(operation_commitment);

    Ok(CompiledWriterTransitionPlan {
        kind,
        writer_epoch,
        writer_epoch_transition_ref: transition_ref,
        predecessor_transition_hash: declaration.expected_predecessor_transition_hash.clone(),
        successor_node_id: declaration.candidate_node_id.clone(),
        membership_root: membership_root.to_owned(),
        transition_material,
        lost_suffix,
        authority_effect,
    })
}

/// Stamp and seal one compiled transition into its immutable committed form.
/// The commit time must sit inside the bound timing-evidence horizon, the
/// content commitment is computed over every field except the transition hash
/// and the CAS resulting head, and both excluded fields are then set to it.
pub fn build_writer_transition_envelope(
    plan: &CompiledWriterTransitionPlan,
    authority_grant_ref: &str,
    timestamp: &str,
) -> Result<WriterTransitionArtifacts, String> {
    if !canonical_ref(authority_grant_ref, &["grant://"]) {
        return Err("authority grant ref is not canonical".to_owned());
    }
    let mut transition = plan.transition_material.clone();
    let observed_at = required_string(&transition, "/timing_evidence/observed_at")?.to_owned();
    let expires_at = required_string(&transition, "/timing_evidence/expires_at")?.to_owned();
    if timestamp < observed_at.as_str() || timestamp > expires_at.as_str() {
        return Err(
            "commit time is outside the bound timing-evidence horizon; the transition fails \
             closed"
                .to_owned(),
        );
    }
    transition["committed_at"] = json!(timestamp);
    transition["authority"]["authority_grant_refs"] = json!([authority_grant_ref]);
    let commitment = writer_transition_commitment(&transition)?;
    transition["writer_epoch_transition_hash"] = json!(commitment);
    transition["continuity_cas"]["resulting_head"] = json!(commitment);
    validate_architecture_contract(WRITER_TRANSITION_CONTRACT, &transition)
        .map_err(|error| format!("built writer transition is invalid: {error}"))?;
    let lost_suffix = match &plan.lost_suffix {
        None => None,
        Some(record) => {
            let mut stamped = record.clone();
            stamped["recorded_at"] = json!(timestamp);
            validate_architecture_contract(LOST_SUFFIX_CONTRACT, &stamped)
                .map_err(|error| format!("built lost-suffix record is invalid: {error}"))?;
            let root = lost_suffix_record_root(&stamped)?;
            Some((stamped, root))
        }
    };
    Ok(WriterTransitionArtifacts {
        transition,
        transition_hash: commitment,
        lost_suffix,
    })
}

/// Where a presented fence context came from. Only the policy enforcement
/// point itself may generate one; a caller-supplied context is refused before
/// any field comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceContextOrigin {
    /// Generated by the daemon-controlled policy enforcement point.
    PepGenerated,
    /// Presented by a caller, transport, projection, or any non-PEP party.
    CallerSupplied,
}

/// Server-derived truth the fence compares a presented context against.
/// Every field is resolved from durable owner state or trusted daemon
/// configuration, never from the request (INV-37).
#[derive(Debug, Clone, PartialEq)]
pub struct FenceServerTruth<'a> {
    /// Owner-derived System identity.
    pub system_id: &'a str,
    /// Trusted daemon startup/config node identity.
    pub executing_node_id: &'a str,
    /// The exact durable active writer transition, absent before genesis.
    pub active_transition: Option<&'a Value>,
    /// Current derived membership set root.
    pub node_membership_root: &'a str,
    /// Current deployment-profile revision root.
    pub deployment_profile_root: &'a str,
    /// Current authority revocation epoch.
    pub authority_revocation_epoch: u64,
    /// Owner-derived read evidence for the resource.
    pub read_state_root: &'a str,
    /// Owner-derived read watermark for the resource.
    pub read_watermark: &'a str,
    /// The exact payload hash the invoker is about to transmit.
    pub expected_payload_hash: &'a str,
    /// Trusted evaluation instant.
    pub now: &'a str,
}

/// The total fence verdict: admit selects exactly one final invoker; every
/// refusal selects zero and names its dimension.
#[derive(Debug, Clone, PartialEq)]
pub struct FenceVerdict {
    /// Whether the exact admitted effect may proceed to its final invoker.
    pub admitted: bool,
    /// Exactly one on admit, constantly zero on refusal.
    pub selected_final_invokers: u8,
    /// The named refusal dimension, absent only on admit.
    pub refusal_dimension: Option<&'static str>,
    /// Human-readable refusal reason, absent only on admit.
    pub refusal_reason: Option<String>,
}

impl FenceVerdict {
    fn refuse(dimension: &'static str, reason: impl Into<String>) -> Self {
        Self {
            admitted: false,
            selected_final_invokers: 0,
            refusal_dimension: Some(dimension),
            refusal_reason: Some(reason.into()),
        }
    }

    fn admit() -> Self {
        Self {
            admitted: true,
            selected_final_invokers: 1,
            refusal_dimension: None,
            refusal_reason: None,
        }
    }
}

fn context_str<'a>(context: &'a Value, pointer: &str) -> &'a str {
    context
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Evaluate one presented consequential-effect fence context against server
/// truth. This is a TOTAL function: every input produces a verdict, never a
/// panic and never an error, and every refusal names exactly one dimension
/// while selecting zero final invokers.
pub fn evaluate_consequential_effect_fence(
    truth: &FenceServerTruth<'_>,
    presented: &Value,
    origin: FenceContextOrigin,
) -> FenceVerdict {
    // Dimension 1 — caller-authored: only the PEP generates fence contexts.
    if origin == FenceContextOrigin::CallerSupplied {
        return FenceVerdict::refuse(
            "caller_authored",
            "caller-authored fence contexts are refused before evaluation",
        );
    }
    if validate_architecture_contract(FENCE_CONTEXT_CONTRACT, presented).is_err() {
        return FenceVerdict::refuse(
            "caller_authored",
            "the presented context is not a well-formed PEP-generated fence tuple",
        );
    }
    match fence_context_commitment(presented) {
        Ok(commitment) if commitment == context_str(presented, "/fence_commitment") => {}
        _ => {
            return FenceVerdict::refuse(
                "caller_authored",
                "the fence commitment does not recompute; a substituted field is refused",
            )
        }
    }
    if context_str(presented, "/system_id") != truth.system_id {
        return FenceVerdict::refuse(
            "caller_authored",
            "the presented context detaches from the owner-derived System identity",
        );
    }
    if context_str(presented, "/executing_node_id") != truth.executing_node_id {
        return FenceVerdict::refuse(
            "caller_authored",
            "the executing node identity is supplied by trusted daemon config, not the context",
        );
    }

    // The active fence is durable owner truth; without it the System-scoped
    // effect is unavailable.
    let Some(active) = truth.active_transition else {
        return FenceVerdict::refuse("epoch", "no admitted writer epoch is active");
    };
    let active_epoch = active
        .pointer("/successor_writer/writer_epoch")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let active_hash = context_str(active, "/writer_epoch_transition_hash");
    let active_node = context_str(active, "/successor_writer/node_id");
    let prior_node = active
        .pointer("/prior_writer/node_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let presented_epoch = presented
        .get("writer_epoch")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    // Dimension 2 — stale: an epoch below the active fence.
    if presented_epoch < active_epoch {
        return FenceVerdict::refuse(
            "stale",
            format!(
                "stale writer epoch {presented_epoch}: the resource has accepted the higher \
                 fence {active_epoch}"
            ),
        );
    }
    // Dimension 6 — epoch: an epoch durable truth never admitted, or the
    // right number over the wrong immutable transition.
    if presented_epoch > active_epoch {
        return FenceVerdict::refuse(
            "epoch",
            format!("writer epoch {presented_epoch} has not been admitted by durable truth"),
        );
    }
    if context_str(presented, "/writer_epoch_transition_hash") != active_hash
        || context_str(presented, "/writer_epoch_transition_ref")
            != context_str(active, "/writer_epoch_transition_id")
    {
        return FenceVerdict::refuse(
            "epoch",
            "the presented transition binding does not match the active writer-epoch transition",
        );
    }

    // Dimensions 3/4 — deposed and foreign: the executing node must BE the
    // active writer; the displaced prior writer is refused as deposed, any
    // other node as foreign.
    if truth.executing_node_id != active_node {
        if truth.executing_node_id == prior_node {
            return FenceVerdict::refuse(
                "deposed",
                "an otherwise fresh former writer is refused after a higher fence",
            );
        }
        return FenceVerdict::refuse(
            "foreign",
            "the executing node is not the active writer for this System",
        );
    }

    // Dimension 5 — membership: exact set root and the writer's exact
    // membership epoch.
    let active_membership_epoch = active
        .pointer("/successor_writer/membership_epoch")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if context_str(presented, "/node_membership_root") != truth.node_membership_root
        || presented
            .get("node_membership_epoch")
            .and_then(Value::as_u64)
            != Some(active_membership_epoch)
    {
        return FenceVerdict::refuse(
            "membership",
            "the presented membership root or epoch does not match durable membership truth",
        );
    }

    // Dimension 7 — resource: the resource and effect kind must be declared
    // by the active transition's fences.
    let empty = Vec::new();
    let fences = active
        .get("resource_fences")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let Some(fence) = fences.iter().find(|fence| {
        fence.get("resource_id").and_then(Value::as_str)
            == Some(context_str(presented, "/resource_id"))
    }) else {
        return FenceVerdict::refuse(
            "resource",
            "the resource carries no declared fence under the active writer epoch",
        );
    };
    let effect_admitted = fence
        .get("allowed_effect_kinds")
        .and_then(Value::as_array)
        .is_some_and(|kinds| {
            kinds
                .iter()
                .any(|kind| kind.as_str() == Some(context_str(presented, "/effect_kind")))
        });
    if !effect_admitted {
        return FenceVerdict::refuse(
            "resource",
            "the effect kind is not admitted by the resource's declared fence",
        );
    }

    // Dimension 8 — grant: the grant must be in the active authority set and
    // the revocation posture current.
    let grant_admitted = active
        .pointer("/authority/authority_grant_refs")
        .and_then(Value::as_array)
        .is_some_and(|grants| {
            grants
                .iter()
                .any(|grant| grant.as_str() == Some(context_str(presented, "/authority_grant_ref")))
        });
    if !grant_admitted {
        return FenceVerdict::refuse(
            "grant",
            "the presented authority grant is not part of the active writer authority set",
        );
    }
    if presented
        .get("authority_revocation_epoch")
        .and_then(Value::as_u64)
        != Some(truth.authority_revocation_epoch)
        || context_str(presented, "/authority_revocation_snapshot_ref")
            != context_str(active, "/authority/authority_revocation_snapshot_ref")
    {
        return FenceVerdict::refuse(
            "grant",
            "the presented revocation posture does not match current authority truth",
        );
    }

    // Dimension 9 — root: deployment and observed read state roots.
    if context_str(presented, "/deployment_profile_root") != truth.deployment_profile_root
        || context_str(presented, "/deployment_profile_root")
            != context_str(active, "/deployment_profile_root")
    {
        return FenceVerdict::refuse(
            "root",
            "the presented deployment-profile root does not match admitted truth",
        );
    }
    if context_str(presented, "/read_state_root") != truth.read_state_root {
        return FenceVerdict::refuse(
            "root",
            "the presented read state root does not match owner-derived read evidence",
        );
    }

    // Dimension 10 — effect state: exact payload, read posture at or above
    // the declared minimum, exact watermark, and an unexpired writer/timing
    // posture.
    if context_str(presented, "/exact_payload_hash") != truth.expected_payload_hash {
        return FenceVerdict::refuse(
            "effect_state",
            "the payload about to be transmitted is not the exact admitted payload",
        );
    }
    let minimum = fence
        .get("minimum_read_consistency")
        .and_then(Value::as_str)
        .and_then(read_consistency_rank)
        .unwrap_or(usize::MAX);
    let presented_rank = read_consistency_rank(context_str(presented, "/read_consistency"));
    if presented_rank.is_none_or(|rank| rank < minimum) {
        return FenceVerdict::refuse(
            "effect_state",
            "the presented read consistency is below the resource's declared minimum",
        );
    }
    if context_str(presented, "/read_watermark") != truth.read_watermark {
        return FenceVerdict::refuse(
            "effect_state",
            "the presented read watermark does not match owner-derived read evidence",
        );
    }
    if truth.now > context_str(presented, "/expires_at")
        || truth.now > context_str(presented, "/writer_lease_expires_at")
    {
        return FenceVerdict::refuse(
            "effect_state",
            "the fence context or writer lease has expired; an expired posture fails closed",
        );
    }
    let not_before = context_str(
        active,
        "/displaced_writer_fencing/effects_admissible_not_before",
    );
    if truth.now < not_before {
        return FenceVerdict::refuse(
            "effect_state",
            "consequential effects are not admissible before the displaced-writer wait-out",
        );
    }

    FenceVerdict::admit()
}

/// Build the PEP-generated fence context from server truth and the active
/// transition only. The caller contributes nothing but the effect payload
/// identity the PEP itself hashed.
#[allow(clippy::too_many_arguments)]
pub fn build_fence_context(
    truth: &FenceServerTruth<'_>,
    resource_id: &str,
    effect_kind: &str,
    idempotency_key: &str,
    writer_lease_expires_at: &str,
    expires_at: &str,
    temporal_validity_evaluation_ref: &str,
    temporal_validity_evaluation_hash: &str,
) -> Result<Value, String> {
    let active = truth
        .active_transition
        .ok_or("no admitted writer epoch is active; the System-scoped effect is unavailable")?;
    let fence = active
        .get("resource_fences")
        .and_then(Value::as_array)
        .and_then(|fences| {
            fences
                .iter()
                .find(|fence| fence.get("resource_id").and_then(Value::as_str) == Some(resource_id))
        })
        .ok_or("the resource carries no declared fence under the active writer epoch")?;
    let mut context = json!({
        "schema_version": "ioi.consequential-effect-fence-context.v1",
        "system_id": truth.system_id,
        "executing_node_id": truth.executing_node_id,
        "resource_id": resource_id,
        "effect_kind": effect_kind,
        "exact_payload_hash": truth.expected_payload_hash,
        "deployment_profile_root": truth.deployment_profile_root,
        "node_membership_epoch": active.pointer("/successor_writer/membership_epoch"),
        "node_membership_root": truth.node_membership_root,
        "writer_epoch_transition_ref": active.get("writer_epoch_transition_id"),
        "writer_epoch_transition_hash": active.get("writer_epoch_transition_hash"),
        "writer_epoch": active.pointer("/successor_writer/writer_epoch"),
        "writer_lease_expires_at": writer_lease_expires_at,
        "authority_grant_ref": active.pointer("/authority/authority_grant_refs/0"),
        "authority_revocation_snapshot_ref": active.pointer("/authority/authority_revocation_snapshot_ref"),
        "authority_revocation_epoch": truth.authority_revocation_epoch,
        "temporal_verification_profile_ref": active.pointer("/timing_evidence/temporal_verification_profile_ref"),
        "temporal_validity_evaluation_ref": temporal_validity_evaluation_ref,
        "temporal_validity_evaluation_hash": temporal_validity_evaluation_hash,
        "read_consistency": fence.get("minimum_read_consistency"),
        "read_watermark": truth.read_watermark,
        "read_state_root": truth.read_state_root,
        "idempotency_key": idempotency_key,
        "evaluated_at": truth.now,
        "expires_at": expires_at,
        "fence_commitment": Value::Null,
    });
    let commitment = fence_context_commitment(&context)?;
    context["fence_commitment"] = json!(commitment);
    validate_architecture_contract(FENCE_CONTEXT_CONTRACT, &context)
        .map_err(|error| format!("built fence context is invalid: {error}"))?;
    Ok(context)
}

/// One explicit custody disposition for one excluded operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LostSuffixEntryResolution {
    /// The exact excluded operation offset.
    pub operation_offset: u64,
    /// Explicit disposition: `resolved` or `refused`, never ambiguous.
    pub custody_status: String,
    /// Receipt binding this per-entry disposition.
    pub resolution_receipt_ref: String,
    /// Supporting evidence.
    #[serde(default)]
    pub resolution_evidence_refs: Vec<String>,
}

/// Apply explicit per-entry custody dispositions to one open lost-suffix
/// record, producing its successor revision. Entries can never be silently
/// dropped or silently replayed: the offset set is immutable, every named
/// disposition is explicit and receipted, an already-disposed entry is
/// immutable, and the record can only leave `open` when no entry remains
/// `retained_ambiguous`.
pub fn resolve_lost_suffix_record(
    current: &Value,
    resolutions: &[LostSuffixEntryResolution],
    resulting_status: &str,
    disposition_receipt_ref: &str,
) -> Result<Value, String> {
    validate_architecture_contract(LOST_SUFFIX_CONTRACT, current)
        .map_err(|error| format!("durable lost-suffix record is invalid: {error}"))?;
    if required_string(current, "/status")? != "open" {
        return Err("only an open lost-suffix record admits custody resolution".to_owned());
    }
    if resolutions.is_empty() {
        return Err("custody resolution requires at least one explicit disposition".to_owned());
    }
    if !canonical_ref(disposition_receipt_ref, &["receipt://"]) {
        return Err("disposition receipt ref is not canonical".to_owned());
    }
    let mut named: Vec<u64> = resolutions
        .iter()
        .map(|entry| entry.operation_offset)
        .collect();
    named.sort_unstable();
    named.dedup();
    if named.len() != resolutions.len() {
        return Err("an excluded operation is disposed twice in one resolution".to_owned());
    }
    let mut record = current.clone();
    let entries = record
        .pointer_mut("/excluded_suffix/entries")
        .and_then(Value::as_array_mut)
        .ok_or("lost-suffix record lacks its custody rows")?;
    let held: Vec<u64> = entries
        .iter()
        .filter_map(|entry| entry.get("operation_offset").and_then(Value::as_u64))
        .collect();
    for resolution in resolutions {
        if !matches!(resolution.custody_status.as_str(), "resolved" | "refused") {
            return Err(
                "a custody disposition must be explicit: resolved or refused, never ambiguous"
                    .to_owned(),
            );
        }
        if !canonical_ref(&resolution.resolution_receipt_ref, &["receipt://"]) {
            return Err("a per-entry resolution receipt ref is not canonical".to_owned());
        }
        ensure_distinct(&resolution.resolution_evidence_refs, "resolution evidence")?;
        if !held.contains(&resolution.operation_offset) {
            return Err(format!(
                "offset {} is not part of the retained excluded suffix",
                resolution.operation_offset
            ));
        }
        let entry = entries
            .iter_mut()
            .find(|entry| {
                entry.get("operation_offset").and_then(Value::as_u64)
                    == Some(resolution.operation_offset)
            })
            .expect("offset membership was checked");
        if entry.get("custody_status").and_then(Value::as_str) != Some("retained_ambiguous") {
            return Err(format!(
                "offset {} already carries an explicit custody disposition; custody is immutable \
                 once disposed",
                resolution.operation_offset
            ));
        }
        entry["custody_status"] = json!(resolution.custody_status);
        entry["resolution_receipt_ref"] = json!(resolution.resolution_receipt_ref);
        entry["resolution_evidence_refs"] = json!(resolution.resolution_evidence_refs);
    }
    let remaining_ambiguous = entries.iter().any(|entry| {
        entry.get("custody_status").and_then(Value::as_str) == Some("retained_ambiguous")
    });
    match resulting_status {
        "open" => {}
        "reconciled" | "adjudicated" | "closed" => {
            if remaining_ambiguous {
                return Err(
                    "the record cannot leave open while any entry remains retained_ambiguous"
                        .to_owned(),
                );
            }
        }
        _ => return Err("resulting status is not a declared member".to_owned()),
    }
    record["status"] = json!(resulting_status);
    let receipts = record
        .get_mut("disposition_receipt_refs")
        .and_then(Value::as_array_mut)
        .ok_or("lost-suffix record lacks its disposition receipts")?;
    if !receipts.iter().any(|held| held == disposition_receipt_ref) {
        receipts.push(json!(disposition_receipt_ref));
    }
    record["predecessor_record_root"] = json!(lost_suffix_record_root(current)?);
    validate_architecture_contract(LOST_SUFFIX_CONTRACT, &record)
        .map_err(|error| format!("resolved lost-suffix revision is invalid: {error}"))?;
    Ok(record)
}

/// Validate one ordering/finality recovery envelope against the active
/// ordering profile class. Single-writer profiles are structurally excluded:
/// their recovery is the writer-epoch transition family, never this envelope.
pub fn validate_ordering_finality_recovery(
    recovery: &Value,
    active_ordering_profile_kind: &str,
) -> Result<(), String> {
    validate_architecture_contract(ORDERING_RECOVERY_CONTRACT, recovery)
        .map_err(|error| format!("ordering recovery is invalid: {error}"))?;
    if matches!(
        active_ordering_profile_kind,
        "single_authority" | "replicated_single_authority"
    ) {
        return Err(
            "single-writer recovery uses the writer-epoch transition family, never an ordering \
             recovery envelope"
                .to_owned(),
        );
    }
    if recovery
        .pointer("/predecessor/membership_root")
        .and_then(Value::as_str)
        != recovery
            .pointer("/transition/expected_membership_root")
            .and_then(Value::as_str)
    {
        return Err(
            "the recovery's compare-and-swap membership input detaches from its predecessor"
                .to_owned(),
        );
    }
    Ok(())
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

    const SYSTEM: &str = "system://acme/system-alpha";
    const NODE_A: &str = "node://acme/system-alpha/alpha-node-1";
    const NODE_B: &str = "node://acme/system-alpha/beta-node-2";

    fn binding() -> WriterIdentityBinding {
        WriterIdentityBinding {
            system_id: SYSTEM.into(),
            genesis_ref: "genesis://acme/system-alpha".into(),
            source_governing_authority_ref: "org://acme/research".into(),
            deployment_profile_ref: format!(
                "deployment-profile://acme/system-alpha/revision/sha256:{}",
                "a".repeat(64)
            ),
            deployment_profile_root: format!("sha256:{}", "d".repeat(64)),
            ordering_profile_ref: "ordering-profile://acme/system-alpha/single-writer-v1".into(),
            ordering_profile_root: h(0x2F),
            authority_revocation_snapshot_ref: "snapshot://acme/authority-revocation/12".into(),
            authority_revocation_epoch: 12,
        }
    }

    fn failover(mechanism: &str) -> Value {
        let mut profile = json!({
            "schema_version": "ioi.autonomous-system-failover-profile.v1",
            "failover_profile_id": "failover-profile://acme/system-alpha/primary",
            "system_id": SYSTEM,
            "version": "1.0.0",
            "response_authorization_mode": "manual_governance",
            "recovery_mechanism": mechanism,
            "ambiguous_partition_response": "fail_closed",
            "deployment_timing_assumptions": {
                "evidence_mode": "bounded_clock_partial_synchrony",
                "temporal_verification_profile_ref": "policy://acme/temporal/writer-v1",
                "maximum_clock_skew_or_uncertainty_ms": 250,
                "heartbeat_interval_ms": 1000,
                "heartbeat_evidence_expires_after_ms": 3000,
                "writer_lease_ttl_ms": 10000,
                "writer_lease_renewal_margin_ms": 2500,
                "maximum_effect_lease_ttl_ms": 5000,
                "maximum_revocation_propagation_ms": 1000,
                "promotion_waitout_policy_ref": "policy://acme/writer/waitout-v1",
            },
            "durable_continuity_cas": {
                "mechanism": "wallet_epoch_authority",
                "substrate_ref": "wallet://wallet.network/acme",
                "head_namespace": "acme/system-alpha/writer",
                "cas_proof_schema_ref": "schema://ioi/foundations/autonomous-system-writer-epoch-transition/v1",
                "minimum_independent_witnesses": 0,
                "unavailable_or_ambiguous_response": "fail_closed",
            },
            "single_writer_restore": Value::Null,
            "single_writer_promotion": Value::Null,
            "ordering_profile_recovery": Value::Null,
            "status": "active",
        });
        match mechanism {
            "single_writer_restore" => {
                profile["single_writer_restore"] = json!({
                    "recovery_target": "same_admitted_node",
                    "restore_policy_ref": "policy://acme/writer/restore-v1",
                    "require_verified_resulting_state_root": true,
                    "require_writer_epoch_increment": true,
                    "require_displaced_writer_fencing": true,
                });
            }
            "single_writer_promotion" => {
                profile["single_writer_promotion"] = json!({
                    "candidate_role": "hot_standby",
                    "minimum_durability": "device_flush",
                    "require_latest_verified_state_root": true,
                    "require_catchup_receipt": true,
                    "require_writer_epoch_increment": true,
                    "require_old_writer_fencing": true,
                    "promotion_policy_ref": "policy://acme/writer/promotion-v1",
                });
            }
            _ => {}
        }
        profile
    }

    fn membership_record(node_id: &str, tail: &str, epoch: u64, roles: &[&str]) -> Value {
        let assignments: Vec<Value> = roles
            .iter()
            .map(|role| {
                json!({
                    "role": role,
                    "role_scope_refs": [],
                    "authority_grant_refs": [],
                    "role_lease_ref": Value::Null,
                    "admitted_epoch": epoch,
                    "valid_from": Value::Null,
                    "expires_at": Value::Null,
                })
            })
            .collect();
        json!({
            "schema_version": "ioi.autonomous-system-node-membership.v1",
            "node_membership_id": format!("node-membership://acme/system-alpha/node/{tail}"),
            "system_id": SYSTEM,
            "deployment_profile_ref": binding().deployment_profile_ref,
            "node_id": node_id,
            "node_owner_ref": "wallet://acme/node-owner",
            "membership_epoch": epoch,
            "membership_lease_ref": format!("lease://acme/system-alpha/membership/{tail}"),
            "role_assignments": assignments,
            "failure_domain_refs": [],
            "failure_independence_evidence_refs": [],
            "node_attestation_refs": [format!("attestation://acme/{tail}/boot")],
            "conformance_profile_refs": [],
            "admission": {
                "proposal_ref": format!("proposal://acme/system-alpha/membership/{tail}"),
                "decision_ref": format!("decision://acme/system-alpha/membership/{tail}"),
                "admitted_constitution_root": h(0x0B),
                "admitted_manifest_root": h(0x0C),
                "admitted_deployment_profile_root": binding().deployment_profile_root,
            },
            "synchronization": {
                "checkpoint_ref": Value::Null,
                "operation_offset": 7,
                "verified_state_root": h(0x0E),
                "catchup_receipt_ref": format!("receipt://acme/system-alpha/catchup/{tail}/7"),
                "verified_at": Value::Null,
            },
            "writer_fencing": {
                "writer_epoch": Value::Null,
                "writer_epoch_transition_ref": Value::Null,
                "writer_epoch_transition_hash": Value::Null,
                "writer_lease_ref": Value::Null,
                "promotion_receipt_ref": Value::Null,
            },
            "observation": {
                "readiness": "ready",
                "health_observation_ref": Value::Null,
                "heartbeat_ref": Value::Null,
                "readiness_evidence_refs": [format!("attestation://acme/{tail}/readiness/7")],
                "last_heartbeat_at": Value::Null,
                "last_observed_at": "2026-07-28T11:59:00Z",
                "observation_expires_at": "2026-07-28T13:59:00Z",
                "status": Value::Null,
            },
            "status": "active",
        })
    }

    fn fix_membership(mut record: Value) -> Value {
        // Drop the placeholder inserted above (observation has no status
        // field in the contract).
        record["observation"]
            .as_object_mut()
            .expect("observation object")
            .remove("status");
        record
    }

    fn member(node_id: &str, tail: &str, epoch: u64, roles: &[&str]) -> Value {
        fix_membership(membership_record(node_id, tail, epoch, roles))
    }

    fn attested_node() -> Value {
        fixture("hypervisoros-node-v1/positive-ready.json")
    }

    fn catchup_receipt(node_id: &str, tail: &str) -> Value {
        json!({
            "receipt_ref": format!("receipt://acme/system-alpha/catchup/{tail}/7"),
            "node_id": node_id,
            "operation_offset": 7,
            "verified_state_root": h(0x0E),
            "checkpoint_ref": Value::Null,
        })
    }

    fn temporal_profile() -> Value {
        fixture("temporal-verification-profile-v1/positive-declared.json")
    }

    fn evaluation_hash_for(evaluation: &Value) -> String {
        jcs_hash(&json!({
            "domain": "ioi.temporal-validity-evaluation-hash-jcs-sha256.v1",
            "evaluation_id": evaluation["evaluation_id"],
            "profile_ref": evaluation["profile_ref"],
            "profile_hash": evaluation["profile_hash"],
            "subject_ref": evaluation["subject_ref"],
            "subject_hash": evaluation["subject_hash"],
            "operation_class": evaluation["operation_class"],
            "evidence_refs": evaluation["evidence_refs"],
            "source_failure_domain_refs": evaluation["source_failure_domain_refs"],
            "claims": evaluation["claims"],
            "temporal_posture": evaluation["temporal_posture"],
            "evidence_horizon": evaluation["evidence_horizon"],
            "invalidation_triggers": evaluation["invalidation_triggers"],
            "obligations": evaluation["obligations"],
        }))
        .expect("evaluation hash")
    }

    fn temporal_evaluation(subject_ref: &str, subject_hash: &str, tail: &str) -> Value {
        let profile = temporal_profile();
        let mut evaluation = fixture("temporal-validity-evaluation-v1/positive-online-fresh.json");
        evaluation["evaluation_id"] = json!(format!(
            "temporal-evaluation://acme/system-alpha/writer/{tail}"
        ));
        evaluation["profile_ref"] = profile["profile_ref"].clone();
        evaluation["profile_hash"] = profile["profile_hash"].clone();
        evaluation["subject_ref"] = json!(subject_ref);
        evaluation["subject_hash"] = json!(subject_hash);
        // Only the profile's required claims must be established; keep the
        // fixture rows and rebind the horizon for this test clock.
        evaluation["evidence_horizon"] = json!({
            "valid_from": "2026-07-28T12:00:00Z",
            "valid_until": "2026-07-28T12:30:00Z",
        });
        evaluation["evaluation_hash"] = json!(evaluation_hash_for(&evaluation));
        evaluation
    }

    fn declaration(
        node_id: &str,
        tail: &str,
        membership_root: &str,
    ) -> WriterTransitionDeclaration {
        WriterTransitionDeclaration {
            candidate_node_id: node_id.into(),
            expected_predecessor_transition_hash: None,
            expected_membership_root: membership_root.into(),
            writer_lease_ref: format!("lease://acme/system-alpha/writer/{tail}"),
            catchup_receipt_ref: format!("receipt://acme/system-alpha/catchup/{tail}/7"),
            state_root_verification_ref: format!(
                "verification://acme/system-alpha/state-root/7-{tail}"
            ),
            attested_node_ref: attested_node()["node_record_id"]
                .as_str()
                .expect("node record id")
                .into(),
            temporal_validity_evaluation_ref: format!(
                "temporal-evaluation://acme/system-alpha/writer/{tail}"
            ),
            resource_fences: vec![ResourceFenceDeclaration {
                resource_id: "wallet.network/effects".into(),
                allowed_effect_kinds: vec!["external_effect".into()],
                minimum_read_consistency: "state_root_consistent".into(),
                read_watermark: "operation-offset:7".into(),
            }],
            evidence_refs: vec![],
        }
    }

    struct Setup {
        records: Vec<Value>,
        membership_root: String,
    }

    fn setup(roles_b: &[&str]) -> Setup {
        let records = vec![
            member(NODE_A, "alpha-node-1", 3, &["state_replica"]),
            member(NODE_B, "beta-node-2", 5, roles_b),
        ];
        let membership_root =
            super::super::system_membership_transitions::membership_set_root(SYSTEM, &records)
                .expect("set root");
        Setup {
            records,
            membership_root,
        }
    }

    fn compile_genesis(setup: &Setup) -> CompiledWriterTransitionPlan {
        let record_root = membership_record_root(&setup.records[0]).expect("record root");
        compile_writer_epoch_transition_plan(
            WriterEpochTransitionKind::Genesis,
            &binding(),
            &failover("unavailable_fail_closed"),
            &setup.records,
            &setup.membership_root,
            &WriterFenceHead {
                active_epoch: 0,
                active_transition: None,
            },
            &declaration(NODE_A, "alpha-node-1", &setup.membership_root),
            &attested_node(),
            &catchup_receipt(NODE_A, "alpha-node-1"),
            &temporal_profile(),
            &temporal_evaluation(NODE_A, &record_root, "alpha-node-1"),
            None,
            None,
        )
        .expect("genesis compiles")
    }

    fn committed_genesis(setup: &Setup) -> Value {
        let plan = compile_genesis(setup);
        build_writer_transition_envelope(
            &plan,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:05Z",
        )
        .expect("genesis builds")
        .transition
    }

    fn displaced() -> DisplacedWriterObservation {
        DisplacedWriterObservation {
            writer_fence_receipt_refs: vec![
                "receipt://acme/system-alpha/writer/fence/epoch-1".into()
            ],
            effect_lease_fence_receipt_refs: vec![
                "receipt://acme/system-alpha/writer/effect-fence/epoch-1".into(),
            ],
            displaced_writer_leases_expire_at: "2026-07-28T12:00:20Z".into(),
            revocation_propagation_complete_at: "2026-07-28T12:00:10Z".into(),
            maximum_clock_skew_or_uncertainty_ms: 250,
            witness_evidence_refs: vec![],
        }
    }

    fn prior_log() -> PriorWriterLogObservation {
        PriorWriterLogObservation {
            last_common_offset: 7,
            last_common_state_root: h(0x0E),
            acknowledged_offset: 9,
            authoritative_head_offset: 7,
            authoritative_head_state_root: h(0x0E),
            entry_commitment_refs: vec![
                (8, "commitment://acme/system-alpha/op/8".into()),
                (9, "commitment://acme/system-alpha/op/9".into()),
            ],
            custody_artifact_refs: vec![
                "artifact://acme/system-alpha/lost-suffix/epoch-2/bytes".into()
            ],
            acknowledgement_certainty: SuffixAcknowledgementCertainty::Ambiguous,
            reconciliation_policy_ref: "policy://acme/lost-suffix/reconciliation-v1".into(),
        }
    }

    fn compile_promotion(
        setup: &Setup,
        genesis: &Value,
        with_suffix: bool,
    ) -> Result<CompiledWriterTransitionPlan, String> {
        let record_root = membership_record_root(&setup.records[1]).expect("record root");
        let mut promote = declaration(NODE_B, "beta-node-2", &setup.membership_root);
        promote.expected_predecessor_transition_hash = Some(
            genesis["writer_epoch_transition_hash"]
                .as_str()
                .expect("hash")
                .to_owned(),
        );
        compile_writer_epoch_transition_plan(
            WriterEpochTransitionKind::Promotion,
            &binding(),
            &failover("single_writer_promotion"),
            &setup.records,
            &setup.membership_root,
            &WriterFenceHead {
                active_epoch: 1,
                active_transition: Some(genesis.clone()),
            },
            &promote,
            &attested_node(),
            &catchup_receipt(NODE_B, "beta-node-2"),
            &temporal_profile(),
            &temporal_evaluation(NODE_B, &record_root, "beta-node-2"),
            Some(&displaced()),
            with_suffix.then(prior_log).as_ref(),
        )
    }

    fn truth_for<'a>(
        setup: &'a Setup,
        active: Option<&'a Value>,
        executing_node_id: &'a str,
    ) -> FenceServerTruth<'a> {
        FenceServerTruth {
            system_id: SYSTEM,
            executing_node_id,
            active_transition: active,
            node_membership_root: &setup.membership_root,
            deployment_profile_root:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            authority_revocation_epoch: 12,
            read_state_root:
                "sha256:0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
            read_watermark: "operation-offset:7",
            expected_payload_hash:
                "sha256:6161616161616161616161616161616161616161616161616161616161616161",
            now: "2026-07-28T12:00:06Z",
        }
    }

    fn pep_context(truth: &FenceServerTruth<'_>) -> Value {
        build_fence_context(
            truth,
            "wallet.network/effects",
            "external_effect",
            "effect-1",
            "2026-07-28T12:03:00Z",
            "2026-07-28T12:00:36Z",
            "temporal-evaluation://acme/system-alpha/effect/1",
            &h(0x4E),
        )
        .expect("PEP context builds")
    }

    #[test]
    fn scopes_are_distinct_and_never_reuse_prior_families() {
        let mut scopes: Vec<String> = WriterEpochTransitionKind::ALL
            .into_iter()
            .map(|kind| kind.required_scope().to_owned())
            .collect();
        scopes.push(DECLARE_FAILOVER_PROFILE_SCOPE.to_owned());
        scopes.push(RESOLVE_LOST_SUFFIX_SCOPE.to_owned());
        let declared = scopes.len();
        scopes.sort();
        scopes.dedup();
        assert_eq!(scopes.len(), declared);
        assert!(scopes.iter().all(|scope| {
            scope.starts_with("scope:autonomous_system.writer.")
                && !scope.starts_with("scope:autonomous_system.lifecycle.")
                && !scope.starts_with("scope:autonomous_system.continuity.")
                && !scope.starts_with("scope:autonomous_system.membership.")
                && !scope.starts_with("scope:hypervisoros.node.")
        }));
        for kind in WriterEpochTransitionKind::ALL {
            assert!(
                super::super::system_membership_transitions::MembershipTransitionOp::parse(
                    kind.as_str()
                )
                .is_none()
            );
        }
    }

    #[test]
    fn registered_positive_fixtures_recompute_their_commitments() {
        for path in [
            "autonomous-system-writer-epoch-transition-v1/positive-genesis.json",
            "autonomous-system-writer-epoch-transition-v1/positive-promotion.json",
        ] {
            let transition = fixture(path);
            let commitment = writer_transition_commitment(&transition).expect("commitment");
            assert_eq!(
                transition["writer_epoch_transition_hash"].as_str(),
                Some(commitment.as_str()),
                "{path}"
            );
            assert_eq!(
                transition["continuity_cas"]["resulting_head"].as_str(),
                Some(commitment.as_str()),
                "{path}"
            );
        }
        let context = fixture("consequential-effect-fence-context-v1/positive-active-writer.json");
        let commitment = fence_context_commitment(&context).expect("fence commitment");
        assert_eq!(
            context["fence_commitment"].as_str(),
            Some(commitment.as_str())
        );
    }

    #[test]
    fn genesis_claim_compiles_and_the_fence_admits_exactly_the_active_writer() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        assert_eq!(genesis["transition_kind"], "genesis");
        assert_eq!(genesis["successor_writer"]["writer_epoch"], 1);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);
        let context = pep_context(&truth);
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert!(verdict.admitted, "{:?}", verdict.refusal_reason);
        assert_eq!(verdict.selected_final_invokers, 1);
    }

    // Fence dimension 1 — caller-authored.
    #[test]
    fn caller_authored_fence_context_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);
        let context = pep_context(&truth);

        // A caller-supplied context is refused before any field comparison.
        let verdict = evaluate_consequential_effect_fence(
            &truth,
            &context,
            FenceContextOrigin::CallerSupplied,
        );
        assert_eq!(verdict.refusal_dimension, Some("caller_authored"));
        assert_eq!(verdict.selected_final_invokers, 0);

        // A substituted field breaks the recomputable fence commitment.
        let mut tampered = context.clone();
        tampered["resource_id"] = json!("wallet.network/other-resource");
        let verdict = evaluate_consequential_effect_fence(
            &truth,
            &tampered,
            FenceContextOrigin::PepGenerated,
        );
        assert_eq!(verdict.refusal_dimension, Some("caller_authored"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 2 — stale epoch.
    #[test]
    fn stale_writer_epoch_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);
        let stale_context = pep_context(&truth);

        let plan = compile_promotion(&setup, &genesis, false).expect("promotion compiles");
        let promotion = build_writer_transition_envelope(
            &plan,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:07Z",
        )
        .expect("promotion builds")
        .transition;
        // The old writer's own PEP still holds the epoch-1 context; against
        // the advanced fence it is stale before any node comparison.
        let mut truth_after = truth_for(&setup, Some(&promotion), NODE_A);
        truth_after.now = "2026-07-28T12:00:21Z";
        let verdict = evaluate_consequential_effect_fence(
            &truth_after,
            &stale_context,
            FenceContextOrigin::PepGenerated,
        );
        assert_eq!(verdict.refusal_dimension, Some("stale"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 3 — foreign node.
    #[test]
    fn foreign_node_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);
        let context = pep_context(&truth);
        // The same context evaluated on a node that is neither the active
        // writer nor the displaced prior writer: foreign.
        let mut foreign_truth = truth_for(&setup, Some(&genesis), NODE_B);
        foreign_truth.now = truth.now;
        let mut foreign_context = context.clone();
        foreign_context["executing_node_id"] = json!(NODE_B);
        foreign_context["fence_commitment"] =
            json!(fence_context_commitment(&foreign_context).expect("commitment"));
        let verdict = evaluate_consequential_effect_fence(
            &foreign_truth,
            &foreign_context,
            FenceContextOrigin::PepGenerated,
        );
        assert_eq!(verdict.refusal_dimension, Some("foreign"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 4 — deposed writer.
    #[test]
    fn deposed_writer_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let plan = compile_promotion(&setup, &genesis, false).expect("promotion compiles");
        let promotion = build_writer_transition_envelope(
            &plan,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:07Z",
        )
        .expect("promotion builds")
        .transition;
        // The former writer (alpha) presents a context freshly rebuilt at the
        // NEW epoch; the fence still refuses it as deposed because the
        // executing node is the displaced prior writer.
        let mut deposed_truth = truth_for(&setup, Some(&promotion), NODE_A);
        deposed_truth.now = "2026-07-28T12:00:21Z";
        let mut context = build_fence_context(
            &deposed_truth,
            "wallet.network/effects",
            "external_effect",
            "effect-2",
            "2026-07-28T12:03:00Z",
            "2026-07-28T12:00:36Z",
            "temporal-evaluation://acme/system-alpha/effect/2",
            &h(0x4E),
        )
        .expect("context builds");
        context["executing_node_id"] = json!(NODE_A);
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict = evaluate_consequential_effect_fence(
            &deposed_truth,
            &context,
            FenceContextOrigin::PepGenerated,
        );
        assert_eq!(verdict.refusal_dimension, Some("deposed"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 5 — mismatched membership state.
    #[test]
    fn mismatched_membership_state_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);
        let mut context = pep_context(&truth);
        context["node_membership_root"] = json!(h(0x77));
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("membership"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 6 — mismatched epoch state.
    #[test]
    fn mismatched_epoch_state_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);

        // A fabricated higher epoch durable truth never admitted.
        let mut context = pep_context(&truth);
        context["writer_epoch"] = json!(7);
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("epoch"));
        assert_eq!(verdict.selected_final_invokers, 0);

        // The right number over the wrong immutable transition.
        let mut context = pep_context(&truth);
        context["writer_epoch_transition_hash"] = json!(h(0x66));
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("epoch"));
        assert_eq!(verdict.selected_final_invokers, 0);

        // No active writer at all.
        let empty_truth = truth_for(&setup, None, NODE_A);
        let verdict = evaluate_consequential_effect_fence(
            &empty_truth,
            &pep_context(&truth),
            FenceContextOrigin::PepGenerated,
        );
        assert_eq!(verdict.refusal_dimension, Some("epoch"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 7 — mismatched resource state.
    #[test]
    fn mismatched_resource_state_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);

        // An unfenced resource.
        assert!(build_fence_context(
            &truth,
            "wallet.network/unfenced-resource",
            "external_effect",
            "effect-3",
            "2026-07-28T12:03:00Z",
            "2026-07-28T12:00:36Z",
            "temporal-evaluation://acme/system-alpha/effect/3",
            &h(0x4E),
        )
        .is_err());
        let mut context = pep_context(&truth);
        context["resource_id"] = json!("wallet.network/unfenced-resource");
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("resource"));
        assert_eq!(verdict.selected_final_invokers, 0);

        // An effect kind the fence does not admit.
        let mut context = pep_context(&truth);
        context["effect_kind"] = json!("settlement");
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("resource"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 8 — mismatched grant state.
    #[test]
    fn mismatched_grant_state_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);

        let mut context = pep_context(&truth);
        context["authority_grant_ref"] =
            json!(format!("grant://wallet.network/approval/{}", h(0x99)));
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("grant"));
        assert_eq!(verdict.selected_final_invokers, 0);

        // A revocation epoch behind current authority truth.
        let mut regressed_truth = truth_for(&setup, Some(&genesis), NODE_A);
        regressed_truth.authority_revocation_epoch = 13;
        let verdict = evaluate_consequential_effect_fence(
            &regressed_truth,
            &pep_context(&truth),
            FenceContextOrigin::PepGenerated,
        );
        assert_eq!(verdict.refusal_dimension, Some("grant"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 9 — mismatched root state.
    #[test]
    fn mismatched_root_state_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);

        let mut context = pep_context(&truth);
        context["deployment_profile_root"] = json!(h(0x88));
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("root"));
        assert_eq!(verdict.selected_final_invokers, 0);

        let mut context = pep_context(&truth);
        context["read_state_root"] = json!(h(0x89));
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("root"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    // Fence dimension 10 — mismatched effect state.
    #[test]
    fn mismatched_effect_state_reaches_zero_selected_final_invokers() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let truth = truth_for(&setup, Some(&genesis), NODE_A);

        // Substituted payload.
        let mut context = pep_context(&truth);
        context["exact_payload_hash"] = json!(h(0x90));
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("effect_state"));
        assert_eq!(verdict.selected_final_invokers, 0);

        // Read posture below the declared minimum.
        let mut context = pep_context(&truth);
        context["read_consistency"] = json!("cached_projection");
        context["fence_commitment"] =
            json!(fence_context_commitment(&context).expect("commitment"));
        let verdict =
            evaluate_consequential_effect_fence(&truth, &context, FenceContextOrigin::PepGenerated);
        assert_eq!(verdict.refusal_dimension, Some("effect_state"));
        assert_eq!(verdict.selected_final_invokers, 0);

        // Expired context.
        let mut expired_truth = truth_for(&setup, Some(&genesis), NODE_A);
        expired_truth.now = "2026-07-28T12:10:00Z";
        let verdict = evaluate_consequential_effect_fence(
            &expired_truth,
            &pep_context(&truth),
            FenceContextOrigin::PepGenerated,
        );
        assert_eq!(verdict.refusal_dimension, Some("effect_state"));
        assert_eq!(verdict.selected_final_invokers, 0);
    }

    #[test]
    fn caller_asserted_writer_fields_are_refused_by_the_closed_declaration() {
        let error = serde_json::from_value::<WriterTransitionDeclaration>(json!({
            "candidate_node_id": NODE_A,
            "expected_membership_root": h(0x31),
            "writer_lease_ref": "lease://acme/system-alpha/writer/alpha-node-1",
            "catchup_receipt_ref": "receipt://acme/system-alpha/catchup/alpha-node-1/7",
            "state_root_verification_ref": "verification://acme/system-alpha/state-root/7",
            "attested_node_ref": "hypervisoros-node://acme/estate-1/node/alpha-node-1",
            "temporal_validity_evaluation_ref": "temporal-evaluation://acme/writer/1",
            "writer_epoch": 7,
        }))
        .expect_err("caller-authored epoch must be refused");
        assert!(error.to_string().contains("writer_epoch"));
    }

    #[test]
    fn stale_predecessor_transition_is_refused() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let record_root = membership_record_root(&setup.records[1]).expect("record root");
        let mut promote = declaration(NODE_B, "beta-node-2", &setup.membership_root);
        promote.expected_predecessor_transition_hash = Some(h(0x99));
        let error = compile_writer_epoch_transition_plan(
            WriterEpochTransitionKind::Promotion,
            &binding(),
            &failover("single_writer_promotion"),
            &setup.records,
            &setup.membership_root,
            &WriterFenceHead {
                active_epoch: 1,
                active_transition: Some(genesis),
            },
            &promote,
            &attested_node(),
            &catchup_receipt(NODE_B, "beta-node-2"),
            &temporal_profile(),
            &temporal_evaluation(NODE_B, &record_root, "beta-node-2"),
            Some(&displaced()),
            None,
        )
        .expect_err("stale CAS must refuse");
        assert!(error.contains("stale predecessor writer-epoch transition"));
    }

    #[test]
    fn foreign_candidate_and_unready_attestation_are_refused() {
        let setup = setup(&["hot_standby"]);
        let mut foreign = declaration(NODE_A, "alpha-node-1", &setup.membership_root);
        foreign.candidate_node_id = "node://mallory/other-system/intruder".into();
        let record_root = membership_record_root(&setup.records[0]).expect("record root");
        let error = compile_writer_epoch_transition_plan(
            WriterEpochTransitionKind::Genesis,
            &binding(),
            &failover("unavailable_fail_closed"),
            &setup.records,
            &setup.membership_root,
            &WriterFenceHead {
                active_epoch: 0,
                active_transition: None,
            },
            &foreign,
            &attested_node(),
            &catchup_receipt(NODE_A, "alpha-node-1"),
            &temporal_profile(),
            &temporal_evaluation(NODE_A, &record_root, "alpha-node-1"),
            None,
            None,
        )
        .expect_err("foreign candidate must refuse");
        assert!(error.contains("outside the System namespace"));

        let mut unready = attested_node();
        unready["status"] = json!("quarantined");
        // A quarantined record is still contract-valid, so the refusal is the
        // named verified-ready gate.
        let error = compile_writer_epoch_transition_plan(
            WriterEpochTransitionKind::Genesis,
            &binding(),
            &failover("unavailable_fail_closed"),
            &setup.records,
            &setup.membership_root,
            &WriterFenceHead {
                active_epoch: 0,
                active_transition: None,
            },
            &declaration(NODE_A, "alpha-node-1", &setup.membership_root),
            &unready,
            &catchup_receipt(NODE_A, "alpha-node-1"),
            &temporal_profile(),
            &temporal_evaluation(NODE_A, &record_root, "alpha-node-1"),
            None,
            None,
        )
        .expect_err("unready attestation must refuse");
        assert!(error.contains("not verified-ready"));
    }

    #[test]
    fn double_claim_cas_race_settles_to_exactly_one_writer() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);

        // Two racing promotions compile from the same head; the first commits.
        let first = compile_promotion(&setup, &genesis, false).expect("first claim compiles");
        let second = compile_promotion(&setup, &genesis, false).expect("second claim compiles");
        let committed = build_writer_transition_envelope(
            &first,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:07Z",
        )
        .expect("first claim commits");

        // The loser now recompiles against durable truth: its CAS view is
        // stale, so zero second writers are admitted.
        let head = replay_writer_epoch_transitions(
            SYSTEM,
            &[genesis.clone(), committed.transition.clone()],
        )
        .expect("replay");
        assert_eq!(head.active_epoch, 2);
        let record_root = membership_record_root(&setup.records[1]).expect("record root");
        let mut loser = declaration(NODE_B, "beta-node-2", &setup.membership_root);
        loser.expected_predecessor_transition_hash = second.predecessor_transition_hash.clone();
        let error = compile_writer_epoch_transition_plan(
            WriterEpochTransitionKind::Promotion,
            &binding(),
            &failover("single_writer_promotion"),
            &setup.records,
            &setup.membership_root,
            &head,
            &loser,
            &attested_node(),
            &catchup_receipt(NODE_B, "beta-node-2"),
            &temporal_profile(),
            &temporal_evaluation(NODE_B, &record_root, "beta-node-2"),
            Some(&displaced()),
            None,
        )
        .expect_err("the losing claim must refuse");
        assert!(error.contains("stale predecessor writer-epoch transition"));

        // And the log itself refuses a fork at the same epoch.
        let fork = build_writer_transition_envelope(
            &second,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:08Z",
        )
        .expect("the fork can be built but never replayed");
        let error = replay_writer_epoch_transitions(
            SYSTEM,
            &[genesis, committed.transition, fork.transition],
        )
        .expect_err("a fork must refuse");
        assert!(error.contains("same epoch"));
    }

    #[test]
    fn the_writer_epoch_never_decreases_or_skips() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let plan = compile_promotion(&setup, &genesis, false).expect("promotion compiles");
        let promotion = build_writer_transition_envelope(
            &plan,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:07Z",
        )
        .expect("promotion builds")
        .transition;

        // A gap: epoch 2 without epoch 1.
        let error = replay_writer_epoch_transitions(SYSTEM, &[promotion.clone()])
            .expect_err("a gap must refuse");
        assert!(error.contains("genesis claim") || error.contains("gap"));

        // Tampered epoch inside a committed transition breaks its commitment
        // (and, if it survived that, the contiguity rule).
        let mut tampered = promotion.clone();
        tampered["successor_writer"]["writer_epoch"] = json!(3);
        let error = replay_writer_epoch_transitions(SYSTEM, &[genesis.clone(), tampered])
            .expect_err("a tampered epoch must refuse");
        assert!(
            error.contains("gap") || error.contains("tampered") || error.contains("invalid"),
            "{error}"
        );

        // The committed pair replays to the exact head.
        let head = replay_writer_epoch_transitions(SYSTEM, &[genesis, promotion]).expect("replay");
        assert_eq!(head.active_epoch, 2);
    }

    #[test]
    fn the_lost_suffix_is_captured_and_bound_to_both_epochs() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let plan = compile_promotion(&setup, &genesis, true).expect("promotion compiles");
        let artifacts = build_writer_transition_envelope(
            &plan,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:07Z",
        )
        .expect("promotion builds");
        let (record, _root) = artifacts.lost_suffix.expect("suffix retained");
        assert_eq!(record["prior_writer_epoch"], 1);
        assert_eq!(record["successor_writer_epoch"], 2);
        assert_eq!(
            artifacts.transition["lost_suffix_record_ref"],
            record["lost_suffix_record_id"]
        );
        assert_eq!(record["excluded_suffix"]["operation_count"], 2);
        assert_eq!(record["status"], "open");
        assert!(record["excluded_suffix"]["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .all(|entry| entry["custody_status"] == "retained_ambiguous"));
    }

    #[test]
    fn lost_suffix_entries_cannot_be_silently_dropped() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let plan = compile_promotion(&setup, &genesis, true).expect("promotion compiles");
        let artifacts = build_writer_transition_envelope(
            &plan,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:07Z",
        )
        .expect("promotion builds");
        let (record, _) = artifacts.lost_suffix.expect("suffix retained");

        // Closing while any entry remains ambiguous is refused.
        let error = resolve_lost_suffix_record(
            &record,
            &[LostSuffixEntryResolution {
                operation_offset: 8,
                custody_status: "resolved".into(),
                resolution_receipt_ref: "receipt://acme/system-alpha/lost-suffix/epoch-2/op-8"
                    .into(),
                resolution_evidence_refs: vec![],
            }],
            "closed",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/disposition",
        )
        .expect_err("closing over ambiguity must refuse");
        assert!(error.contains("retained_ambiguous"));

        // An implicit (unnamed) disposition does not exist: an offset outside
        // the retained suffix is refused, and ambiguity is not a disposition.
        let error = resolve_lost_suffix_record(
            &record,
            &[LostSuffixEntryResolution {
                operation_offset: 11,
                custody_status: "resolved".into(),
                resolution_receipt_ref: "receipt://acme/system-alpha/lost-suffix/epoch-2/op-11"
                    .into(),
                resolution_evidence_refs: vec![],
            }],
            "open",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/disposition",
        )
        .expect_err("a foreign offset must refuse");
        assert!(error.contains("not part of the retained excluded suffix"));
        let error = resolve_lost_suffix_record(
            &record,
            &[LostSuffixEntryResolution {
                operation_offset: 8,
                custody_status: "retained_ambiguous".into(),
                resolution_receipt_ref: "receipt://acme/system-alpha/lost-suffix/epoch-2/op-8"
                    .into(),
                resolution_evidence_refs: vec![],
            }],
            "open",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/disposition",
        )
        .expect_err("ambiguity is not a disposition");
        assert!(error.contains("explicit"));

        // Explicit per-entry custody resolution, then closure.
        let partially = resolve_lost_suffix_record(
            &record,
            &[LostSuffixEntryResolution {
                operation_offset: 8,
                custody_status: "resolved".into(),
                resolution_receipt_ref: "receipt://acme/system-alpha/lost-suffix/epoch-2/op-8"
                    .into(),
                resolution_evidence_refs: vec![
                    "evidence://acme/system-alpha/lost-suffix/epoch-2/op-8".into(),
                ],
            }],
            "open",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/disposition",
        )
        .expect("partial resolution stays open");
        assert_eq!(partially["status"], "open");

        // A disposed entry is immutable.
        let error = resolve_lost_suffix_record(
            &partially,
            &[LostSuffixEntryResolution {
                operation_offset: 8,
                custody_status: "refused".into(),
                resolution_receipt_ref: "receipt://acme/system-alpha/lost-suffix/epoch-2/op-8b"
                    .into(),
                resolution_evidence_refs: vec![],
            }],
            "open",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/disposition",
        )
        .expect_err("re-disposing must refuse");
        assert!(error.contains("immutable"));

        let closed = resolve_lost_suffix_record(
            &partially,
            &[LostSuffixEntryResolution {
                operation_offset: 9,
                custody_status: "refused".into(),
                resolution_receipt_ref: "receipt://acme/system-alpha/lost-suffix/epoch-2/op-9"
                    .into(),
                resolution_evidence_refs: vec![],
            }],
            "reconciled",
            "receipt://acme/system-alpha/lost-suffix/epoch-2/disposition",
        )
        .expect("full resolution reconciles");
        assert_eq!(closed["status"], "reconciled");
        assert_eq!(closed["excluded_suffix"]["operation_count"], 2);
        // Revision lineage is compare-and-swap: each revision cites the exact
        // predecessor revision root.
        assert_eq!(
            partially["predecessor_record_root"],
            json!(lost_suffix_record_root(&record).expect("root"))
        );
        assert_eq!(
            closed["predecessor_record_root"],
            json!(lost_suffix_record_root(&partially).expect("root"))
        );
    }

    #[test]
    fn restart_rebuilds_the_fence_head_byte_exactly_from_durable_records() {
        let setup = setup(&["hot_standby"]);
        let genesis = committed_genesis(&setup);
        let plan = compile_promotion(&setup, &genesis, true).expect("promotion compiles");
        let artifacts = build_writer_transition_envelope(
            &plan,
            &format!("grant://wallet.network/approval/{}", h(0x54)),
            "2026-07-28T12:00:07Z",
        )
        .expect("promotion builds");
        let transitions = vec![genesis, artifacts.transition];
        let before = replay_writer_epoch_transitions(SYSTEM, &transitions).expect("replay");

        // Restart: only serialized durable bytes remain.
        let bytes: Vec<String> = transitions
            .iter()
            .map(|value| serde_json::to_string(value).expect("bytes"))
            .collect();
        drop(transitions);
        let reloaded: Vec<Value> = bytes
            .iter()
            .map(|value| serde_json::from_str(value).expect("stored transition"))
            .collect();
        let after = replay_writer_epoch_transitions(SYSTEM, &reloaded).expect("replay");
        assert_eq!(before, after);
        assert_eq!(
            serde_json::to_string(&before.active_transition).expect("bytes"),
            serde_json::to_string(&after.active_transition).expect("bytes"),
        );

        // The lost-suffix revision root is likewise recomputable byte-exactly.
        let (record, root) = artifacts.lost_suffix.expect("suffix retained");
        let stored: Value =
            serde_json::from_str(&serde_json::to_string(&record).expect("bytes")).expect("record");
        assert_eq!(lost_suffix_record_root(&stored).expect("root"), root);
    }

    #[test]
    fn ordering_recovery_never_covers_single_writer_profiles() {
        let recovery = fixture("ordering-finality-recovery-v1/positive-committed-bft.json");
        validate_ordering_finality_recovery(&recovery, "bft_consensus").expect("bft recovery");
        let error = validate_ordering_finality_recovery(&recovery, "replicated_single_authority")
            .expect_err("single-writer profiles use the writer family");
        assert!(error.contains("writer-epoch transition family"));
    }
}
