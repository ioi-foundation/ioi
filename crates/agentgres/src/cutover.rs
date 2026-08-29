//! Canonical Agentgres profile-cutover control plane.
//!
//! A cutover is not a configuration change. It is an admitted spine operation
//! that serializes through the same mux domain and object head as recognized
//! effects, so "which profile is active" and "which effects were recognized"
//! are one totally ordered history — never two clocks that can disagree.
//!
//! Three control operations exist, all on that one head:
//!
//! * `profile.genesis` — seals the initial profile, writer identity, and fence
//!   token. Sealed once; every later open must present byte-identical genesis.
//! * `profile.cutover` — moves to a successor profile epoch with a new writer
//!   identity and a strictly greater fence token.
//! * `profile.freeze` — retires the active writer without naming a successor.
//!   A frozen spine admits no new effect and no new writer.
//!
//! `INV-41` — one admission owner per domain; replacing it is a governed
//! cutover with no dual-authority interval. Local application: eligibility is
//! derived only from the single latest committed control record on this head,
//! so exactly one `(writer_identity, fence_token)` pair is eligible at any
//! point in the history and no interval exists in which two are.
//!
//! `INV-42` — upgrades do not expand authority; weakening a guarantee that
//! bounds authority takes its own governed path declaring all four of an
//! approval threshold, an enforced delay, a checkpoint pinning the exact
//! pre-change state, and a rollback or freeze executable without the changed
//! authority. Local application: `bft_consensus` -> `single_authority` relaxes
//! the ordering and finality guarantee, so it is refused unless all four are
//! present and separately validated ([`GovernanceValidator`]). The reverse
//! direction carries no such burden.
//!
//! The admitted record binds the six operation bindings named by the M04.9
//! finality-framework adjudication: previous and next canonical
//! profile/version; exact cutover epoch and canonical head; current authority
//! and governance evidence; prior-writer fencing; recovery and downgrade
//! behavior; availability and verifier requirements.
//!
//! Rollback is always forward. A cutover already followed by next-profile
//! effects is undone by a *successor* cutover or a freeze — never by deleting
//! admitted history and never by reviving a retired fence token. Both are
//! structurally impossible here: the spine is append-only through the mux, and
//! fence tokens must strictly increase.
//!
//! Nonclaim (local): the fence enforced here is spine-local. It is not the
//! per-System `AutonomousSystemWriterEpochTransition` fence, and it does not
//! constitute a bounded-DAS fencing plane — see the Agentgres doctrine's
//! separation of the mux epoch from a System writer epoch.

use crate::profile::{
    FinalityProfile, GuaranteeDelta, GuaranteeDirection, ProfileBindingsDigest, ProfileIdentity,
};
use crate::recognized_effect::{
    hash_value, validate_hash, validate_token, AuthoritySnapshot, ProfileRefusal,
    RecognizedEffectError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PROFILE_GENESIS_SCHEMA: &str = "ioi.agentgres-profile-genesis.v1";
pub const PROFILE_CUTOVER_SCHEMA: &str = "ioi.agentgres-profile-cutover.v1";
/// v2 adds the live authority/revocation snapshot. v1 carried only opaque
/// authorization references and is never reinterpreted as satisfying this
/// stronger admission contract.
pub const PROFILE_FREEZE_SCHEMA: &str = "ioi.agentgres-profile-freeze.v2";

pub const OP_KIND_GENESIS: &str = "profile.genesis";
pub const OP_KIND_CUTOVER: &str = "profile.cutover";
pub const OP_KIND_FREEZE: &str = "profile.freeze";
pub const OP_KIND_RECOGNIZED_EFFECT: &str = "recognized_effect.commit";

/// Separately validated governance evidence for an INV-42 weakening.
///
/// Every field is load-bearing and separately checked: a threshold with no
/// authorization refs, refs that do not meet the threshold, an evidence digest
/// the owner validator does not confirm, a delta digest that does not bind the
/// exact declared delta, an unmet delay, or an anchor that names no committed
/// checkpoint each produce a distinct refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvidence {
    pub governance_id: String,
    /// Digest of the owner-held evidence package. The owner validator must
    /// confirm this exact digest; it cannot approve a different package.
    pub evidence_digest: String,
    pub approval_threshold: u32,
    /// Distinct authorization refs. Count must meet the threshold.
    pub authorization_refs: Vec<String>,
    /// Earliest `recorded_at_ms` at which the weakening may commit.
    pub effective_after_ms: u64,
    /// A committed Agentgres batch this evidence was taken against.
    pub anchor_batch_seq: u64,
    pub anchor_root: String,
    /// Digest of the exact `GuaranteeDelta` this evidence approves.
    pub guarantee_delta_digest: String,
}

impl GovernanceEvidence {
    fn validate_shape(&self, delta: &GuaranteeDelta) -> Result<(), RecognizedEffectError> {
        validate_token("governance_id", &self.governance_id)?;
        validate_hash("evidence_digest", &self.evidence_digest)?;
        validate_hash("anchor_root", &self.anchor_root)?;
        validate_hash("guarantee_delta_digest", &self.guarantee_delta_digest)?;
        if self.approval_threshold == 0 {
            return Err(ProfileRefusal::GovernanceThresholdUnmet {
                approvals: 0,
                threshold: 0,
            }
            .into_error());
        }
        let mut distinct = BTreeSet::new();
        for reference in &self.authorization_refs {
            validate_token("authorization_ref", reference)?;
            if !distinct.insert(reference.as_str()) {
                return Err(ProfileRefusal::GovernanceEvidenceRejected {
                    detail: format!("duplicate authorization ref {reference}"),
                }
                .into_error());
            }
        }
        let approvals = u32::try_from(distinct.len()).unwrap_or(u32::MAX);
        if approvals < self.approval_threshold {
            return Err(ProfileRefusal::GovernanceThresholdUnmet {
                approvals,
                threshold: self.approval_threshold,
            }
            .into_error());
        }
        // The evidence approves one exact delta. A substituted delta — even a
        // reordering of the same guarantee names — no longer matches.
        let delta_digest = guarantee_delta_digest(delta)?;
        if delta_digest != self.guarantee_delta_digest {
            return Err(ProfileRefusal::GovernanceEvidenceRejected {
                detail: "governance evidence does not bind the declared guarantee delta".into(),
            }
            .into_error());
        }
        Ok(())
    }

    pub fn approvals(&self) -> u32 {
        u32::try_from(
            self.authorization_refs
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .unwrap_or(u32::MAX)
    }
}

/// Digest over the exact declared guarantee delta.
pub fn guarantee_delta_digest(delta: &GuaranteeDelta) -> Result<String, RecognizedEffectError> {
    hash_value(&serde_json::to_value(delta)?)
}

/// How a weakening is undone. Both forms move the spine forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackKind {
    /// A successor cutover back to the stronger profile.
    SuccessorCutover,
    /// A freeze: retire the writer, name no successor.
    Freeze,
}

/// The pre-declared, executable escape from a weakening.
///
/// The whole point is that it must not depend on the authority the weakening
/// installs. If the single authority you just cut over to is also the only
/// party who can undo it, you have no rollback — you have a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub kind: RollbackKind,
    /// Who executes the rollback. Must not be the incoming writer.
    pub executor_writer_identity: String,
    /// The executor's own authorization refs. Must not include the incoming
    /// writer identity.
    pub executor_authorization_refs: Vec<String>,
    /// Target profile for `SuccessorCutover`; absent for `Freeze`.
    pub target: Option<ProfileIdentity>,
    /// Explicit operator declaration, cross-checked structurally below.
    pub independent_of_new_authority: bool,
}

impl RollbackPlan {
    fn validate_shape(&self) -> Result<(), RecognizedEffectError> {
        validate_token("executor_writer_identity", &self.executor_writer_identity)?;
        let mut distinct = BTreeSet::new();
        for reference in &self.executor_authorization_refs {
            validate_token("executor_authorization_ref", reference)?;
            if !distinct.insert(reference.as_str()) {
                return Err(ProfileRefusal::RollbackPlanInvalid {
                    detail: format!("duplicate executor authorization ref {reference}"),
                }
                .into_error());
            }
        }
        match (self.kind, &self.target) {
            (RollbackKind::SuccessorCutover, Some(target)) => target.validate()?,
            (RollbackKind::SuccessorCutover, None) => {
                return Err(ProfileRefusal::RollbackPlanInvalid {
                    detail: "successor-cutover rollback names no target profile".into(),
                }
                .into_error())
            }
            (RollbackKind::Freeze, Some(_)) => {
                return Err(ProfileRefusal::RollbackPlanInvalid {
                    detail: "freeze rollback must not name a target profile".into(),
                }
                .into_error())
            }
            (RollbackKind::Freeze, None) => {}
        }
        Ok(())
    }

    /// Independence from the authority the weakening installs.
    fn validate_independence(
        &self,
        from: &ProfileIdentity,
        to_writer_identity: &str,
    ) -> Result<(), RecognizedEffectError> {
        if !self.independent_of_new_authority {
            return Err(ProfileRefusal::RollbackNotIndependent {
                detail: "rollback plan is not declared independent of the new authority".into(),
            }
            .into_error());
        }
        if self.executor_writer_identity == to_writer_identity {
            return Err(ProfileRefusal::RollbackNotIndependent {
                detail: format!(
                    "rollback executor {} is the incoming writer",
                    self.executor_writer_identity
                ),
            }
            .into_error());
        }
        if self
            .executor_authorization_refs
            .iter()
            .any(|reference| reference == to_writer_identity)
        {
            return Err(ProfileRefusal::RollbackNotIndependent {
                detail: "rollback authorization depends on the incoming writer".into(),
            }
            .into_error());
        }
        if self.executor_authorization_refs.is_empty() {
            return Err(ProfileRefusal::RollbackNotIndependent {
                detail: "rollback plan carries no independent authorization".into(),
            }
            .into_error());
        }
        if let (RollbackKind::SuccessorCutover, Some(target)) = (self.kind, &self.target) {
            if target.profile != from.profile {
                return Err(ProfileRefusal::RollbackPlanInvalid {
                    detail: format!(
                        "rollback target {} does not restore {}",
                        target.profile.profile(),
                        from.profile.profile()
                    ),
                }
                .into_error());
            }
        }
        Ok(())
    }
}

/// What an owner governance authority is asked to rule on.
#[derive(Clone, Debug)]
pub struct WeakeningReview<'a> {
    pub domain_id: &'a str,
    pub cutover_id: &'a str,
    pub from: &'a ProfileIdentity,
    pub to: &'a ProfileIdentity,
    pub from_writer_identity: &'a str,
    pub to_writer_identity: &'a str,
    pub guarantee_delta: &'a GuaranteeDelta,
    pub governance: &'a GovernanceEvidence,
    pub rollback: &'a RollbackPlan,
    pub recorded_at_ms: u64,
}

/// An owner authority's ruling. `evidence_digest` must echo the exact digest
/// under review, so a validator cannot approve a different package than the
/// one the cutover record binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceVerdict {
    pub approved: bool,
    pub approvals: u32,
    pub evidence_digest: String,
    pub detail: String,
}

/// The owner-implemented governance boundary for an INV-42 weakening.
///
/// Agentgres does not mint governance authority and cannot honestly evaluate
/// an owner's approval package: the signatures, quorum roster, and delegation
/// chain live outside this crate. This trait is that boundary. The default
/// production implementation refuses every weakening, so an unwired estate
/// fails closed rather than silently accepting one.
pub trait GovernanceValidator {
    fn validate_weakening(&self, review: &WeakeningReview<'_>)
        -> Result<GovernanceVerdict, String>;
}

/// Production default: no weakening is approved until an owner authority is
/// wired in. Refusing is the honest answer, not an outage.
pub struct RefuseAllWeakening;

impl GovernanceValidator for RefuseAllWeakening {
    fn validate_weakening(
        &self,
        _review: &WeakeningReview<'_>,
    ) -> Result<GovernanceVerdict, String> {
        Err("no governance authority is bound to this Agentgres spine".into())
    }
}

// ---------------------------------------------------------------------------
// Admitted control records
// ---------------------------------------------------------------------------

/// Sealed once, on the spine's first open. Re-opening with any different
/// genesis is refused rather than silently adopted — otherwise a restart could
/// substitute the active profile or the eligible writer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileGenesisRecord {
    pub schema_version: String,
    pub domain_id: String,
    pub identity: ProfileIdentity,
    pub profile_epoch: u64,
    pub writer_identity: String,
    pub fence_token: u64,
    pub initial_canonical_head: String,
    pub bindings: ProfileBindingsDigest,
    /// Authority snapshot sealed into the same rooted genesis record. Side
    /// files and process configuration cannot manufacture the initial
    /// authority/revocation coordinates.
    pub authority: AuthoritySnapshot,
    pub record_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCutoverRecord {
    pub schema_version: String,
    pub cutover_id: String,
    pub domain_id: String,
    pub from: ProfileIdentity,
    pub to: ProfileIdentity,
    pub from_profile_epoch: u64,
    pub to_profile_epoch: u64,
    pub from_writer_identity: String,
    pub to_writer_identity: String,
    pub from_fence_token: u64,
    pub to_fence_token: u64,
    pub expected_canonical_head: String,
    pub agentgres_expected_head: Option<String>,
    /// Exact canonical authorization operation and the already-admitted effect
    /// that carried it. This is present for strengthening and weakening alike;
    /// `governance` below is the additional INV-42 burden for a weakening.
    pub authorization_operation_ref: String,
    pub authorization_effect_ref: String,
    pub authorization_effect_agentgres_head: String,
    pub authorization_refs: Vec<String>,
    pub activation_not_before_ms: u64,
    pub activation_checkpoint_height: u64,
    /// The authority in force when this cutover was prepared. Revalidated
    /// against the live owner at commit, exactly as an effect commit is.
    pub authority: AuthoritySnapshot,
    pub bindings: ProfileBindingsDigest,
    pub guarantee_delta: GuaranteeDelta,
    pub governance: Option<GovernanceEvidence>,
    pub rollback: RollbackPlan,
    pub record_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFreezeRecord {
    pub schema_version: String,
    pub freeze_id: String,
    pub domain_id: String,
    pub frozen_identity: ProfileIdentity,
    pub from_profile_epoch: u64,
    pub from_fence_token: u64,
    pub from_writer_identity: String,
    /// The authority and revocation epochs in force at the freeze
    /// linearization point. Recovery verifies the rooted bytes; live admission
    /// additionally revalidates this exact snapshot with the domain owner.
    pub authority: AuthoritySnapshot,
    pub reason: String,
    pub authorization_refs: Vec<String>,
    pub expected_canonical_head: String,
    pub agentgres_expected_head: Option<String>,
    pub record_hash: String,
}

/// Caller-authored cutover request. Profile spellings are aliases here and are
/// resolved to canonical members before anything is admitted.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileCutoverRequest {
    pub cutover_id: String,
    /// Operator spelling of the target profile; resolved via alias table.
    pub to_profile: String,
    pub to_profile_contract_version: String,
    pub to_writer_identity: String,
    pub to_fence_token: u64,
    pub authorization_operation_ref: String,
    pub authorization_effect_ref: String,
    pub authorization_effect_agentgres_head: String,
    pub authorization_refs: Vec<String>,
    pub activation_not_before_ms: u64,
    pub activation_checkpoint_height: u64,
    /// Authority snapshot the caller believes is in force. Revalidated
    /// against the live owner before anything is admitted.
    pub authority: AuthoritySnapshot,
    pub bindings: ProfileBindingsDigest,
    pub guarantee_delta: GuaranteeDelta,
    pub governance: Option<GovernanceEvidence>,
    pub rollback: RollbackPlan,
}

/// Caller-authored freeze request.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfileFreezeRequest {
    pub freeze_id: String,
    pub authority: AuthoritySnapshot,
    pub reason: String,
    pub authorization_refs: Vec<String>,
}

/// Prepared cutover material. Preparation grants no authority: this value is
/// inert until `commit_cutover` revalidates every bound against live spine
/// state and the mux admits it in a device-flushed rooted batch.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedProfileCutover {
    pub(crate) record: ProfileCutoverRecord,
    pub(crate) canonical_bytes: Vec<u8>,
    pub(crate) direction: GuaranteeDirection,
}

impl PreparedProfileCutover {
    pub(crate) fn new(
        record: ProfileCutoverRecord,
        canonical_bytes: Vec<u8>,
        direction: GuaranteeDirection,
    ) -> Self {
        Self {
            record,
            canonical_bytes,
            direction,
        }
    }

    pub fn record(&self) -> &ProfileCutoverRecord {
        &self.record
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn direction(&self) -> GuaranteeDirection {
        self.direction
    }
}

/// A committed control operation, carrying the exact Agentgres coordinates it
/// linearized at.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommittedProfileCutover {
    pub record: ProfileCutoverRecord,
    pub canonical_bytes: Vec<u8>,
    pub operation_sequence: u64,
    pub agentgres_head: String,
    pub agentgres_batch_sequence: u64,
    pub agentgres_root: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Structural validation of a cutover record, independent of live state.
pub(crate) fn validate_cutover_record(
    record: &ProfileCutoverRecord,
    canonical_bytes: &[u8],
) -> Result<GuaranteeDirection, RecognizedEffectError> {
    if record.schema_version != PROFILE_CUTOVER_SCHEMA {
        return Err(RecognizedEffectError::Invalid(
            "profile-cutover schema mismatch".into(),
        ));
    }
    validate_token("cutover_id", &record.cutover_id)?;
    validate_token("domain_id", &record.domain_id)?;
    validate_token("from_writer_identity", &record.from_writer_identity)?;
    validate_token("to_writer_identity", &record.to_writer_identity)?;
    validate_hash("expected_canonical_head", &record.expected_canonical_head)?;
    if let Some(head) = record.agentgres_expected_head.as_deref() {
        validate_hash("agentgres_expected_head", head)?;
    }
    validate_hash(
        "authorization_operation_ref",
        &record.authorization_operation_ref,
    )?;
    validate_token("authorization_effect_ref", &record.authorization_effect_ref)?;
    validate_hash(
        "authorization_effect_agentgres_head",
        &record.authorization_effect_agentgres_head,
    )?;
    let mut authorization_refs = BTreeSet::new();
    for reference in &record.authorization_refs {
        validate_token("authorization_ref", reference)?;
        if !authorization_refs.insert(reference) {
            return Err(RecognizedEffectError::Invalid(
                "profile cutover carries duplicate authorization refs".into(),
            ));
        }
    }
    if record.authorization_refs.is_empty() || record.activation_checkpoint_height == 0 {
        return Err(RecognizedEffectError::Invalid(
            "profile cutover lacks authorization refs or activation checkpoint".into(),
        ));
    }
    validate_token("authority.domain_id", &record.authority.domain_id)?;
    validate_token("authority.issuer_key_id", &record.authority.issuer_key_id)?;
    record.from.validate()?;
    record.to.validate()?;
    record.bindings.validate()?;
    record.rollback.validate_shape()?;

    // A cutover must move. Same member is a no-op that would still burn an
    // epoch and a fence token, so it is refused outright.
    let direction = record
        .from
        .profile
        .direction_to(record.to.profile)
        .ok_or_else(|| {
            ProfileRefusal::NoOpCutover {
                profile: record.to.profile.profile().into(),
            }
            .into_error()
        })?;

    // The declared delta must equal the delta the exact profile pair implies.
    if record.guarantee_delta.direction != direction {
        return Err(ProfileRefusal::GuaranteeDeltaMismatch {
            declared: record.guarantee_delta.direction.as_str().into(),
            computed: direction.as_str().into(),
        }
        .into_error());
    }
    if direction == GuaranteeDirection::Weakening
        && record.guarantee_delta.lost_guarantees.is_empty()
    {
        return Err(ProfileRefusal::GuaranteeDeltaIncomplete {
            detail: "a weakening must name the guarantees it gives up".into(),
        }
        .into_error());
    }
    for guarantee in record
        .guarantee_delta
        .lost_guarantees
        .iter()
        .chain(&record.guarantee_delta.retained_guarantees)
        .chain(&record.guarantee_delta.gained_guarantees)
    {
        validate_token("guarantee", guarantee)?;
    }

    // Epoch and fence token must both advance, and the epoch by exactly one:
    // a skipped epoch would leave an unaccounted-for gap in the spine's
    // control history.
    if record.to_profile_epoch != record.from_profile_epoch.saturating_add(1) {
        return Err(ProfileRefusal::ProfileEpochNotSuccessor {
            active: record.from_profile_epoch,
            requested: record.to_profile_epoch,
        }
        .into_error());
    }
    if record.to_fence_token <= record.from_fence_token {
        return Err(ProfileRefusal::FenceTokenNotMonotonic {
            active: record.from_fence_token,
            requested: record.to_fence_token,
        }
        .into_error());
    }

    match (direction, &record.governance) {
        (GuaranteeDirection::Weakening, None) => {
            return Err(ProfileRefusal::GovernanceEvidenceRequired.into_error())
        }
        (GuaranteeDirection::Weakening, Some(governance)) => {
            governance.validate_shape(&record.guarantee_delta)?;
            if governance.effective_after_ms != record.activation_not_before_ms {
                return Err(ProfileRefusal::GovernanceEvidenceRejected {
                    detail: "governance delay differs from the cutover activation delay".into(),
                }
                .into_error());
            }
            record
                .rollback
                .validate_independence(&record.from, &record.to_writer_identity)?;
        }
        // A strengthening carries no weakening burden, and unvalidated
        // governance material must not ride along inside admitted bytes.
        (GuaranteeDirection::Strengthening, Some(_)) => {
            return Err(ProfileRefusal::GovernanceEvidenceRejected {
                detail: "a strengthening cutover must not carry weakening evidence".into(),
            }
            .into_error())
        }
        (GuaranteeDirection::Strengthening, None) => {}
    }

    let expected_hash = cutover_record_hash(record)?;
    if record.record_hash != expected_hash {
        return Err(RecognizedEffectError::Invalid(
            "profile-cutover record hash mismatch".into(),
        ));
    }
    let expected_bytes = serde_jcs::to_vec(record)
        .map_err(|error| RecognizedEffectError::Invalid(error.to_string()))?;
    if expected_bytes != canonical_bytes {
        return Err(RecognizedEffectError::Invalid(
            "profile-cutover canonical bytes mismatch".into(),
        ));
    }
    Ok(direction)
}

pub(crate) fn validate_genesis_record(
    record: &ProfileGenesisRecord,
) -> Result<(), RecognizedEffectError> {
    if record.schema_version != PROFILE_GENESIS_SCHEMA {
        return Err(RecognizedEffectError::Invalid(
            "profile-genesis schema mismatch".into(),
        ));
    }
    validate_token("domain_id", &record.domain_id)?;
    validate_token("writer_identity", &record.writer_identity)?;
    validate_hash("initial_canonical_head", &record.initial_canonical_head)?;
    record.identity.validate()?;
    record.bindings.validate()?;
    if record.authority.domain_id != record.domain_id
        || record.authority.authority_epoch == 0
        || !record.authority.admission_permitted
    {
        return Err(RecognizedEffectError::Invalid(
            "profile-genesis authority snapshot is not admissible for the domain".into(),
        ));
    }
    validate_token("genesis issuer_key_id", &record.authority.issuer_key_id)?;
    // Fence token zero is reserved for "no eligible writer", so a sealed
    // genesis must claim a real token.
    if record.fence_token == 0 {
        return Err(ProfileRefusal::FenceTokenNotMonotonic {
            active: 0,
            requested: 0,
        }
        .into_error());
    }
    let expected_hash = genesis_record_hash(record)?;
    if record.record_hash != expected_hash {
        return Err(RecognizedEffectError::Invalid(
            "profile-genesis record hash mismatch".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_freeze_record(
    record: &ProfileFreezeRecord,
) -> Result<(), RecognizedEffectError> {
    if record.schema_version != PROFILE_FREEZE_SCHEMA {
        return Err(RecognizedEffectError::Invalid(
            "profile-freeze schema mismatch".into(),
        ));
    }
    validate_token("freeze_id", &record.freeze_id)?;
    validate_token("domain_id", &record.domain_id)?;
    validate_token("reason", &record.reason)?;
    validate_token("from_writer_identity", &record.from_writer_identity)?;
    validate_hash("expected_canonical_head", &record.expected_canonical_head)?;
    record.frozen_identity.validate()?;
    if record.authority.domain_id != record.domain_id
        || record.authority.authority_epoch == 0
        || !record.authority.admission_permitted
    {
        return Err(RecognizedEffectError::Invalid(
            "freeze authority snapshot is not admissible for the frozen domain".into(),
        ));
    }
    validate_token("freeze issuer_key_id", &record.authority.issuer_key_id)?;
    let mut distinct = BTreeSet::new();
    for reference in &record.authorization_refs {
        validate_token("authorization_ref", reference)?;
        if !distinct.insert(reference.as_str()) {
            return Err(RecognizedEffectError::Invalid(
                "duplicate freeze authorization ref".into(),
            ));
        }
    }
    if record.authorization_refs.is_empty() {
        return Err(RecognizedEffectError::Invalid(
            "freeze carries no authorization".into(),
        ));
    }
    let expected_hash = freeze_record_hash(record)?;
    if record.record_hash != expected_hash {
        return Err(RecognizedEffectError::Invalid(
            "profile-freeze record hash mismatch".into(),
        ));
    }
    Ok(())
}

pub(crate) fn cutover_record_hash(
    record: &ProfileCutoverRecord,
) -> Result<String, RecognizedEffectError> {
    let mut preimage = record.clone();
    preimage.record_hash.clear();
    hash_value(&serde_json::to_value(preimage)?)
}

pub(crate) fn genesis_record_hash(
    record: &ProfileGenesisRecord,
) -> Result<String, RecognizedEffectError> {
    let mut preimage = record.clone();
    preimage.record_hash.clear();
    hash_value(&serde_json::to_value(preimage)?)
}

pub(crate) fn freeze_record_hash(
    record: &ProfileFreezeRecord,
) -> Result<String, RecognizedEffectError> {
    let mut preimage = record.clone();
    preimage.record_hash.clear();
    hash_value(&serde_json::to_value(preimage)?)
}

/// The spine's sealed genesis declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpineGenesis {
    pub identity: ProfileIdentity,
    pub writer_identity: String,
    pub fence_token: u64,
    pub initial_canonical_head: String,
    pub bindings: ProfileBindingsDigest,
    pub authority: AuthoritySnapshot,
}

/// A writer's claim on the spine: exact identity plus exact fence token.
/// Neither alone is sufficient, and neither is inferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterClaim {
    pub writer_identity: String,
    pub fence_token: u64,
}

impl WriterClaim {
    pub fn new(writer_identity: impl Into<String>, fence_token: u64) -> Self {
        Self {
            writer_identity: writer_identity.into(),
            fence_token,
        }
    }
}

/// The live control state derived by replaying the spine. Exactly one of
/// these outcomes is possible after recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpineState {
    /// Exactly one writer identity is eligible, at this fence token.
    Active(ActiveProfile),
    /// No writer is eligible until a successor cutover admits one.
    Frozen(FrozenProfile),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveProfile {
    pub identity: ProfileIdentity,
    pub profile_epoch: u64,
    pub writer_identity: String,
    pub fence_token: u64,
    pub bindings: ProfileBindingsDigest,
    /// Authority in force for every effect and control operation admitted
    /// under this profile epoch.
    pub authority: AuthoritySnapshot,
    /// The cutover that installed this profile; absent at genesis.
    pub installed_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenProfile {
    pub freeze_id: String,
    pub reason: String,
    pub identity: ProfileIdentity,
    pub profile_epoch: u64,
    pub fence_token: u64,
    pub retired_writer_identity: String,
    /// The exact authority snapshot that admitted the freeze. Retained so a
    /// restart can validate its local issuer while binding no writer.
    pub authority: AuthoritySnapshot,
}

impl SpineState {
    pub fn active(&self) -> Result<&ActiveProfile, RecognizedEffectError> {
        match self {
            Self::Active(active) => Ok(active),
            Self::Frozen(frozen) => Err(ProfileRefusal::SpineFrozen {
                freeze_id: frozen.freeze_id.clone(),
            }
            .into_error()),
        }
    }

    pub fn profile(&self) -> FinalityProfile {
        match self {
            Self::Active(active) => active.identity.profile,
            Self::Frozen(frozen) => frozen.identity.profile,
        }
    }

    pub fn profile_epoch(&self) -> u64 {
        match self {
            Self::Active(active) => active.profile_epoch,
            Self::Frozen(frozen) => frozen.profile_epoch,
        }
    }

    pub fn fence_token(&self) -> u64 {
        match self {
            Self::Active(active) => active.fence_token,
            Self::Frozen(frozen) => frozen.fence_token,
        }
    }

    pub fn is_frozen(&self) -> bool {
        matches!(self, Self::Frozen(_))
    }
}
