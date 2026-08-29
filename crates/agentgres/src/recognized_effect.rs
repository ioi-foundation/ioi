//! The Agentgres two-profile control/data spine.
//!
//! One mux domain and one object head carry both planes: profile control
//! operations (genesis, cutover, freeze) and recognized effects. They are
//! therefore one totally ordered history, so "which profile is active" and
//! "which effects were recognized" can never disagree — that shared head is
//! what makes an unambiguous cutover with no dual-authority interval
//! structural rather than procedural (`INV-41`).
//!
//! Availability bytes and a signed candidate are preparation material.  They
//! become authoritative only when the complete record is admitted in the
//! dedicated Agentgres mux domain and its rooted batch is device-flushed.
//! Everything after that boundary is a rebuildable, idempotent consequence of
//! the committed record.  A prepared cutover is inert on exactly the same
//! terms: it grants no authority until it linearizes.

#[cfg(test)]
use crate::mux::MuxCommitTestPoint;
use crate::mux::{ExactProjection, MuxEngine};
use crate::cutover::{
    cutover_record_hash, freeze_record_hash, genesis_record_hash, validate_cutover_record,
    validate_freeze_record, validate_genesis_record, ActiveProfile, CommittedProfileCutover,
    FrozenProfile, GovernanceValidator, ProfileCutoverRecord, ProfileCutoverRequest,
    ProfileFreezeRecord, ProfileFreezeRequest, ProfileGenesisRecord, PreparedProfileCutover,
    SpineGenesis, SpineState, WeakeningReview, WriterClaim, OP_KIND_CUTOVER, OP_KIND_FREEZE,
    OP_KIND_GENESIS, OP_KIND_RECOGNIZED_EFFECT, PROFILE_CUTOVER_SCHEMA, PROFILE_FREEZE_SCHEMA,
    PROFILE_GENESIS_SCHEMA,
};
use crate::profile::{
    FinalityProfile, GuaranteeDirection, ProfileBindings, ProfileBindingsDigest, ProfileIdentity,
};
use crate::refs::profile_spine_object_ref;
use crate::{Durability, Operation, Refusal, GENESIS_ROOT};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_finality::VerificationError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const RECOGNIZED_EFFECT_SCHEMA: &str = "ioi.agentgres-recognized-effect.v1";

/// The single spine domain. Profile-neutral by construction: a domain named
/// after one profile could not host the cutover that leaves it. The mux owns
/// the reserved-domain fence; this re-export preserves the public contract.
pub use crate::mux::AGENTGRES_PROFILE_SPINE_DOMAIN;
pub const REQUIRED_OUTBOX_KINDS: [&str; 5] = [
    "projection_materialization",
    "root_publication",
    "committed_status_publication",
    "transaction_committed",
    "ack_publication",
];

#[derive(Debug)]
pub enum RecognizedEffectError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Finality(VerificationError),
    Invalid(String),
    Authority(String),
    StaleAuthority,
    StaleHead {
        expected: String,
        actual: String,
    },
    ReplayConflict {
        identity: String,
    },
    ProjectionDivergence {
        identity: String,
    },
    Admission(Refusal),
    Durability(String),
    Profile(ProfileRefusal),
    #[cfg(test)]
    InjectedCrash(CrashPoint),
}

/// Fail-closed profile, fencing, cutover, and governance refusals.
///
/// Each variant is a distinct fact. Collapsing them would let a downgrade read
/// as a typo, or an unwired emitter read as a verification failure.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileRefusal {
    /// The label resolves to nothing in the owner's compatibility map.
    UnknownProfileAlias { value: String },
    /// The label resolves cleanly, to a canonical member this spine does not
    /// admit.
    ProfileOutsideSpineScope {
        value: String,
        canonical_member: String,
    },
    /// The owner records this label as resolving to no single member.
    AmbiguousProfileLabel { value: String },
    /// Admitted bytes carried a non-canonical spelling.
    NonCanonicalProfileBytes { field: String, value: String },
    VariantMismatch { profile: String, variant: String },
    /// The profile's emit/verify adapter is not wired in this build.
    ProfileNotWired { profile: String },
    SpineFrozen { freeze_id: String },
    NoWriterBound,
    WriterIdentityMismatch { expected: String, actual: String },
    FenceTokenMismatch { expected: u64, actual: u64 },
    FenceTokenNotMonotonic { active: u64, requested: u64 },
    ProfileEpochMismatch { expected: u64, actual: u64 },
    ProfileEpochNotSuccessor { active: u64, requested: u64 },
    ActiveProfileMismatch { expected: String, actual: String },
    ProfileContractVersionMismatch { expected: String, actual: String },
    BindingsDigestMismatch {
        field: String,
        expected: String,
        actual: String,
    },
    GenesisMismatch { field: String },
    NoOpCutover { profile: String },
    GuaranteeDeltaMismatch { declared: String, computed: String },
    GuaranteeDeltaIncomplete { detail: String },
    GovernanceEvidenceRequired,
    GovernanceEvidenceRejected { detail: String },
    GovernanceThresholdUnmet { approvals: u32, threshold: u32 },
    GovernanceDelayUnmet {
        effective_after_ms: u64,
        recorded_at_ms: u64,
    },
    GovernanceAnchorUnmet { detail: String },
    RollbackNotIndependent { detail: String },
    RollbackPlanInvalid { detail: String },
    DuplicateControlOperation { identity: String },
    StalePreparedMaterial { detail: String },
}

impl ProfileRefusal {
    pub(crate) fn into_error(self) -> RecognizedEffectError {
        RecognizedEffectError::Profile(self)
    }
}

impl std::fmt::Display for ProfileRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProfileAlias { value } => {
                write!(f, "profile label does not resolve: {value}")
            }
            Self::ProfileOutsideSpineScope {
                value,
                canonical_member,
            } => write!(
                f,
                "profile label {value} resolves to {canonical_member}, which this spine does not admit"
            ),
            Self::AmbiguousProfileLabel { value } => write!(
                f,
                "profile label {value} resolves to no single canonical member"
            ),
            Self::NonCanonicalProfileBytes { field, value } => {
                write!(f, "{field} is not a canonical profile identity: {value}")
            }
            Self::VariantMismatch { profile, variant } => {
                write!(f, "certificate variant {variant} does not bind {profile}")
            }
            Self::ProfileNotWired { profile } => write!(
                f,
                "profile {profile} has no emit/verify adapter wired in this build"
            ),
            Self::SpineFrozen { freeze_id } => {
                write!(f, "spine is frozen by {freeze_id}; no writer is eligible")
            }
            Self::NoWriterBound => write!(f, "no writer is bound to this spine"),
            Self::WriterIdentityMismatch { expected, actual } => write!(
                f,
                "writer identity is not the eligible writer: expected={expected} actual={actual}"
            ),
            Self::FenceTokenMismatch { expected, actual } => write!(
                f,
                "fence token is not the active token: expected={expected} actual={actual}"
            ),
            Self::FenceTokenNotMonotonic { active, requested } => write!(
                f,
                "fence token must strictly increase: active={active} requested={requested}"
            ),
            Self::ProfileEpochMismatch { expected, actual } => write!(
                f,
                "profile epoch is stale: expected={expected} actual={actual}"
            ),
            Self::ProfileEpochNotSuccessor { active, requested } => write!(
                f,
                "profile epoch must be the exact successor: active={active} requested={requested}"
            ),
            Self::ActiveProfileMismatch { expected, actual } => write!(
                f,
                "profile is not the active profile: expected={expected} actual={actual}"
            ),
            Self::ProfileContractVersionMismatch { expected, actual } => write!(
                f,
                "profile contract version mismatch: expected={expected} actual={actual}"
            ),
            Self::BindingsDigestMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "profile binding {field} substituted: expected={expected} actual={actual}"
            ),
            Self::GenesisMismatch { field } => {
                write!(f, "sealed genesis does not match presented {field}")
            }
            Self::NoOpCutover { profile } => {
                write!(f, "cutover does not change the profile: {profile}")
            }
            Self::GuaranteeDeltaMismatch { declared, computed } => write!(
                f,
                "guarantee delta misdeclared: declared={declared} computed={computed}"
            ),
            Self::GuaranteeDeltaIncomplete { detail } => {
                write!(f, "guarantee delta incomplete: {detail}")
            }
            Self::GovernanceEvidenceRequired => write!(
                f,
                "an authority-weakening cutover requires separately validated governance evidence"
            ),
            Self::GovernanceEvidenceRejected { detail } => {
                write!(f, "governance evidence rejected: {detail}")
            }
            Self::GovernanceThresholdUnmet {
                approvals,
                threshold,
            } => write!(
                f,
                "governance threshold unmet: approvals={approvals} threshold={threshold}"
            ),
            Self::GovernanceDelayUnmet {
                effective_after_ms,
                recorded_at_ms,
            } => write!(
                f,
                "governance delay unmet: effective_after_ms={effective_after_ms} recorded_at_ms={recorded_at_ms}"
            ),
            Self::GovernanceAnchorUnmet { detail } => {
                write!(f, "governance checkpoint anchor unmet: {detail}")
            }
            Self::RollbackNotIndependent { detail } => {
                write!(f, "rollback is not independent of the new authority: {detail}")
            }
            Self::RollbackPlanInvalid { detail } => write!(f, "rollback plan invalid: {detail}"),
            Self::DuplicateControlOperation { identity } => {
                write!(f, "control operation already admitted: {identity}")
            }
            Self::StalePreparedMaterial { detail } => {
                write!(f, "prepared material is stale: {detail}")
            }
        }
    }
}

impl std::fmt::Display for RecognizedEffectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "recognized-effect I/O failed: {error}"),
            Self::Json(error) => write!(f, "recognized-effect JSON failed: {error}"),
            Self::Finality(error) => write!(f, "recognized-effect finality failed: {error}"),
            Self::Invalid(detail) => write!(f, "recognized-effect invalid: {detail}"),
            Self::Authority(detail) => write!(f, "recognized-effect authority failed: {detail}"),
            Self::StaleAuthority => write!(f, "recognized-effect authority snapshot is stale"),
            Self::StaleHead { expected, actual } => write!(
                f,
                "recognized-effect canonical head is stale: expected={expected} actual={actual}"
            ),
            Self::ReplayConflict { identity } => {
                write!(f, "recognized-effect replay conflict: {identity}")
            }
            Self::ProjectionDivergence { identity } => {
                write!(f, "recognized-effect projection diverged: {identity}")
            }
            Self::Admission(refusal) => write!(f, "recognized-effect admission refused: {refusal}"),
            Self::Durability(detail) => {
                write!(f, "recognized-effect durability uncertain: {detail}")
            }
            Self::Profile(refusal) => write!(f, "agentgres spine refused: {refusal}"),
            #[cfg(test)]
            Self::InjectedCrash(point) => write!(f, "injected crash at {point}"),
        }
    }
}

impl std::error::Error for RecognizedEffectError {}

impl From<std::io::Error> for RecognizedEffectError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for RecognizedEffectError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<VerificationError> for RecognizedEffectError {
    fn from(value: VerificationError) -> Self {
        Self::Finality(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritySnapshot {
    pub domain_id: String,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub issuer_key_id: String,
    pub admission_permitted: bool,
}

/// wallet.network (or the domain's admitted authority owner) implements this
/// check.  Agentgres consumes the exact result; it does not mint authority.
pub trait AuthorityRevalidator {
    fn current_snapshot(&self, prepared: &AuthoritySnapshot) -> Result<AuthoritySnapshot, String>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutboxIntent {
    pub consequence_id: String,
    pub kind: String,
    pub payload: Value,
    pub payload_hash: String,
}

impl OutboxIntent {
    pub fn new(
        consequence_id: impl Into<String>,
        kind: impl Into<String>,
        payload: Value,
    ) -> Result<Self, RecognizedEffectError> {
        let consequence_id = consequence_id.into();
        let kind = kind.into();
        let payload_hash = hash_value(&payload)?;
        Ok(Self {
            consequence_id,
            kind,
            payload,
            payload_hash,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecognizedEffectRecord {
    pub schema_version: String,
    pub effect_id: String,
    pub domain_id: String,
    /// Canonical profile identity this effect was recognized under. Carried
    /// explicitly rather than read back out of the bundle, so a substituted
    /// profile is a record-level refusal and not a verification subtlety.
    pub profile: String,
    pub certificate_variant: String,
    pub profile_contract_version: String,
    /// Control-plane coordinates in force at preparation. All four are
    /// revalidated against live state at commit.
    pub profile_epoch: u64,
    pub writer_identity: String,
    pub fence_token: u64,
    pub bindings: ProfileBindingsDigest,
    pub canonical_expected_head: String,
    pub agentgres_expected_head: Option<String>,
    pub authority: AuthoritySnapshot,
    pub bundle: Value,
    pub outbox: Vec<OutboxIntent>,
    pub record_hash: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedRecognizedEffect {
    record: RecognizedEffectRecord,
    canonical_bytes: Vec<u8>,
}

impl PreparedRecognizedEffect {
    pub fn record(&self) -> &RecognizedEffectRecord {
        &self.record
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommittedRecognizedEffect {
    pub record: RecognizedEffectRecord,
    pub canonical_bytes: Vec<u8>,
    pub operation_sequence: u64,
    pub agentgres_head: String,
    pub agentgres_batch_sequence: u64,
    pub agentgres_root: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitDisposition {
    Committed,
    Replayed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommitResult {
    pub disposition: CommitDisposition,
    pub effect: CommittedRecognizedEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Recorded,
    Replayed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DeliveryMarker {
    schema_version: String,
    effect_id: String,
    consequence_id: String,
    kind: String,
    payload_hash: String,
    record_hash: String,
}

pub struct RecognizedEffectStore {
    root: PathBuf,
    domain_id: String,
    object_ref: String,
    initial_canonical_head: String,
    canonical_head: String,
    mux: MuxEngine,
    bindings: ProfileBindings,
    /// Sealed on first open; every later open must present it byte-identical.
    genesis: Option<ProfileGenesisRecord>,
    /// Derived purely from committed control records — never from the caller.
    state: SpineState,
    /// The writer that has proved identity and fence token this process.
    bound_writer: Option<WriterClaim>,
    effects: BTreeMap<String, CommittedRecognizedEffect>,
    cutovers: BTreeMap<String, CommittedProfileCutover>,
    freezes: BTreeSet<String>,
    /// Terminal spine coordinates, for governance checkpoint anchoring.
    last_batch_seq: u64,
    #[cfg(test)]
    armed_crash: Option<CrashPoint>,
    #[cfg(test)]
    observed_points: Vec<CrashPoint>,
}

impl RecognizedEffectStore {
    /// Open the spine, sealing `genesis` if this is its first open.
    ///
    /// On every later open the presented genesis must match the sealed one
    /// exactly. A restart cannot substitute the active profile, the eligible
    /// writer, or the initial canonical head by passing different arguments.
    pub fn open(
        root: &Path,
        domain_id: impl Into<String>,
        genesis: SpineGenesis,
    ) -> Result<Self, RecognizedEffectError> {
        Self::open_with_bindings(root, domain_id, genesis, ProfileBindings::production())
    }

    /// `open` with an explicit adapter registry. This is the seam a caller
    /// uses to supply the sibling `ioi-finality` two-profile emitter.
    pub fn open_with_bindings(
        root: &Path,
        domain_id: impl Into<String>,
        genesis: SpineGenesis,
        bindings: ProfileBindings,
    ) -> Result<Self, RecognizedEffectError> {
        let domain_id = domain_id.into();
        validate_token("domain_id", &domain_id)?;
        validate_token("writer_identity", &genesis.writer_identity)?;
        validate_hash("initial_canonical_head", &genesis.initial_canonical_head)?;
        genesis.identity.validate()?;
        genesis.bindings.validate()?;
        fs::create_dir_all(root)?;
        fs::create_dir_all(root.join("availability"))?;
        fs::create_dir_all(root.join("deliveries"))?;
        fs::create_dir_all(root.join("projections"))?;
        let mux_dir = root.join("canonical");
        let mux = MuxEngine::open(&mux_dir, true)?;
        let object_ref = profile_spine_object_ref(&domain_id);
        let mut store = Self {
            root: root.to_path_buf(),
            domain_id,
            object_ref,
            initial_canonical_head: genesis.initial_canonical_head.clone(),
            canonical_head: genesis.initial_canonical_head.clone(),
            mux,
            bindings,
            genesis: None,
            // Provisional; `recover` replaces it from committed truth, and
            // `seal_genesis` installs it when the spine is empty.
            state: SpineState::Active(ActiveProfile {
                identity: genesis.identity.clone(),
                profile_epoch: 0,
                writer_identity: genesis.writer_identity.clone(),
                fence_token: genesis.fence_token,
                bindings: genesis.bindings.clone(),
                installed_by: None,
            }),
            bound_writer: None,
            effects: BTreeMap::new(),
            cutovers: BTreeMap::new(),
            freezes: BTreeSet::new(),
            last_batch_seq: 0,
            #[cfg(test)]
            armed_crash: None,
            #[cfg(test)]
            observed_points: Vec::new(),
        };
        store.recover()?;
        match &store.genesis {
            Some(sealed) => store.require_matching_genesis(sealed.clone(), &genesis)?,
            None => store.seal_genesis(&genesis)?,
        }
        Ok(store)
    }

    pub fn canonical_head(&self) -> &str {
        &self.canonical_head
    }

    /// The control state recovered from committed truth: exactly one eligible
    /// writer, or an explicit frozen state.
    pub fn spine_state(&self) -> &SpineState {
        &self.state
    }

    pub fn sealed_genesis(&self) -> Option<&ProfileGenesisRecord> {
        self.genesis.as_ref()
    }

    pub fn bound_writer(&self) -> Option<&WriterClaim> {
        self.bound_writer.as_ref()
    }

    pub fn committed_cutover(&self, cutover_id: &str) -> Option<&CommittedProfileCutover> {
        self.cutovers.get(cutover_id)
    }

    pub fn committed(&self, effect_id: &str) -> Option<&CommittedRecognizedEffect> {
        self.effects.get(effect_id)
    }

    /// Prove eligibility: exact writer identity AND exact active fence token.
    ///
    /// Exactness in both directions is the point. A retired writer presents a
    /// lower token and is refused as stale; a forged claim presents a token
    /// no cutover ever installed and is refused as unknown. There is no
    /// "greater than" rule a caller could win by inventing a large number.
    pub fn bind_writer(&mut self, claim: WriterClaim) -> Result<(), RecognizedEffectError> {
        let active = self.state.active()?;
        if claim.writer_identity != active.writer_identity {
            return Err(ProfileRefusal::WriterIdentityMismatch {
                expected: active.writer_identity.clone(),
                actual: claim.writer_identity,
            }
            .into_error());
        }
        if claim.fence_token != active.fence_token {
            return Err(ProfileRefusal::FenceTokenMismatch {
                expected: active.fence_token,
                actual: claim.fence_token,
            }
            .into_error());
        }
        self.bound_writer = Some(claim);
        Ok(())
    }

    fn require_bound_writer(&self) -> Result<&ActiveProfile, RecognizedEffectError> {
        let active = self.state.active()?;
        let claim = self
            .bound_writer
            .as_ref()
            .ok_or_else(|| ProfileRefusal::NoWriterBound.into_error())?;
        // The binding is re-checked, not trusted: a cutover committed after
        // this writer bound retires it immediately.
        if claim.writer_identity != active.writer_identity {
            return Err(ProfileRefusal::WriterIdentityMismatch {
                expected: active.writer_identity.clone(),
                actual: claim.writer_identity.clone(),
            }
            .into_error());
        }
        if claim.fence_token != active.fence_token {
            return Err(ProfileRefusal::FenceTokenMismatch {
                expected: active.fence_token,
                actual: claim.fence_token,
            }
            .into_error());
        }
        Ok(active)
    }

    fn spine_head(&self) -> Option<String> {
        self.mux
            .domain_head(AGENTGRES_PROFILE_SPINE_DOMAIN, &self.object_ref)
            .cloned()
    }

    /// Terminal spine coordinates a governance checkpoint anchor must pin.
    fn current_anchor(&self) -> (u64, String) {
        (
            self.last_batch_seq,
            self.mux
                .domain_root(AGENTGRES_PROFILE_SPINE_DOMAIN)
                .cloned()
                .unwrap_or_else(|| GENESIS_ROOT.to_owned()),
        )
    }

    fn require_matching_genesis(
        &self,
        sealed: ProfileGenesisRecord,
        presented: &SpineGenesis,
    ) -> Result<(), RecognizedEffectError> {
        let mismatch = |field: &str| ProfileRefusal::GenesisMismatch { field: field.into() }.into_error();
        if sealed.identity.profile != presented.identity.profile {
            return Err(mismatch("profile"));
        }
        if sealed.identity.certificate_variant != presented.identity.certificate_variant {
            return Err(mismatch("certificate_variant"));
        }
        if sealed.identity.profile_contract_version != presented.identity.profile_contract_version {
            return Err(mismatch("profile_contract_version"));
        }
        if sealed.writer_identity != presented.writer_identity {
            return Err(mismatch("writer_identity"));
        }
        if sealed.fence_token != presented.fence_token {
            return Err(mismatch("fence_token"));
        }
        if sealed.initial_canonical_head != presented.initial_canonical_head {
            return Err(mismatch("initial_canonical_head"));
        }
        if sealed.bindings != presented.bindings {
            return Err(mismatch("bindings"));
        }
        Ok(())
    }

    fn seal_genesis(&mut self, genesis: &SpineGenesis) -> Result<(), RecognizedEffectError> {
        let mut record = ProfileGenesisRecord {
            schema_version: PROFILE_GENESIS_SCHEMA.into(),
            domain_id: self.domain_id.clone(),
            identity: genesis.identity.clone(),
            profile_epoch: 0,
            writer_identity: genesis.writer_identity.clone(),
            fence_token: genesis.fence_token,
            initial_canonical_head: genesis.initial_canonical_head.clone(),
            bindings: genesis.bindings.clone(),
            record_hash: String::new(),
        };
        record.record_hash = genesis_record_hash(&record)?;
        validate_genesis_record(&record)?;
        let payload = serde_json::to_value(&record)?;
        let ack = self.admit_control(OP_KIND_GENESIS, record.record_hash.clone(), payload, 0)?;
        self.last_batch_seq = ack.batch_seq;
        self.state = SpineState::Active(ActiveProfile {
            identity: record.identity.clone(),
            profile_epoch: 0,
            writer_identity: record.writer_identity.clone(),
            fence_token: record.fence_token,
            bindings: record.bindings.clone(),
            installed_by: None,
        });
        self.genesis = Some(record);
        Ok(())
    }

    /// One control operation, through the same head and the same
    /// device-flushed rooted batch every effect uses.
    fn admit_control(
        &mut self,
        op_kind: &str,
        idem_key: String,
        payload: Value,
        recorded_at_ms: u64,
    ) -> Result<crate::AdmitAck, RecognizedEffectError> {
        let expected_head = self.spine_head();
        let operation = Operation {
            domain: AGENTGRES_PROFILE_SPINE_DOMAIN.into(),
            object_ref: self.object_ref.clone(),
            op_kind: op_kind.into(),
            expected_absent: expected_head.is_none(),
            expected_head,
            payload,
            recorded_at_ms,
            idem_key,
        };
        self.hit(CrashPoint::before(Phase::CanonicalWrite))?;
        let results = self
            .mux
            .admit_profile_spine_batch(vec![operation])
            .map_err(|error| RecognizedEffectError::Durability(error.to_string()))?;
        let ack = results
            .into_iter()
            .next()
            .ok_or_else(|| RecognizedEffectError::Invalid("missing Agentgres ack".into()))?
            .map_err(RecognizedEffectError::Admission)?;
        if ack.durability != Durability::DeviceFlush {
            self.mux.stop_admission_until_reopen();
            return Err(RecognizedEffectError::Durability(format!(
                "required device_flush, received {:?}",
                ack.durability
            )));
        }
        Ok(ack)
    }

    pub fn prepare(
        &mut self,
        effect_id: impl Into<String>,
        bundle_template: Value,
        authority: AuthoritySnapshot,
        authority_owner: &dyn AuthorityRevalidator,
        issuer_key_id: &str,
        signing_key: &Ed25519PrivateKey,
        outbox: Vec<OutboxIntent>,
    ) -> Result<PreparedRecognizedEffect, RecognizedEffectError> {
        let effect_id = effect_id.into();
        // Eligibility first: an unbound, retired, or frozen writer prepares
        // nothing. Preparation is cheap, but it must not look like progress.
        let active = self.require_bound_writer()?.clone();
        self.around(Phase::AdmissionValidation, |_store| {
            validate_outbox(&outbox)?;
            validate_token("effect_id", &effect_id)?;
            Ok(())
        })?;
        let profile = self.around(Phase::ProfileResolution, |_store| {
            let profile = FinalityProfile::from_exact(
                pointer_text(&bundle_template, "/checkpoint/profile")?,
                pointer_text(
                    &bundle_template,
                    "/checkpoint/finality_certificate/certificate_variant",
                )?,
            )?;
            if profile != active.identity.profile {
                return Err(ProfileRefusal::ActiveProfileMismatch {
                    expected: active.identity.profile.profile().into(),
                    actual: profile.profile().into(),
                }
                .into_error());
            }
            let version = pointer_text(&bundle_template, "/checkpoint/profile_contract_version")?;
            if version != active.identity.profile_contract_version {
                return Err(ProfileRefusal::ProfileContractVersionMismatch {
                    expected: active.identity.profile_contract_version.clone(),
                    actual: version.to_owned(),
                }
                .into_error());
            }
            Ok(profile)
        })?;

        self.around(Phase::AuthorityRevalidation, |_store| {
            let current = authority_owner
                .current_snapshot(&authority)
                .map_err(RecognizedEffectError::Authority)?;
            if current != authority || !current.admission_permitted {
                return Err(RecognizedEffectError::StaleAuthority);
            }
            if current.issuer_key_id != issuer_key_id {
                return Err(RecognizedEffectError::StaleAuthority);
            }
            Ok(())
        })?;

        self.around(Phase::StateTransitionConstruction, |_store| {
            require_array(&bundle_template, "/previous_state_entries")?;
            require_nonempty_array(&bundle_template, "/resulting_state_entries")?;
            Ok(())
        })?;
        self.around(Phase::IndividualReceiptCreation, |_store| {
            require_nonempty_array(&bundle_template, "/receipts")?;
            Ok(())
        })?;
        self.around(Phase::CheckpointConstruction, |_store| {
            bundle_template
                .pointer("/checkpoint")
                .and_then(Value::as_object)
                .ok_or_else(|| RecognizedEffectError::Invalid("checkpoint is absent".into()))?;
            Ok(())
        })?;

        self.around(Phase::AvailabilityBytePersistence, |store| {
            store.persist_availability(&bundle_template)
        })?;
        self.around(Phase::AvailabilityManifestValidation, |store| {
            store.verify_availability(&bundle_template)
        })?;

        let bundle = self.around(Phase::CertificateConstructionSigning, |store| {
            store
                .bindings
                .binding(profile)
                .emit(bundle_template, issuer_key_id, signing_key)
        })?;
        self.bindings.binding(profile).verify(&bundle)?;
        validate_bundle_authority(&bundle, &authority)?;
        let previous_head = pointer_text(&bundle, "/checkpoint/previous_canonical_head")?;
        if previous_head != self.canonical_head {
            return Err(RecognizedEffectError::StaleHead {
                expected: previous_head.to_owned(),
                actual: self.canonical_head.clone(),
            });
        }
        self.verify_availability(&bundle)?;

        let mut record = RecognizedEffectRecord {
            schema_version: RECOGNIZED_EFFECT_SCHEMA.into(),
            effect_id,
            domain_id: self.domain_id.clone(),
            profile: profile.profile().into(),
            certificate_variant: profile.certificate_variant().into(),
            profile_contract_version: active.identity.profile_contract_version.clone(),
            profile_epoch: active.profile_epoch,
            writer_identity: active.writer_identity.clone(),
            fence_token: active.fence_token,
            bindings: active.bindings.clone(),
            canonical_expected_head: previous_head.to_owned(),
            agentgres_expected_head: self.spine_head(),
            authority,
            bundle,
            outbox,
            record_hash: String::new(),
        };
        record.record_hash = record_hash(&record)?;
        let canonical_bytes = serde_jcs::to_vec(&record)
            .map_err(|error| RecognizedEffectError::Invalid(error.to_string()))?;
        Ok(PreparedRecognizedEffect {
            record,
            canonical_bytes,
        })
    }

    pub fn commit(
        &mut self,
        prepared: PreparedRecognizedEffect,
        authority_owner: &dyn AuthorityRevalidator,
        recorded_at_ms: u64,
    ) -> Result<CommitResult, RecognizedEffectError> {
        if let Some(existing) = self.effects.get(&prepared.record.effect_id) {
            if existing.canonical_bytes == prepared.canonical_bytes {
                return Ok(CommitResult {
                    disposition: CommitDisposition::Replayed,
                    effect: existing.clone(),
                });
            }
            return Err(RecognizedEffectError::ReplayConflict {
                identity: prepared.record.effect_id,
            });
        }
        validate_record(&prepared.record, &prepared.canonical_bytes, &self.bindings)?;
        self.verify_availability(&prepared.record.bundle)?;

        // Every bound the prepared record claimed is rechecked here against
        // live state. Preparation proved nothing; this is the gate.
        self.revalidate_effect_bounds(&prepared.record)?;

        let current = authority_owner
            .current_snapshot(&prepared.record.authority)
            .map_err(RecognizedEffectError::Authority)?;
        if current != prepared.record.authority || !current.admission_permitted {
            return Err(RecognizedEffectError::StaleAuthority);
        }
        let previous_head = pointer_text(
            &prepared.record.bundle,
            "/checkpoint/previous_canonical_head",
        )?;
        if previous_head != self.canonical_head
            || prepared.record.canonical_expected_head != self.canonical_head
        {
            return Err(RecognizedEffectError::StaleHead {
                expected: previous_head.to_owned(),
                actual: self.canonical_head.clone(),
            });
        }
        if self.spine_head() != prepared.record.agentgres_expected_head {
            return Err(RecognizedEffectError::ReplayConflict {
                identity: prepared.record.effect_id,
            });
        }

        self.hit(CrashPoint::before(Phase::FrameConstruction))?;
        let operation = Operation {
            domain: AGENTGRES_PROFILE_SPINE_DOMAIN.into(),
            object_ref: self.object_ref.clone(),
            op_kind: OP_KIND_RECOGNIZED_EFFECT.into(),
            expected_head: prepared.record.agentgres_expected_head.clone(),
            expected_absent: prepared.record.agentgres_expected_head.is_none(),
            payload: serde_json::to_value(&prepared.record)?,
            recorded_at_ms,
            idem_key: prepared.record.effect_id.clone(),
        };
        self.hit(CrashPoint::after(Phase::FrameConstruction))?;
        self.hit(CrashPoint::before(Phase::CanonicalWrite))?;
        let results = self
            .mux
            .admit_profile_spine_batch(vec![operation])
            .map_err(|error| RecognizedEffectError::Durability(error.to_string()))?;
        let ack = results
            .into_iter()
            .next()
            .ok_or_else(|| RecognizedEffectError::Invalid("missing Agentgres ack".into()))?
            .map_err(RecognizedEffectError::Admission)?;
        if ack.durability != Durability::DeviceFlush {
            self.mux.stop_admission_until_reopen();
            return Err(RecognizedEffectError::Durability(format!(
                "required device_flush, received {:?}",
                ack.durability
            )));
        }
        let resulting_head = pointer_text(
            &prepared.record.bundle,
            "/checkpoint/resulting_canonical_head",
        )?
        .to_owned();
        self.canonical_head = resulting_head;
        self.last_batch_seq = ack.batch_seq;
        let effect = CommittedRecognizedEffect {
            record: prepared.record,
            canonical_bytes: prepared.canonical_bytes,
            operation_sequence: ack.seq,
            agentgres_head: ack.new_head,
            agentgres_batch_sequence: ack.batch_seq,
            agentgres_root: ack.root,
        };
        self.effects
            .insert(effect.record.effect_id.clone(), effect.clone());
        Ok(CommitResult {
            disposition: CommitDisposition::Committed,
            effect,
        })
    }

    pub fn pending_outbox(
        &self,
        effect_id: &str,
    ) -> Result<Vec<OutboxIntent>, RecognizedEffectError> {
        let effect = self.effects.get(effect_id).ok_or_else(|| {
            RecognizedEffectError::Invalid(format!("effect {effect_id} is not committed"))
        })?;
        let mut pending = Vec::new();
        let mut predecessor_missing = false;
        for intent in &effect.record.outbox {
            let path = self.delivery_path(&intent.consequence_id);
            if !path.exists() {
                predecessor_missing = true;
                pending.push(intent.clone());
                continue;
            }
            if predecessor_missing {
                return Err(RecognizedEffectError::Invalid(format!(
                    "outbox delivery order is torn: {} is recorded before a predecessor",
                    intent.consequence_id
                )));
            }
            let marker: DeliveryMarker = serde_json::from_slice(&fs::read(&path)?)?;
            validate_delivery_marker(&marker, effect, intent)?;
        }
        Ok(pending)
    }

    /// Records the idempotent consequence after its transport or projection
    /// has applied the exact committed payload.  A lost marker is redriven;
    /// the stable consequence identity makes duplicate transport harmless.
    pub fn record_delivery(
        &mut self,
        effect_id: &str,
        consequence_id: &str,
        delivered_payload: &Value,
    ) -> Result<DeliveryDisposition, RecognizedEffectError> {
        let effect = self.effects.get(effect_id).cloned().ok_or_else(|| {
            RecognizedEffectError::Invalid(format!("effect {effect_id} is not committed"))
        })?;
        let intent_index = effect
            .record
            .outbox
            .iter()
            .position(|intent| intent.consequence_id == consequence_id)
            .ok_or_else(|| {
                RecognizedEffectError::Invalid(format!(
                    "consequence {consequence_id} is not in committed outbox"
                ))
            })?;
        let intent = &effect.record.outbox[intent_index];
        for predecessor in &effect.record.outbox[..intent_index] {
            let predecessor_path = self.delivery_path(&predecessor.consequence_id);
            if !predecessor_path.exists() {
                return Err(RecognizedEffectError::Invalid(format!(
                    "consequence {consequence_id} cannot be recorded before predecessor {}",
                    predecessor.consequence_id
                )));
            }
            let marker: DeliveryMarker =
                serde_json::from_slice(&fs::read(&predecessor_path)?)?;
            validate_delivery_marker(&marker, &effect, predecessor)?;
        }
        if hash_value(delivered_payload)? != intent.payload_hash
            || delivered_payload != &intent.payload
        {
            return Err(RecognizedEffectError::ReplayConflict {
                identity: consequence_id.into(),
            });
        }
        let phase = phase_for_outbox_kind(&intent.kind)?;
        self.hit(CrashPoint::before(phase))?;
        let marker = DeliveryMarker {
            schema_version: "ioi.agentgres-outbox-delivery.v1".into(),
            effect_id: effect_id.into(),
            consequence_id: consequence_id.into(),
            kind: intent.kind.clone(),
            payload_hash: intent.payload_hash.clone(),
            record_hash: effect.record.record_hash.clone(),
        };
        let path = self.delivery_path(consequence_id);
        let disposition = if path.exists() {
            let existing: DeliveryMarker = serde_json::from_slice(&fs::read(&path)?)?;
            if existing != marker {
                return Err(RecognizedEffectError::ReplayConflict {
                    identity: consequence_id.into(),
                });
            }
            DeliveryDisposition::Replayed
        } else {
            atomic_write(
                &path,
                &serde_jcs::to_vec(&marker).map_err(|error| {
                    RecognizedEffectError::Invalid(format!("delivery JCS: {error}"))
                })?,
            )?;
            DeliveryDisposition::Recorded
        };
        self.hit(CrashPoint::after(phase))?;
        Ok(disposition)
    }

    pub fn materialize_projection(
        &mut self,
        effect_id: &str,
    ) -> Result<DeliveryDisposition, RecognizedEffectError> {
        let effect = self.effects.get(effect_id).cloned().ok_or_else(|| {
            RecognizedEffectError::Invalid(format!("effect {effect_id} is not committed"))
        })?;
        self.hit(CrashPoint::before(Phase::ProjectionMaterialization))?;
        let path = self
            .root
            .join("projections")
            .join(format!("{}.json", safe_hash(&effect.record.effect_id)));
        let disposition = if path.exists() {
            if fs::read(&path)? != effect.canonical_bytes {
                return Err(RecognizedEffectError::ProjectionDivergence {
                    identity: effect_id.into(),
                });
            }
            DeliveryDisposition::Replayed
        } else {
            atomic_write(&path, &effect.canonical_bytes)?;
            DeliveryDisposition::Recorded
        };
        self.hit(CrashPoint::after(Phase::ProjectionMaterialization))?;
        Ok(disposition)
    }

    /// The exact control bounds an effect commit must still satisfy: active
    /// profile, variant, contract version, profile epoch, writer identity,
    /// fence token, and the governing bindings digest.
    ///
    /// Each is a separate comparison with its own refusal, so a substituted
    /// writer never reports as a stale epoch and a substituted retention
    /// policy never reports as a profile mismatch.
    fn revalidate_effect_bounds(
        &self,
        record: &RecognizedEffectRecord,
    ) -> Result<(), RecognizedEffectError> {
        let active = self.require_bound_writer()?;
        if record.profile != active.identity.profile.profile()
            || record.certificate_variant != active.identity.certificate_variant
        {
            return Err(ProfileRefusal::ActiveProfileMismatch {
                expected: active.identity.label(),
                actual: format!("{}/{}", record.profile, record.certificate_variant),
            }
            .into_error());
        }
        if record.profile_contract_version != active.identity.profile_contract_version {
            return Err(ProfileRefusal::ProfileContractVersionMismatch {
                expected: active.identity.profile_contract_version.clone(),
                actual: record.profile_contract_version.clone(),
            }
            .into_error());
        }
        if record.profile_epoch != active.profile_epoch {
            return Err(ProfileRefusal::ProfileEpochMismatch {
                expected: active.profile_epoch,
                actual: record.profile_epoch,
            }
            .into_error());
        }
        if record.writer_identity != active.writer_identity {
            return Err(ProfileRefusal::WriterIdentityMismatch {
                expected: active.writer_identity.clone(),
                actual: record.writer_identity.clone(),
            }
            .into_error());
        }
        if record.fence_token != active.fence_token {
            return Err(ProfileRefusal::FenceTokenMismatch {
                expected: active.fence_token,
                actual: record.fence_token,
            }
            .into_error());
        }
        record.bindings.require_exact(&active.bindings)
    }

    /// Build inert cutover material. Grants nothing: the returned value is
    /// only a proposal until `commit_cutover` revalidates every bound against
    /// live state and the mux admits it.
    pub fn prepare_cutover(
        &mut self,
        request: ProfileCutoverRequest,
        authority_owner: &dyn AuthorityRevalidator,
        governance: &dyn GovernanceValidator,
        recorded_at_ms: u64,
    ) -> Result<PreparedProfileCutover, RecognizedEffectError> {
        let active = self.require_bound_writer()?.clone();
        let to = self.around(Phase::ProfileResolution, |_store| {
            let member = FinalityProfile::resolve_label(&request.to_profile)?;
            ProfileIdentity::new(member, request.to_profile_contract_version.clone())
        })?;

        self.around(Phase::AuthorityRevalidation, |_store| {
            let current = authority_owner
                .current_snapshot(&request.authority)
                .map_err(RecognizedEffectError::Authority)?;
            if current != request.authority || !current.admission_permitted {
                return Err(RecognizedEffectError::StaleAuthority);
            }
            Ok(())
        })?;

        let (record, canonical_bytes, direction) =
            self.around(Phase::ControlRecordConstruction, |store| {
                let mut record = ProfileCutoverRecord {
                    schema_version: PROFILE_CUTOVER_SCHEMA.into(),
                    cutover_id: request.cutover_id.clone(),
                    domain_id: store.domain_id.clone(),
                    from: active.identity.clone(),
                    to: to.clone(),
                    from_profile_epoch: active.profile_epoch,
                    to_profile_epoch: active.profile_epoch.saturating_add(1),
                    from_writer_identity: active.writer_identity.clone(),
                    to_writer_identity: request.to_writer_identity.clone(),
                    from_fence_token: active.fence_token,
                    to_fence_token: request.to_fence_token,
                    expected_canonical_head: store.canonical_head.clone(),
                    agentgres_expected_head: store.spine_head(),
                    authority: request.authority.clone(),
                    bindings: request.bindings.clone(),
                    guarantee_delta: request.guarantee_delta.clone(),
                    governance: request.governance.clone(),
                    rollback: request.rollback.clone(),
                    record_hash: String::new(),
                };
                record.record_hash = cutover_record_hash(&record)?;
                let bytes = serde_jcs::to_vec(&record)
                    .map_err(|error| RecognizedEffectError::Invalid(error.to_string()))?;
                let direction = validate_cutover_record(&record, &bytes)?;
                Ok((record, bytes, direction))
            })?;

        self.around(Phase::GovernanceValidation, |store| {
            store.validate_governance(&record, direction, governance, recorded_at_ms)
        })?;

        Ok(PreparedProfileCutover::new(record, canonical_bytes, direction))
    }

    /// Linearize a cutover through the same head and device-flushed rooted
    /// batch as every recognized effect.
    ///
    /// The retirement of the old `(writer_identity, fence_token)` and the
    /// installation of the new one are the same admitted record, so there is
    /// no instant at which both are eligible and none at which neither is.
    pub fn commit_cutover(
        &mut self,
        prepared: PreparedProfileCutover,
        authority_owner: &dyn AuthorityRevalidator,
        governance: &dyn GovernanceValidator,
        recorded_at_ms: u64,
    ) -> Result<CommittedProfileCutover, RecognizedEffectError> {
        if let Some(existing) = self.cutovers.get(&prepared.record().cutover_id) {
            // A byte-identical retry of an already-linearized cutover is the
            // same fact, not a second one. Anything else is a duplicate.
            if existing.canonical_bytes == prepared.canonical_bytes() {
                return Ok(existing.clone());
            }
            return Err(ProfileRefusal::DuplicateControlOperation {
                identity: prepared.record().cutover_id.clone(),
            }
            .into_error());
        }
        let direction = validate_cutover_record(prepared.record(), prepared.canonical_bytes())?;
        if direction != prepared.direction() {
            return Err(ProfileRefusal::GuaranteeDeltaMismatch {
                declared: prepared.direction().as_str().into(),
                computed: direction.as_str().into(),
            }
            .into_error());
        }

        let record = prepared.record().clone();
        self.require_bound_writer()?;
        self.require_cutover_continuity(&record)?;
        if record.domain_id != self.domain_id {
            return Err(ProfileRefusal::StalePreparedMaterial {
                detail: "cutover names a different domain".into(),
            }
            .into_error());
        }
        let current = authority_owner
            .current_snapshot(&record.authority)
            .map_err(RecognizedEffectError::Authority)?;
        if current != record.authority || !current.admission_permitted {
            return Err(RecognizedEffectError::StaleAuthority);
        }
        if record.expected_canonical_head != self.canonical_head {
            return Err(RecognizedEffectError::StaleHead {
                expected: record.expected_canonical_head.clone(),
                actual: self.canonical_head.clone(),
            });
        }
        if record.agentgres_expected_head != self.spine_head() {
            return Err(ProfileRefusal::StalePreparedMaterial {
                detail: "Agentgres head advanced after preparation".into(),
            }
            .into_error());
        }
        // Governance is revalidated here, not trusted from preparation: the
        // delay and the pinned checkpoint are only meaningful at the instant
        // the weakening actually takes effect.
        self.validate_governance(&record, direction, governance, recorded_at_ms)?;

        self.hit(CrashPoint::before(Phase::WriterFenceRetirement))?;
        let payload = serde_json::to_value(&record)?;
        let ack = self.admit_control(
            OP_KIND_CUTOVER,
            record.cutover_id.clone(),
            payload,
            recorded_at_ms,
        )?;
        self.hit(CrashPoint::after(Phase::WriterFenceRetirement))?;
        self.last_batch_seq = ack.batch_seq;
        self.state = SpineState::Active(ActiveProfile {
            identity: record.to.clone(),
            profile_epoch: record.to_profile_epoch,
            writer_identity: record.to_writer_identity.clone(),
            fence_token: record.to_fence_token,
            bindings: record.bindings.clone(),
            installed_by: Some(record.cutover_id.clone()),
        });
        // The writer that authored this cutover is retired by it. It must
        // re-bind under the new token, exactly as any other process would.
        self.bound_writer = None;
        let committed = CommittedProfileCutover {
            record,
            canonical_bytes: prepared.canonical_bytes().to_vec(),
            operation_sequence: ack.seq,
            agentgres_head: ack.new_head,
            agentgres_batch_sequence: ack.batch_seq,
            agentgres_root: ack.root,
        };
        self.cutovers
            .insert(committed.record.cutover_id.clone(), committed.clone());
        Ok(committed)
    }

    /// Retire the active writer without naming a successor. A frozen spine
    /// admits no effect and no writer until a successor cutover installs one.
    pub fn freeze(
        &mut self,
        request: ProfileFreezeRequest,
        recorded_at_ms: u64,
    ) -> Result<ProfileFreezeRecord, RecognizedEffectError> {
        let active = self.require_bound_writer()?.clone();
        if self.freezes.contains(&request.freeze_id) {
            return Err(ProfileRefusal::DuplicateControlOperation {
                identity: request.freeze_id,
            }
            .into_error());
        }
        let mut record = ProfileFreezeRecord {
            schema_version: PROFILE_FREEZE_SCHEMA.into(),
            freeze_id: request.freeze_id,
            domain_id: self.domain_id.clone(),
            frozen_identity: active.identity.clone(),
            from_profile_epoch: active.profile_epoch,
            from_fence_token: active.fence_token,
            from_writer_identity: active.writer_identity.clone(),
            reason: request.reason,
            authorization_refs: request.authorization_refs,
            expected_canonical_head: self.canonical_head.clone(),
            agentgres_expected_head: self.spine_head(),
            record_hash: String::new(),
        };
        record.record_hash = freeze_record_hash(&record)?;
        validate_freeze_record(&record)?;
        let payload = serde_json::to_value(&record)?;
        let ack = self.admit_control(
            OP_KIND_FREEZE,
            record.freeze_id.clone(),
            payload,
            recorded_at_ms,
        )?;
        self.last_batch_seq = ack.batch_seq;
        self.freezes.insert(record.freeze_id.clone());
        self.state = SpineState::Frozen(FrozenProfile {
            freeze_id: record.freeze_id.clone(),
            reason: record.reason.clone(),
            identity: active.identity.clone(),
            profile_epoch: active.profile_epoch,
            fence_token: active.fence_token,
            retired_writer_identity: active.writer_identity.clone(),
        });
        self.bound_writer = None;
        Ok(record)
    }

    /// The INV-42 burden, checked in full. A strengthening carries none of it
    /// and must carry no evidence; `validate_cutover_record` already refused
    /// the mixed cases before this point.
    fn validate_governance(
        &self,
        record: &ProfileCutoverRecord,
        direction: GuaranteeDirection,
        governance: &dyn GovernanceValidator,
        recorded_at_ms: u64,
    ) -> Result<(), RecognizedEffectError> {
        if direction != GuaranteeDirection::Weakening {
            return Ok(());
        }
        let evidence = record
            .governance
            .as_ref()
            .ok_or_else(|| ProfileRefusal::GovernanceEvidenceRequired.into_error())?;
        // Enforced delay before effect.
        if recorded_at_ms < evidence.effective_after_ms {
            return Err(ProfileRefusal::GovernanceDelayUnmet {
                effective_after_ms: evidence.effective_after_ms,
                recorded_at_ms,
            }
            .into_error());
        }
        // A checkpoint pinning the exact pre-change state. Anything but the
        // current terminal coordinates pins some other state.
        let (batch_seq, root) = self.current_anchor();
        if evidence.anchor_batch_seq != batch_seq || evidence.anchor_root != root {
            return Err(ProfileRefusal::GovernanceAnchorUnmet {
                detail: format!(
                    "anchor batch_seq={} root={} does not pin the pre-change state batch_seq={batch_seq} root={root}",
                    evidence.anchor_batch_seq, evidence.anchor_root
                ),
            }
            .into_error());
        }
        let review = WeakeningReview {
            domain_id: &self.domain_id,
            cutover_id: &record.cutover_id,
            from: &record.from,
            to: &record.to,
            from_writer_identity: &record.from_writer_identity,
            to_writer_identity: &record.to_writer_identity,
            guarantee_delta: &record.guarantee_delta,
            governance: evidence,
            rollback: &record.rollback,
            recorded_at_ms,
        };
        let verdict = governance
            .validate_weakening(&review)
            .map_err(|detail| ProfileRefusal::GovernanceEvidenceRejected { detail }.into_error())?;
        if !verdict.approved {
            return Err(ProfileRefusal::GovernanceEvidenceRejected {
                detail: verdict.detail,
            }
            .into_error());
        }
        // The verdict must be about THIS evidence package, at or above the
        // declared threshold. A validator cannot approve a substitute.
        if verdict.evidence_digest != evidence.evidence_digest {
            return Err(ProfileRefusal::GovernanceEvidenceRejected {
                detail: "verdict does not bind the presented evidence digest".into(),
            }
            .into_error());
        }
        if verdict.approvals < evidence.approval_threshold {
            return Err(ProfileRefusal::GovernanceThresholdUnmet {
                approvals: verdict.approvals,
                threshold: evidence.approval_threshold,
            }
            .into_error());
        }
        Ok(())
    }

    /// Replay the one spine history, folding control and data operations in
    /// their exact admitted order.
    ///
    /// Because both planes share this head, the recovered control state is
    /// the state that was in force for each effect as it linearized — there is
    /// no second ordering to reconcile and no window in which the two could
    /// disagree about who was eligible.
    fn recover(&mut self) -> Result<(), RecognizedEffectError> {
        self.effects.clear();
        self.cutovers.clear();
        self.freezes.clear();
        self.genesis = None;
        self.canonical_head = self.initial_canonical_head.clone();
        let history = self
            .mux
            .project_exact_history(AGENTGRES_PROFILE_SPINE_DOMAIN, &self.object_ref)?;
        let mut prior_agentgres_head: Option<String> = None;
        for projection in history {
            let payload = projection.operation.payload.clone();
            let op_kind = projection.operation.op_kind.as_str();
            match op_kind {
                OP_KIND_GENESIS => {
                    if self.genesis.is_some() || prior_agentgres_head.is_some() {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered genesis is not the first spine operation".into(),
                        ));
                    }
                    let record: ProfileGenesisRecord = serde_json::from_value(payload)?;
                    validate_genesis_record(&record)?;
                    self.require_recovered_domain(&record.domain_id)?;
                    self.canonical_head = record.initial_canonical_head.clone();
                    self.initial_canonical_head = record.initial_canonical_head.clone();
                    self.state = SpineState::Active(ActiveProfile {
                        identity: record.identity.clone(),
                        profile_epoch: record.profile_epoch,
                        writer_identity: record.writer_identity.clone(),
                        fence_token: record.fence_token,
                        bindings: record.bindings.clone(),
                        installed_by: None,
                    });
                    self.genesis = Some(record);
                }
                OP_KIND_CUTOVER => {
                    let record: ProfileCutoverRecord = serde_json::from_value(payload)?;
                    let bytes = serde_jcs::to_vec(&record)
                        .map_err(|error| RecognizedEffectError::Invalid(error.to_string()))?;
                    validate_cutover_record(&record, &bytes)?;
                    self.require_recovered_domain(&record.domain_id)?;
                    if record.agentgres_expected_head != prior_agentgres_head {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered Agentgres predecessor mismatch".into(),
                        ));
                    }
                    if record.expected_canonical_head != self.canonical_head {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered canonical predecessor mismatch".into(),
                        ));
                    }
                    self.require_cutover_continuity(&record)?;
                    if self.cutovers.contains_key(&record.cutover_id) {
                        return Err(ProfileRefusal::DuplicateControlOperation {
                            identity: record.cutover_id,
                        }
                        .into_error());
                    }
                    self.state = SpineState::Active(ActiveProfile {
                        identity: record.to.clone(),
                        profile_epoch: record.to_profile_epoch,
                        writer_identity: record.to_writer_identity.clone(),
                        fence_token: record.to_fence_token,
                        bindings: record.bindings.clone(),
                        installed_by: Some(record.cutover_id.clone()),
                    });
                    let cutover_id = record.cutover_id.clone();
                    self.cutovers.insert(
                        cutover_id,
                        CommittedProfileCutover {
                            record,
                            canonical_bytes: bytes,
                            operation_sequence: projection.seq,
                            agentgres_head: projection.head.clone(),
                            agentgres_batch_sequence: projection.admission_batch_seq,
                            agentgres_root: projection.admission_root.clone(),
                        },
                    );
                }
                OP_KIND_FREEZE => {
                    let record: ProfileFreezeRecord = serde_json::from_value(payload)?;
                    validate_freeze_record(&record)?;
                    self.require_recovered_domain(&record.domain_id)?;
                    if record.agentgres_expected_head != prior_agentgres_head {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered Agentgres predecessor mismatch".into(),
                        ));
                    }
                    if record.expected_canonical_head != self.canonical_head {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered canonical predecessor mismatch".into(),
                        ));
                    }
                    let active = self.state.active()?;
                    if record.from_profile_epoch != active.profile_epoch
                        || record.from_fence_token != active.fence_token
                        || record.from_writer_identity != active.writer_identity
                    {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered freeze does not retire the active writer".into(),
                        ));
                    }
                    if !self.freezes.insert(record.freeze_id.clone()) {
                        return Err(ProfileRefusal::DuplicateControlOperation {
                            identity: record.freeze_id,
                        }
                        .into_error());
                    }
                    self.state = SpineState::Frozen(FrozenProfile {
                        freeze_id: record.freeze_id.clone(),
                        reason: record.reason.clone(),
                        identity: record.frozen_identity.clone(),
                        profile_epoch: record.from_profile_epoch,
                        fence_token: record.from_fence_token,
                        retired_writer_identity: record.from_writer_identity.clone(),
                    });
                }
                OP_KIND_RECOGNIZED_EFFECT => {
                    let record: RecognizedEffectRecord = serde_json::from_value(payload)?;
                    let bytes = serde_jcs::to_vec(&record)
                        .map_err(|error| RecognizedEffectError::Invalid(error.to_string()))?;
                    validate_record(&record, &bytes, &self.bindings)?;
                    // The signed bundle carries the exact verifier input
                    // bytes.  The CAS is availability preparation/projection,
                    // so recovery may restore a missing side file from
                    // canonical bytes but may never accept a conflicting file
                    // under the same content identity.
                    self.persist_availability(&record.bundle)?;
                    self.verify_availability(&record.bundle)?;
                    self.require_recovered_domain(&record.domain_id)?;
                    if record.agentgres_expected_head != prior_agentgres_head {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered Agentgres predecessor mismatch".into(),
                        ));
                    }
                    let previous =
                        pointer_text(&record.bundle, "/checkpoint/previous_canonical_head")?;
                    if previous != self.canonical_head {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered canonical predecessor mismatch".into(),
                        ));
                    }
                    // An effect must have been admitted under the control
                    // state that was live at its position in this history.
                    let active = self.state.active()?;
                    if record.profile != active.identity.profile.profile()
                        || record.certificate_variant != active.identity.certificate_variant
                        || record.profile_contract_version
                            != active.identity.profile_contract_version
                        || record.profile_epoch != active.profile_epoch
                        || record.writer_identity != active.writer_identity
                        || record.fence_token != active.fence_token
                    {
                        return Err(RecognizedEffectError::Invalid(
                            "recovered effect was not admitted under the active profile".into(),
                        ));
                    }
                    record.bindings.require_exact(&active.bindings)?;
                    if self.effects.contains_key(&record.effect_id) {
                        return Err(RecognizedEffectError::ReplayConflict {
                            identity: record.effect_id,
                        });
                    }
                    self.canonical_head =
                        pointer_text(&record.bundle, "/checkpoint/resulting_canonical_head")?
                            .to_owned();
                    let effect = committed_from_projection(record, bytes, projection.clone());
                    self.effects.insert(effect.record.effect_id.clone(), effect);
                }
                other => {
                    return Err(RecognizedEffectError::Invalid(format!(
                        "unknown spine operation kind {other}"
                    )))
                }
            }
            self.last_batch_seq = projection.admission_batch_seq;
            prior_agentgres_head = Some(projection.head.clone());
        }
        Ok(())
    }

    fn require_recovered_domain(&self, domain_id: &str) -> Result<(), RecognizedEffectError> {
        if domain_id != self.domain_id {
            return Err(RecognizedEffectError::Invalid(
                "recovered record domain mismatch".into(),
            ));
        }
        Ok(())
    }

    /// A recovered cutover must chain off the exact prior control state.
    /// Anything else is a reordering or a revived token.
    fn require_cutover_continuity(
        &self,
        record: &ProfileCutoverRecord,
    ) -> Result<(), RecognizedEffectError> {
        let active = self.state.active()?;
        if record.from != active.identity {
            return Err(ProfileRefusal::ActiveProfileMismatch {
                expected: active.identity.label(),
                actual: record.from.label(),
            }
            .into_error());
        }
        if record.from_profile_epoch != active.profile_epoch {
            return Err(ProfileRefusal::ProfileEpochMismatch {
                expected: active.profile_epoch,
                actual: record.from_profile_epoch,
            }
            .into_error());
        }
        if record.from_writer_identity != active.writer_identity {
            return Err(ProfileRefusal::WriterIdentityMismatch {
                expected: active.writer_identity.clone(),
                actual: record.from_writer_identity.clone(),
            }
            .into_error());
        }
        if record.from_fence_token != active.fence_token {
            return Err(ProfileRefusal::FenceTokenMismatch {
                expected: active.fence_token,
                actual: record.from_fence_token,
            }
            .into_error());
        }
        Ok(())
    }

    fn persist_availability(&self, bundle: &Value) -> Result<(), RecognizedEffectError> {
        let declared = manifest_payloads(bundle)?;
        let supplied = supplied_payloads(bundle)?;
        for (payload_ref, payload_hash, byte_length) in declared {
            let bytes = supplied.get(&payload_ref).ok_or_else(|| {
                RecognizedEffectError::Invalid(format!(
                    "availability bytes missing for {payload_ref}"
                ))
            })?;
            if bytes.is_empty() || bytes.len() as u64 != byte_length {
                return Err(RecognizedEffectError::Invalid(format!(
                    "availability length mismatch for {payload_ref}"
                )));
            }
            if hash_bytes(bytes) != payload_hash {
                return Err(RecognizedEffectError::Invalid(format!(
                    "availability hash mismatch for {payload_ref}"
                )));
            }
            let path = self.availability_path(&payload_hash)?;
            if path.exists() {
                if fs::read(&path)? != *bytes {
                    return Err(RecognizedEffectError::ProjectionDivergence {
                        identity: payload_hash,
                    });
                }
            } else {
                atomic_write(&path, bytes)?;
            }
        }
        Ok(())
    }

    fn verify_availability(&self, bundle: &Value) -> Result<(), RecognizedEffectError> {
        for (payload_ref, payload_hash, byte_length) in manifest_payloads(bundle)? {
            let path = self.availability_path(&payload_hash)?;
            let bytes = fs::read(&path).map_err(|_| {
                RecognizedEffectError::Invalid(format!(
                    "committed availability bytes missing for {payload_ref}"
                ))
            })?;
            if bytes.is_empty()
                || bytes.len() as u64 != byte_length
                || hash_bytes(&bytes) != payload_hash
            {
                return Err(RecognizedEffectError::Invalid(format!(
                    "committed availability bytes mismatch for {payload_ref}"
                )));
            }
        }
        Ok(())
    }

    fn availability_path(&self, hash: &str) -> Result<PathBuf, RecognizedEffectError> {
        validate_hash("payload_hash", hash)?;
        Ok(self.root.join("availability").join(&hash[7..]))
    }

    fn delivery_path(&self, consequence_id: &str) -> PathBuf {
        self.root
            .join("deliveries")
            .join(format!("{}.json", safe_hash(consequence_id)))
    }

    #[cfg(not(test))]
    fn hit(&mut self, _point: CrashPoint) -> Result<(), RecognizedEffectError> {
        Ok(())
    }

    #[cfg(test)]
    fn hit(&mut self, point: CrashPoint) -> Result<(), RecognizedEffectError> {
        self.observed_points.push(point);
        if self.armed_crash == Some(point) {
            self.armed_crash = None;
            return Err(RecognizedEffectError::InjectedCrash(point));
        }
        Ok(())
    }

    fn around<T>(
        &mut self,
        phase: Phase,
        action: impl FnOnce(&mut Self) -> Result<T, RecognizedEffectError>,
    ) -> Result<T, RecognizedEffectError> {
        self.hit(CrashPoint::before(phase))?;
        let result = action(self)?;
        self.hit(CrashPoint::after(phase))?;
        Ok(result)
    }

    #[cfg(test)]
    fn arm_crash(&mut self, point: CrashPoint) {
        let mux_point = match point {
            CrashPoint {
                phase: Phase::CanonicalWrite,
                boundary: Boundary::After,
            } => Some(MuxCommitTestPoint::AfterWrite),
            CrashPoint {
                phase: Phase::CanonicalFsync,
                boundary: Boundary::Before,
            } => Some(MuxCommitTestPoint::BeforeFsync),
            CrashPoint {
                phase: Phase::CanonicalFsync,
                boundary: Boundary::After,
            } => Some(MuxCommitTestPoint::AfterFsync),
            CrashPoint {
                phase: Phase::HeadRootAdvancement,
                boundary: Boundary::Before,
            } => Some(MuxCommitTestPoint::BeforeHeadAdvance),
            CrashPoint {
                phase: Phase::HeadRootAdvancement,
                boundary: Boundary::After,
            } => Some(MuxCommitTestPoint::AfterHeadAdvance),
            _ => None,
        };
        if let Some(point) = mux_point {
            self.mux.arm_commit_test_point(point);
        } else {
            self.armed_crash = Some(point);
        }
    }
}

fn committed_from_projection(
    record: RecognizedEffectRecord,
    canonical_bytes: Vec<u8>,
    projection: ExactProjection,
) -> CommittedRecognizedEffect {
    CommittedRecognizedEffect {
        record,
        canonical_bytes,
        operation_sequence: projection.seq,
        agentgres_head: projection.head,
        agentgres_batch_sequence: projection.admission_batch_seq,
        agentgres_root: projection.admission_root,
    }
}

fn validate_record(
    record: &RecognizedEffectRecord,
    canonical_bytes: &[u8],
    bindings: &ProfileBindings,
) -> Result<(), RecognizedEffectError> {
    if record.schema_version != RECOGNIZED_EFFECT_SCHEMA {
        return Err(RecognizedEffectError::Invalid(
            "recognized-effect schema mismatch".into(),
        ));
    }
    validate_token("effect_id", &record.effect_id)?;
    validate_token("domain_id", &record.domain_id)?;
    validate_token("writer_identity", &record.writer_identity)?;
    validate_hash("canonical_expected_head", &record.canonical_expected_head)?;
    record.bindings.validate()?;
    // The record's declared profile must be canonical AND must be the profile
    // the bundle itself carries: a record that names one profile while
    // carrying another is a substitution, not a mismatch to reconcile.
    let profile = FinalityProfile::from_exact(&record.profile, &record.certificate_variant)?;
    let bundle_profile = FinalityProfile::from_exact(
        pointer_text(&record.bundle, "/checkpoint/profile")?,
        pointer_text(
            &record.bundle,
            "/checkpoint/finality_certificate/certificate_variant",
        )?,
    )?;
    if profile != bundle_profile {
        return Err(ProfileRefusal::ActiveProfileMismatch {
            expected: profile.profile().into(),
            actual: bundle_profile.profile().into(),
        }
        .into_error());
    }
    if pointer_text(&record.bundle, "/checkpoint/profile_contract_version")?
        != record.profile_contract_version
    {
        return Err(ProfileRefusal::ProfileContractVersionMismatch {
            expected: record.profile_contract_version.clone(),
            actual: pointer_text(&record.bundle, "/checkpoint/profile_contract_version")?
                .to_owned(),
        }
        .into_error());
    }
    if pointer_text(&record.bundle, "/checkpoint/previous_canonical_head")?
        != record.canonical_expected_head
    {
        return Err(RecognizedEffectError::StaleHead {
            expected: record.canonical_expected_head.clone(),
            actual: pointer_text(&record.bundle, "/checkpoint/previous_canonical_head")?.to_owned(),
        });
    }
    bindings.binding(profile).verify(&record.bundle)?;
    validate_bundle_authority(&record.bundle, &record.authority)?;
    validate_outbox(&record.outbox)?;
    let expected_hash = record_hash(record)?;
    if record.record_hash != expected_hash {
        return Err(RecognizedEffectError::Invalid(
            "recognized-effect record hash mismatch".into(),
        ));
    }
    let expected_bytes = serde_jcs::to_vec(record)
        .map_err(|error| RecognizedEffectError::Invalid(error.to_string()))?;
    if expected_bytes != canonical_bytes {
        return Err(RecognizedEffectError::Invalid(
            "recognized-effect canonical bytes mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_bundle_authority(
    bundle: &Value,
    authority: &AuthoritySnapshot,
) -> Result<(), RecognizedEffectError> {
    if pointer_text(bundle, "/checkpoint/domain_id")? != authority.domain_id
        || pointer_u64(bundle, "/checkpoint/authority_epoch")? != authority.authority_epoch
        || pointer_u64(bundle, "/checkpoint/authority_revocation_epoch")?
            != authority.revocation_epoch
        || pointer_text(bundle, "/checkpoint/finality_certificate/issuer_key_id")?
            != authority.issuer_key_id
    {
        return Err(RecognizedEffectError::StaleAuthority);
    }
    Ok(())
}

fn validate_outbox(outbox: &[OutboxIntent]) -> Result<(), RecognizedEffectError> {
    let mut ids = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for (index, intent) in outbox.iter().enumerate() {
        validate_token("consequence_id", &intent.consequence_id)?;
        if !REQUIRED_OUTBOX_KINDS.contains(&intent.kind.as_str()) {
            return Err(RecognizedEffectError::Invalid(format!(
                "unsupported outbox kind {}",
                intent.kind
            )));
        }
        if !ids.insert(intent.consequence_id.as_str()) || !kinds.insert(intent.kind.as_str()) {
            return Err(RecognizedEffectError::Invalid(
                "duplicate outbox identity or kind".into(),
            ));
        }
        if hash_value(&intent.payload)? != intent.payload_hash {
            return Err(RecognizedEffectError::Invalid(format!(
                "outbox payload hash mismatch for {}",
                intent.consequence_id
            )));
        }
        if REQUIRED_OUTBOX_KINDS.get(index).copied() != Some(intent.kind.as_str()) {
            return Err(RecognizedEffectError::Invalid(format!(
                "outbox consequence {} is out of order at index {index}",
                intent.kind
            )));
        }
    }
    if REQUIRED_OUTBOX_KINDS
        .iter()
        .any(|required| !kinds.contains(required))
    {
        return Err(RecognizedEffectError::Invalid(
            "recognized-effect outbox is incomplete".into(),
        ));
    }
    Ok(())
}

fn phase_for_outbox_kind(kind: &str) -> Result<Phase, RecognizedEffectError> {
    match kind {
        "projection_materialization" => Ok(Phase::ProjectionMaterialization),
        "root_publication" => Ok(Phase::RootPublication),
        "committed_status_publication" => Ok(Phase::CommittedStatusPublication),
        "transaction_committed" => Ok(Phase::TransactionCommittedEmission),
        "ack_publication" => Ok(Phase::AckPublication),
        other => Err(RecognizedEffectError::Invalid(format!(
            "unsupported outbox kind {other}"
        ))),
    }
}

fn validate_delivery_marker(
    marker: &DeliveryMarker,
    effect: &CommittedRecognizedEffect,
    intent: &OutboxIntent,
) -> Result<(), RecognizedEffectError> {
    if marker.effect_id != effect.record.effect_id
        || marker.consequence_id != intent.consequence_id
        || marker.kind != intent.kind
        || marker.payload_hash != intent.payload_hash
        || marker.record_hash != effect.record.record_hash
    {
        return Err(RecognizedEffectError::ReplayConflict {
            identity: intent.consequence_id.clone(),
        });
    }
    Ok(())
}

pub(crate) fn record_hash(record: &RecognizedEffectRecord) -> Result<String, RecognizedEffectError> {
    let mut preimage = record.clone();
    preimage.record_hash.clear();
    hash_value(&serde_json::to_value(preimage)?)
}

fn manifest_payloads(bundle: &Value) -> Result<Vec<(String, String, u64)>, RecognizedEffectError> {
    let values = bundle
        .pointer("/checkpoint/availability_manifest/payloads")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            RecognizedEffectError::Invalid("availability payload manifest absent".into())
        })?;
    let mut result = Vec::with_capacity(values.len());
    let mut refs = BTreeSet::new();
    for value in values {
        let payload_ref = object_text(value, "payload_ref")?.to_owned();
        let payload_hash = object_text(value, "payload_hash")?.to_owned();
        let byte_length = value
            .get("byte_length")
            .and_then(Value::as_u64)
            .ok_or_else(|| RecognizedEffectError::Invalid("payload byte_length absent".into()))?;
        if !refs.insert(payload_ref.clone()) || byte_length == 0 {
            return Err(RecognizedEffectError::Invalid(
                "duplicate or empty availability payload".into(),
            ));
        }
        validate_hash("payload_hash", &payload_hash)?;
        result.push((payload_ref, payload_hash, byte_length));
    }
    Ok(result)
}

fn supplied_payloads(bundle: &Value) -> Result<BTreeMap<String, Vec<u8>>, RecognizedEffectError> {
    let values = bundle
        .get("availability_payloads")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            RecognizedEffectError::Invalid("availability payload bytes absent".into())
        })?;
    let mut result = BTreeMap::new();
    for value in values {
        let payload_ref = object_text(value, "payload_ref")?.to_owned();
        let encoded = object_text(value, "payload_base64")?;
        let bytes = BASE64.decode(encoded).map_err(|error| {
            RecognizedEffectError::Invalid(format!("availability base64: {error}"))
        })?;
        if result.insert(payload_ref.clone(), bytes).is_some() {
            return Err(RecognizedEffectError::Invalid(format!(
                "duplicate availability bytes for {payload_ref}"
            )));
        }
    }
    Ok(result)
}

fn require_nonempty_array(value: &Value, pointer: &str) -> Result<(), RecognizedEffectError> {
    if value
        .pointer(pointer)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
    {
        Ok(())
    } else {
        Err(RecognizedEffectError::Invalid(format!(
            "required material absent at {pointer}"
        )))
    }
}

fn require_array(value: &Value, pointer: &str) -> Result<(), RecognizedEffectError> {
    if value.pointer(pointer).and_then(Value::as_array).is_some() {
        Ok(())
    } else {
        Err(RecognizedEffectError::Invalid(format!(
            "required material absent at {pointer}"
        )))
    }
}

fn pointer_text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, RecognizedEffectError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| RecognizedEffectError::Invalid(format!("required text absent at {pointer}")))
}

fn pointer_u64(value: &Value, pointer: &str) -> Result<u64, RecognizedEffectError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            RecognizedEffectError::Invalid(format!("required integer absent at {pointer}"))
        })
}

fn object_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, RecognizedEffectError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| RecognizedEffectError::Invalid(format!("required text absent: {key}")))
}

pub(crate) fn validate_token(name: &str, value: &str) -> Result<(), RecognizedEffectError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(RecognizedEffectError::Invalid(format!(
            "{name} is not a bounded stable identity"
        )));
    }
    Ok(())
}

pub(crate) fn validate_hash(name: &str, value: &str) -> Result<(), RecognizedEffectError> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else {
        Err(RecognizedEffectError::Invalid(format!(
            "{name} is not a canonical sha256 identity"
        )))
    }
}

pub(crate) fn hash_value(value: &Value) -> Result<String, RecognizedEffectError> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|error| RecognizedEffectError::Invalid(format!("JCS encoding: {error}")))?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn safe_hash(identity: &str) -> String {
    format!("{:x}", Sha256::digest(identity.as_bytes()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RecognizedEffectError> {
    let parent = path
        .parent()
        .ok_or_else(|| RecognizedEffectError::Invalid("atomic path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RecognizedEffectError::Invalid("atomic path has no filename".into()))?;
    let temporary = parent.join(format!(".{name}.prepared"));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    AdmissionValidation,
    ProfileResolution,
    AuthorityRevalidation,
    StateTransitionConstruction,
    IndividualReceiptCreation,
    CheckpointConstruction,
    CertificateConstructionSigning,
    AvailabilityBytePersistence,
    AvailabilityManifestValidation,
    FrameConstruction,
    CanonicalWrite,
    CanonicalFsync,
    HeadRootAdvancement,
    ProjectionMaterialization,
    RootPublication,
    CommittedStatusPublication,
    TransactionCommittedEmission,
    AckPublication,
    ControlRecordConstruction,
    GovernanceValidation,
    WriterFenceRetirement,
}

impl Phase {
    /// Effect preparation: everything before any durable claim exists.
    pub const EFFECT_PREPARATION: [Self; 9] = [
        Self::AdmissionValidation,
        Self::ProfileResolution,
        Self::AuthorityRevalidation,
        Self::StateTransitionConstruction,
        Self::IndividualReceiptCreation,
        Self::CheckpointConstruction,
        Self::CertificateConstructionSigning,
        Self::AvailabilityBytePersistence,
        Self::AvailabilityManifestValidation,
    ];

    /// The linearization window. Crossing it is what makes a record true.
    pub const LINEARIZATION: [Self; 4] = [
        Self::FrameConstruction,
        Self::CanonicalWrite,
        Self::CanonicalFsync,
        Self::HeadRootAdvancement,
    ];

    /// Rebuildable, idempotent consequences of a committed record.
    pub const CONSEQUENCE: [Self; 5] = [
        Self::ProjectionMaterialization,
        Self::RootPublication,
        Self::CommittedStatusPublication,
        Self::TransactionCommittedEmission,
        Self::AckPublication,
    ];

    /// Control-plane preparation for a cutover or freeze.
    pub const CONTROL: [Self; 3] = [
        Self::ControlRecordConstruction,
        Self::GovernanceValidation,
        Self::WriterFenceRetirement,
    ];

    pub const ALL: [Self; 21] = [
        Self::AdmissionValidation,
        Self::ProfileResolution,
        Self::AuthorityRevalidation,
        Self::StateTransitionConstruction,
        Self::IndividualReceiptCreation,
        Self::CheckpointConstruction,
        Self::CertificateConstructionSigning,
        Self::AvailabilityBytePersistence,
        Self::AvailabilityManifestValidation,
        Self::FrameConstruction,
        Self::CanonicalWrite,
        Self::CanonicalFsync,
        Self::HeadRootAdvancement,
        Self::ProjectionMaterialization,
        Self::RootPublication,
        Self::CommittedStatusPublication,
        Self::TransactionCommittedEmission,
        Self::AckPublication,
        Self::ControlRecordConstruction,
        Self::GovernanceValidation,
        Self::WriterFenceRetirement,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::AdmissionValidation => "admission_validation",
            Self::ProfileResolution => "profile_resolution",
            Self::ControlRecordConstruction => "control_record_construction",
            Self::GovernanceValidation => "governance_validation",
            Self::WriterFenceRetirement => "writer_fence_retirement",
            Self::AuthorityRevalidation => "authority_revalidation",
            Self::StateTransitionConstruction => "state_transition_construction",
            Self::IndividualReceiptCreation => "individual_receipt_creation",
            Self::CheckpointConstruction => "checkpoint_construction",
            Self::CertificateConstructionSigning => "certificate_construction_signing",
            Self::AvailabilityBytePersistence => "availability_byte_persistence",
            Self::AvailabilityManifestValidation => "availability_manifest_validation",
            Self::FrameConstruction => "agentgres_frame_construction",
            Self::CanonicalWrite => "canonical_write",
            Self::CanonicalFsync => "canonical_fsync",
            Self::HeadRootAdvancement => "head_root_advancement",
            Self::ProjectionMaterialization => "projection_materialization",
            Self::RootPublication => "root_publication",
            Self::CommittedStatusPublication => "committed_status_publication",
            Self::TransactionCommittedEmission => "transaction_committed_emission",
            Self::AckPublication => "ack_publication",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Boundary {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CrashPoint {
    pub boundary: Boundary,
    pub phase: Phase,
}

impl CrashPoint {
    pub const fn before(phase: Phase) -> Self {
        Self {
            boundary: Boundary::Before,
            phase,
        }
    }

    pub const fn after(phase: Phase) -> Self {
        Self {
            boundary: Boundary::After,
            phase,
        }
    }
}

impl std::fmt::Display for CrashPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let boundary = match self.boundary {
            Boundary::Before => "before",
            Boundary::After => "after",
        };
        write!(f, "{boundary}:{}", self.phase.name())
    }
}

impl std::str::FromStr for CrashPoint {
    type Err = RecognizedEffectError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (boundary, phase) = value.split_once(':').ok_or_else(|| {
            RecognizedEffectError::Invalid("crash point must be boundary:phase".into())
        })?;
        if phase.is_empty() || phase.contains(':') {
            return Err(RecognizedEffectError::Invalid(
                "crash point is malformed".into(),
            ));
        }
        let boundary = match boundary {
            "before" => Boundary::Before,
            "after" => Boundary::After,
            _ => {
                return Err(RecognizedEffectError::Invalid(
                    "unknown crash boundary".into(),
                ))
            }
        };
        let phase = Phase::ALL
            .into_iter()
            .find(|candidate| candidate.name() == phase)
            .ok_or_else(|| RecognizedEffectError::Invalid("unknown crash phase".into()))?;
        Ok(Self { boundary, phase })
    }
}

#[cfg(test)]
mod tests;
