//! Agentgres-owned atomic recognized effects for `single_authority_v1`.
//!
//! Availability bytes and a signed candidate are preparation material.  They
//! become authoritative only when the complete record is admitted in the
//! dedicated Agentgres mux domain and its rooted batch is device-flushed.
//! Everything after that boundary is a rebuildable, idempotent consequence of
//! the committed record.

#[cfg(test)]
use crate::mux::MuxCommitTestPoint;
use crate::mux::{ExactProjection, MuxEngine};
use crate::{Durability, Operation, Refusal};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_finality::{emit_single_authority, verify_bundle, VerificationError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const RECOGNIZED_EFFECT_SCHEMA: &str = "ioi.agentgres-recognized-effect.v1";
pub const RECOGNIZED_EFFECT_DOMAIN: &str = "ioi.recognized-effect.single-authority.v1";
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
    #[cfg(test)]
    InjectedCrash(CrashPoint),
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
    effects: BTreeMap<String, CommittedRecognizedEffect>,
    #[cfg(test)]
    armed_crash: Option<CrashPoint>,
    #[cfg(test)]
    observed_points: Vec<CrashPoint>,
}

impl RecognizedEffectStore {
    pub fn open(
        root: &Path,
        domain_id: impl Into<String>,
        initial_canonical_head: impl Into<String>,
    ) -> Result<Self, RecognizedEffectError> {
        let domain_id = domain_id.into();
        let initial_canonical_head = initial_canonical_head.into();
        validate_token("domain_id", &domain_id)?;
        validate_hash("initial_canonical_head", &initial_canonical_head)?;
        fs::create_dir_all(root)?;
        fs::create_dir_all(root.join("availability"))?;
        fs::create_dir_all(root.join("deliveries"))?;
        fs::create_dir_all(root.join("projections"))?;
        let mux_dir = root.join("canonical");
        let mux = MuxEngine::open(&mux_dir, true)?;
        let object_ref = format!("recognized-effect://{domain_id}");
        let mut store = Self {
            root: root.to_path_buf(),
            domain_id,
            object_ref,
            initial_canonical_head: initial_canonical_head.clone(),
            canonical_head: initial_canonical_head,
            mux,
            effects: BTreeMap::new(),
            #[cfg(test)]
            armed_crash: None,
            #[cfg(test)]
            observed_points: Vec::new(),
        };
        store.recover()?;
        Ok(store)
    }

    pub fn canonical_head(&self) -> &str {
        &self.canonical_head
    }

    pub fn committed(&self, effect_id: &str) -> Option<&CommittedRecognizedEffect> {
        self.effects.get(effect_id)
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
        self.around(Phase::AdmissionValidation, |_store| {
            let profile = pointer_text(&bundle_template, "/checkpoint/profile")?;
            let variant = pointer_text(
                &bundle_template,
                "/checkpoint/finality_certificate/certificate_variant",
            )?;
            if profile != "single_authority" || variant != "single_authority_v1" {
                return Err(RecognizedEffectError::Invalid(format!(
                    "unsupported profile={profile} variant={variant}"
                )));
            }
            validate_outbox(&outbox)?;
            validate_token("effect_id", &effect_id)?;
            Ok(())
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

        let bundle = self.around(Phase::CertificateConstructionSigning, |_store| {
            emit_single_authority(bundle_template, issuer_key_id, signing_key)
                .map_err(RecognizedEffectError::Finality)
        })?;
        verify_bundle(&bundle)?;
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
            agentgres_expected_head: self
                .mux
                .domain_head(RECOGNIZED_EFFECT_DOMAIN, &self.object_ref)
                .cloned(),
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
        validate_record(&prepared.record, &prepared.canonical_bytes)?;
        self.verify_availability(&prepared.record.bundle)?;
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
        if previous_head != self.canonical_head {
            return Err(RecognizedEffectError::StaleHead {
                expected: previous_head.to_owned(),
                actual: self.canonical_head.clone(),
            });
        }
        let actual_agentgres_head = self
            .mux
            .domain_head(RECOGNIZED_EFFECT_DOMAIN, &self.object_ref)
            .cloned();
        if actual_agentgres_head != prepared.record.agentgres_expected_head {
            return Err(RecognizedEffectError::ReplayConflict {
                identity: prepared.record.effect_id,
            });
        }

        self.hit(CrashPoint::before(Phase::FrameConstruction))?;
        let operation = Operation {
            domain: RECOGNIZED_EFFECT_DOMAIN.into(),
            object_ref: self.object_ref.clone(),
            op_kind: "recognized_effect.commit".into(),
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
            .admit_batch(vec![operation])
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
        for intent in &effect.record.outbox {
            let path = self.delivery_path(&intent.consequence_id);
            if !path.exists() {
                pending.push(intent.clone());
                continue;
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
        let intent = effect
            .record
            .outbox
            .iter()
            .find(|intent| intent.consequence_id == consequence_id)
            .ok_or_else(|| {
                RecognizedEffectError::Invalid(format!(
                    "consequence {consequence_id} is not in committed outbox"
                ))
            })?;
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

    fn recover(&mut self) -> Result<(), RecognizedEffectError> {
        self.effects.clear();
        self.canonical_head = self.initial_canonical_head.clone();
        let history = self
            .mux
            .project_exact_history(RECOGNIZED_EFFECT_DOMAIN, &self.object_ref)?;
        let mut prior_agentgres_head: Option<String> = None;
        for projection in history {
            let record: RecognizedEffectRecord =
                serde_json::from_value(projection.operation.payload.clone())?;
            let bytes = serde_jcs::to_vec(&record)
                .map_err(|error| RecognizedEffectError::Invalid(error.to_string()))?;
            validate_record(&record, &bytes)?;
            // The signed bundle carries the exact verifier input bytes.  The
            // CAS is availability preparation/projection, so recovery may
            // restore a missing side file from canonical bytes but may never
            // accept a conflicting file under the same content identity.
            self.persist_availability(&record.bundle)?;
            self.verify_availability(&record.bundle)?;
            if record.domain_id != self.domain_id {
                return Err(RecognizedEffectError::Invalid(
                    "recovered record domain mismatch".into(),
                ));
            }
            if record.agentgres_expected_head != prior_agentgres_head {
                return Err(RecognizedEffectError::Invalid(
                    "recovered Agentgres predecessor mismatch".into(),
                ));
            }
            let previous = pointer_text(&record.bundle, "/checkpoint/previous_canonical_head")?;
            if previous != self.canonical_head {
                return Err(RecognizedEffectError::Invalid(
                    "recovered canonical predecessor mismatch".into(),
                ));
            }
            if self.effects.contains_key(&record.effect_id) {
                return Err(RecognizedEffectError::ReplayConflict {
                    identity: record.effect_id,
                });
            }
            self.canonical_head =
                pointer_text(&record.bundle, "/checkpoint/resulting_canonical_head")?.to_owned();
            prior_agentgres_head = Some(projection.head.clone());
            let effect = committed_from_projection(record, bytes, projection);
            self.effects.insert(effect.record.effect_id.clone(), effect);
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
) -> Result<(), RecognizedEffectError> {
    if record.schema_version != RECOGNIZED_EFFECT_SCHEMA {
        return Err(RecognizedEffectError::Invalid(
            "recognized-effect schema mismatch".into(),
        ));
    }
    validate_token("effect_id", &record.effect_id)?;
    validate_token("domain_id", &record.domain_id)?;
    verify_bundle(&record.bundle)?;
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
    for intent in outbox {
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

fn record_hash(record: &RecognizedEffectRecord) -> Result<String, RecognizedEffectError> {
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

fn validate_token(name: &str, value: &str) -> Result<(), RecognizedEffectError> {
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

fn validate_hash(name: &str, value: &str) -> Result<(), RecognizedEffectError> {
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

fn hash_value(value: &Value) -> Result<String, RecognizedEffectError> {
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
}

impl Phase {
    pub const ALL: [Self; 17] = [
        Self::AdmissionValidation,
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
    ];

    fn name(self) -> &'static str {
        match self {
            Self::AdmissionValidation => "admission_validation",
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
