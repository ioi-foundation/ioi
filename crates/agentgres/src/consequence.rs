//! Durable effect-native consequence execution.
//!
//! The local claim is flushed before any external invocation. Once an
//! invocation can have started, restart and retry are reconciliation-only:
//! they query the same atomic idempotency register and never blindly invoke
//! the mutation again.

use crate::recognized_effect::CommittedRecognizedEffect;
use fs2::FileExt;
use ioi_types::app::consensus::VerifiedGuaranteeV1;
use ioi_types::app::{
    ConsequenceHash, EffectFenceV1, EffectManifestV1, ExternalResourceProfileV1,
    ExternalResourceRecordV1, ReconciliationPolicyV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const RECEIPT_SCHEMA: &str = "ioi.aft-consequence-receipt.v1";
const CLAIM_DOMAIN: &[u8] = b"ioi::aft::consequence-claim::v1\0";
const RECONCILIATION_DOMAIN: &[u8] = b"ioi::aft::consequence-reconciliation::v1\0";
const RECEIPT_DOMAIN: &[u8] = b"ioi::aft::consequence-receipt::v1\0";
const AMBIGUITY_DOMAIN: &[u8] = b"ioi::aft::consequence-ambiguity::v1\0";
const VIOLATION_DOMAIN: &[u8] = b"ioi::aft::consequence-violation::v1\0";

/// Opaque binding from one Agentgres-linearized runtime-v3 effect to its
/// exact consequence manifest and independently verified assurance vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedEffectAuthorizationV1 {
    effect_id: String,
    manifest_root: ConsequenceHash,
    achieved_guarantee_root: ConsequenceHash,
    authority_epoch: u64,
    authority_snapshot_root: ConsequenceHash,
    authorization_receipt_root: ConsequenceHash,
}

impl AcceptedEffectAuthorizationV1 {
    /// Commitment to the Agentgres record, manifest and achieved assurance.
    pub fn commitment(&self) -> ConsequenceHash {
        self.authorization_receipt_root
    }

    /// Reverify the committed runtime-v3 bundle and bind its achieved
    /// assurance to the manifest root carried through Agentgres admission.
    pub fn from_committed(
        committed: &CommittedRecognizedEffect,
        manifest: &EffectManifestV1,
    ) -> Result<Self, ConsequenceError> {
        manifest.validate().map_err(type_error)?;
        let manifest_root = manifest.commitment().map_err(type_error)?;
        let expected_manifest_text = format_hash(manifest_root);
        if committed.record.effect_id != manifest.effect_id
            || committed.record.effect_manifest_root.as_deref()
                != Some(expected_manifest_text.as_str())
        {
            return Err(ConsequenceError::ReplayConflict);
        }
        let claim = ioi_finality::verify_runtime_bundle_v3(&committed.record.bundle)
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        if !claim.effect_committed_in_block || claim.domain_id != committed.record.domain_id {
            return Err(ConsequenceError::Invalid(
                "Agentgres record does not carry one verified effect authorization".into(),
            ));
        }
        let achieved_guarantee_root = claim
            .assurance
            .commitment()
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        let authority_snapshot_root = canonical_hash(
            b"ioi::aft::effect-authority-snapshot::v1\0",
            &committed.record.authority,
        )?;
        let authorization_receipt_root = canonical_hash(
            b"ioi::aft::accepted-effect-authorization::v1\0",
            &(
                &committed.record.record_hash,
                &committed.agentgres_root,
                committed.operation_sequence,
                manifest_root,
                achieved_guarantee_root,
                committed.record.authority.authority_epoch,
                authority_snapshot_root,
            ),
        )?;
        Ok(Self {
            effect_id: manifest.effect_id.clone(),
            manifest_root,
            achieved_guarantee_root,
            authority_epoch: committed.record.authority.authority_epoch,
            authority_snapshot_root,
            authorization_receipt_root,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsequencePhaseV1 {
    Authorized,
    Claimed,
    InFlight,
    Executed,
    Unknown,
    Reconciled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsequenceStateV1 {
    Authorized {
        authorization_root: ConsequenceHash,
        achieved_guarantee_root: ConsequenceHash,
    },
    Claimed {
        claim_root: ConsequenceHash,
    },
    InFlight {
        claim_root: ConsequenceHash,
    },
    Executed {
        claim_root: ConsequenceHash,
        resource_record: ExternalResourceRecordV1,
        resource_record_root: ConsequenceHash,
    },
    Unknown {
        claim_root: ConsequenceHash,
        reason: AmbiguityReasonV1,
        ambiguity_root: ConsequenceHash,
        observations: u32,
    },
    Reconciled {
        claim_root: ConsequenceHash,
        resolution: ReconciliationResolutionV1,
        reconciliation_root: ConsequenceHash,
    },
}

impl ConsequenceStateV1 {
    pub fn phase(&self) -> ConsequencePhaseV1 {
        match self {
            Self::Authorized { .. } => ConsequencePhaseV1::Authorized,
            Self::Claimed { .. } => ConsequencePhaseV1::Claimed,
            Self::InFlight { .. } => ConsequencePhaseV1::InFlight,
            Self::Executed { .. } => ConsequencePhaseV1::Executed,
            Self::Unknown { .. } => ConsequencePhaseV1::Unknown,
            Self::Reconciled { .. } => ConsequencePhaseV1::Reconciled,
        }
    }

    fn claim_root(&self) -> Option<ConsequenceHash> {
        match self {
            Self::Authorized { .. } => None,
            Self::Claimed { claim_root }
            | Self::InFlight { claim_root }
            | Self::Executed { claim_root, .. }
            | Self::Unknown { claim_root, .. }
            | Self::Reconciled { claim_root, .. } => Some(*claim_root),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resolution", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReconciliationResolutionV1 {
    Executed {
        resource_record: ExternalResourceRecordV1,
        resource_record_root: ConsequenceHash,
    },
    Absent,
}

/// A locally observed ambiguity class. None is itself attribution evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum AmbiguityReasonV1 {
    InvocationResultAmbiguous,
    RestartedFromInFlight,
    ReconciliationLookupAmbiguous,
    DefinitiveRejection { reason_hash: ConsequenceHash },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsequenceTransitionV1 {
    pub sequence: u64,
    pub from: Option<ConsequencePhaseV1>,
    pub to: ConsequencePhaseV1,
    pub evidence_root: ConsequenceHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsequenceReceiptV1 {
    pub schema_version: String,
    pub manifest: EffectManifestV1,
    pub manifest_root: ConsequenceHash,
    pub achieved_guarantee_root: ConsequenceHash,
    pub state: ConsequenceStateV1,
    pub trace: Vec<ConsequenceTransitionV1>,
    pub generation: u64,
    pub receipt_root: ConsequenceHash,
}

impl ConsequenceReceiptV1 {
    pub fn validate(&self) -> Result<(), ConsequenceError> {
        if self.schema_version != RECEIPT_SCHEMA
            || self.manifest.commitment().map_err(type_error)? != self.manifest_root
            || self.trace.is_empty()
            || self.generation != self.trace.len() as u64
            || self.trace.last().map(|step| step.to) != Some(self.state.phase())
            || self.trace.last().map(|step| step.evidence_root)
                != Some(state_evidence_root(&self.state)?)
        {
            return Err(ConsequenceError::CorruptReceipt);
        }
        validate_trace(&self.trace)?;
        validate_state(&self.manifest, self.achieved_guarantee_root, &self.state)?;
        if let ConsequenceStateV1::Reconciled {
            resolution,
            reconciliation_root: stored,
            ..
        } = &self.state
        {
            if reconciliation_root(self, resolution)? != *stored {
                return Err(ConsequenceError::CorruptReceipt);
            }
        }
        if receipt_root(self)? != self.receipt_root {
            return Err(ConsequenceError::CorruptReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtomicMutationResultV1 {
    Inserted(ExternalResourceRecordV1),
    Existing(ExternalResourceRecordV1),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceInvocationErrorV1 {
    /// The caller cannot know whether the atomic mutation happened.
    Ambiguous,
    /// The endpoint proved the request was not applied.
    DefinitiveRejection(String),
    /// A conflicting record was observed.
    Conflict(ExternalResourceRecordV1),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceLookupErrorV1 {
    /// Lookup produced no reliable observation. This is not blame evidence.
    Ambiguous,
    /// A conflicting register record was observed.
    Conflict(ExternalResourceRecordV1),
}

/// An external endpoint exposing one declared atomic idempotency contract.
pub trait ExternalResourceV1 {
    fn profile(&self) -> &ExternalResourceProfileV1;

    /// Invoke the one atomic mutation. The runtime calls this at most once for
    /// a manifest, and never from reconciliation or restart recovery.
    fn invoke_atomic(
        &mut self,
        manifest: &EffectManifestV1,
    ) -> Result<AtomicMutationResultV1, ResourceInvocationErrorV1>;

    /// Observe the same idempotency key without requesting a mutation.
    fn lookup(
        &mut self,
        resource_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ExternalResourceRecordV1>, ResourceLookupErrorV1>;

    /// Verify endpoint evidence under the exact committed resource profile.
    /// Returning false keeps a contradiction unattributed.
    fn verify_record_evidence(&self, record: &ExternalResourceRecordV1) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceViolationKindV1 {
    ScopeMismatch,
    RequestSubstitution,
    PredecessorSubstitution,
    OutcomeSubstitution,
}

/// Transferable contradiction exists only when the resource supplied
/// committed evidence. Unsigned network ambiguity never constructs this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceViolationEvidenceV1 {
    pub manifest_root: ConsequenceHash,
    pub observed: ExternalResourceRecordV1,
    pub kind: ResourceViolationKindV1,
    pub verifier_profile_root: ConsequenceHash,
    pub proof_root: ConsequenceHash,
}

impl ResourceViolationEvidenceV1 {
    pub fn verify_with(
        &self,
        manifest: &EffectManifestV1,
        verifier: &dyn ExternalResourceV1,
    ) -> Result<(), ConsequenceError> {
        if manifest.commitment().map_err(type_error)? != self.manifest_root
            || self.observed.evidence.is_none()
            || record_violation_kind(manifest, &self.observed) != Some(self.kind.clone())
            || verifier.profile() != &manifest.resource_profile
            || manifest.resource_profile.commitment().map_err(type_error)?
                != self.verifier_profile_root
            || !verifier.verify_record_evidence(&self.observed)
            || violation_root(
                self.manifest_root,
                &self.observed,
                &self.kind,
                self.verifier_profile_root,
            )? != self.proof_root
        {
            return Err(ConsequenceError::InvalidViolationEvidence);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConsequenceError {
    Io(std::io::Error),
    Invalid(String),
    PolicyUnsatisfied,
    ProfileMismatch,
    FenceExpired,
    ReplayConflict,
    UnsafeResourceContract,
    WrongState(ConsequencePhaseV1),
    Ambiguous,
    ReconciliationExhausted,
    DefinitiveRejection(String),
    UnattributedResourceConflict,
    TransferableViolation(ResourceViolationEvidenceV1),
    InvalidViolationEvidence,
    CorruptReceipt,
    StoreBusy,
    #[cfg(test)]
    InjectedCrash(ConsequenceCrashPoint),
}

impl std::fmt::Display for ConsequenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ConsequenceError {}

impl From<std::io::Error> for ConsequenceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsequenceCrashPoint {
    AfterAuthorized,
    AfterClaimed,
    AfterInFlight,
    AfterInvocation,
    AfterExecuted,
    AfterUnknown,
    AfterLookup,
    AfterReconciled,
}

/// Single-owner durable consequence state. The held file lock prevents two
/// local clones from issuing the external call concurrently.
pub struct ConsequenceStore {
    root: PathBuf,
    _lock: File,
    #[cfg(test)]
    armed_crash: Option<ConsequenceCrashPoint>,
}

impl ConsequenceStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ConsequenceError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("effects"))?;
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(root.join("consequence.lock"))?;
        FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                ConsequenceError::StoreBusy
            } else {
                ConsequenceError::Io(error)
            }
        })?;
        Ok(Self {
            root,
            _lock: lock,
            #[cfg(test)]
            armed_crash: None,
        })
    }

    #[cfg(test)]
    pub fn arm_crash(&mut self, point: ConsequenceCrashPoint) {
        self.armed_crash = Some(point);
    }

    pub fn authorize(
        &mut self,
        manifest: EffectManifestV1,
        achieved: &VerifiedGuaranteeV1,
        authorization: &AcceptedEffectAuthorizationV1,
        current_height: u64,
    ) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        manifest.validate().map_err(type_error)?;
        validate_fence(&manifest.fence, current_height, achieved, authorization)?;
        if !manifest.required_guarantees.is_satisfied_by(achieved) {
            return Err(ConsequenceError::PolicyUnsatisfied);
        }
        let advertised = manifest
            .resource_profile
            .advertised_externalization()
            .map_err(type_error)?;
        let actual = &achieved.achieved().externalization;
        if actual.adapter_profile_hash != advertised.adapter_profile_hash
            || actual.mode != advertised.mode
            || actual.at_most_once != advertised.at_most_once
            || achieved.achieved().crypto.externalization_pq
                != manifest.resource_profile.externalization_pq
        {
            return Err(ConsequenceError::ProfileMismatch);
        }
        if manifest.irreversible && !manifest.resource_profile.contract.supports_at_most_once() {
            return Err(ConsequenceError::UnsafeResourceContract);
        }
        let manifest_root = manifest.commitment().map_err(type_error)?;
        let achieved_guarantee_root = achieved
            .achieved()
            .commitment()
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        if authorization.effect_id != manifest.effect_id
            || authorization.manifest_root != manifest_root
            || authorization.achieved_guarantee_root != achieved_guarantee_root
            || authorization.authorization_receipt_root == [0; 32]
        {
            return Err(ConsequenceError::ReplayConflict);
        }
        let path = self.receipt_path(&manifest.effect_id);
        if path.exists() {
            let existing = self.load(&manifest.effect_id)?;
            if existing.manifest_root == manifest_root
                && existing.achieved_guarantee_root == achieved_guarantee_root
            {
                return Ok(existing);
            }
            return Err(ConsequenceError::ReplayConflict);
        }
        let state = ConsequenceStateV1::Authorized {
            authorization_root: authorization.authorization_receipt_root,
            achieved_guarantee_root,
        };
        let evidence_root = state_evidence_root(&state)?;
        let mut receipt = ConsequenceReceiptV1 {
            schema_version: RECEIPT_SCHEMA.into(),
            manifest,
            manifest_root,
            achieved_guarantee_root,
            state,
            trace: vec![ConsequenceTransitionV1 {
                sequence: 1,
                from: None,
                to: ConsequencePhaseV1::Authorized,
                evidence_root,
            }],
            generation: 1,
            receipt_root: [0; 32],
        };
        persist_receipt(&path, &mut receipt)?;
        self.hit(ConsequenceCrashPoint::AfterAuthorized)?;
        Ok(receipt)
    }

    /// Execute from `Authorized`/`Claimed`. If durable state is already
    /// `InFlight` or `Unknown`, execution is forbidden and reconciliation is
    /// required.
    pub fn execute(
        &mut self,
        effect_id: &str,
        resource: &mut dyn ExternalResourceV1,
    ) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        let mut receipt = self.load(effect_id)?;
        if resource.profile() != &receipt.manifest.resource_profile {
            return Err(ConsequenceError::ProfileMismatch);
        }
        if !resource.profile().contract.supports_at_most_once() {
            return Err(ConsequenceError::UnsafeResourceContract);
        }
        if matches!(receipt.state, ConsequenceStateV1::Authorized { .. }) {
            let claim_root = claim_root(&receipt)?;
            transition(&mut receipt, ConsequenceStateV1::Claimed { claim_root })?;
            persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
            self.hit(ConsequenceCrashPoint::AfterClaimed)?;
        }
        let claim_root = match receipt.state {
            ConsequenceStateV1::Claimed { claim_root } => claim_root,
            _ => return Err(ConsequenceError::WrongState(receipt.state.phase())),
        };
        transition(&mut receipt, ConsequenceStateV1::InFlight { claim_root })?;
        persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
        self.hit(ConsequenceCrashPoint::AfterInFlight)?;

        let result = resource.invoke_atomic(&receipt.manifest);
        self.hit(ConsequenceCrashPoint::AfterInvocation)?;
        match result {
            Ok(AtomicMutationResultV1::Inserted(record))
            | Ok(AtomicMutationResultV1::Existing(record)) => {
                validate_live_resource_record(&receipt.manifest, &record, resource)?;
                let resource_record_root = record.commitment().map_err(type_error)?;
                transition(
                    &mut receipt,
                    ConsequenceStateV1::Executed {
                        claim_root,
                        resource_record: record,
                        resource_record_root,
                    },
                )?;
                persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
                self.hit(ConsequenceCrashPoint::AfterExecuted)?;
                Ok(receipt)
            }
            Err(ResourceInvocationErrorV1::Ambiguous) => {
                mark_unknown(
                    &mut receipt,
                    AmbiguityReasonV1::InvocationResultAmbiguous,
                    0,
                )?;
                persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
                self.hit(ConsequenceCrashPoint::AfterUnknown)?;
                Err(ConsequenceError::Ambiguous)
            }
            Err(ResourceInvocationErrorV1::DefinitiveRejection(reason)) => {
                mark_unknown(
                    &mut receipt,
                    AmbiguityReasonV1::DefinitiveRejection {
                        reason_hash: hash_parts(b"definitive-rejection", &[reason.as_bytes()]),
                    },
                    0,
                )?;
                persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
                Err(ConsequenceError::DefinitiveRejection(reason))
            }
            Err(ResourceInvocationErrorV1::Conflict(observed)) => {
                resource_conflict(&receipt.manifest, observed, resource)
            }
        }
    }

    /// Recover a durable in-flight invocation without replaying it. `Claimed`
    /// is safe to resume because `InFlight` is persisted immediately before
    /// the only external call; `InFlight` itself is always converted to
    /// `Unknown` and must be reconciled.
    pub fn recover(&mut self, effect_id: &str) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        let mut receipt = self.load(effect_id)?;
        if matches!(receipt.state, ConsequenceStateV1::InFlight { .. }) {
            mark_unknown(&mut receipt, AmbiguityReasonV1::RestartedFromInFlight, 0)?;
            persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
        }
        Ok(receipt)
    }

    pub fn reconcile(
        &mut self,
        effect_id: &str,
        resource: &mut dyn ExternalResourceV1,
    ) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        let mut receipt = self.recover(effect_id)?;
        if resource.profile() != &receipt.manifest.resource_profile {
            return Err(ConsequenceError::ProfileMismatch);
        }
        let maximum_observations = match receipt.manifest.reconciliation {
            ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations,
            } => maximum_observations,
            ReconciliationPolicyV1::NoSafeReconciliation => {
                return Err(ConsequenceError::UnsafeResourceContract)
            }
        };
        let (claim_root, observations) = match receipt.state {
            ConsequenceStateV1::Executed { claim_root, .. } => (claim_root, 0),
            ConsequenceStateV1::Unknown {
                claim_root,
                observations,
                ..
            } => (claim_root, observations),
            ConsequenceStateV1::Reconciled { .. } => return Ok(receipt),
            _ => return Err(ConsequenceError::WrongState(receipt.state.phase())),
        };
        let observation = resource.lookup(
            &receipt.manifest.resource_id,
            &receipt.manifest.idempotency_key,
        );
        self.hit(ConsequenceCrashPoint::AfterLookup)?;
        let resolution = match observation {
            Ok(Some(record)) => {
                validate_live_resource_record(&receipt.manifest, &record, resource)?;
                ReconciliationResolutionV1::Executed {
                    resource_record_root: record.commitment().map_err(type_error)?,
                    resource_record: record,
                }
            }
            Ok(None) => ReconciliationResolutionV1::Absent,
            Err(ResourceLookupErrorV1::Ambiguous) => {
                let next = observations.saturating_add(1);
                mark_unknown(
                    &mut receipt,
                    AmbiguityReasonV1::ReconciliationLookupAmbiguous,
                    next,
                )?;
                persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
                return if next >= maximum_observations {
                    Err(ConsequenceError::ReconciliationExhausted)
                } else {
                    Err(ConsequenceError::Ambiguous)
                };
            }
            Err(ResourceLookupErrorV1::Conflict(observed)) => {
                return resource_conflict(&receipt.manifest, observed, resource)
            }
        };
        let reconciliation_root = reconciliation_root(&receipt, &resolution)?;
        transition(
            &mut receipt,
            ConsequenceStateV1::Reconciled {
                claim_root,
                resolution,
                reconciliation_root,
            },
        )?;
        persist_receipt(&self.receipt_path(effect_id), &mut receipt)?;
        self.hit(ConsequenceCrashPoint::AfterReconciled)?;
        Ok(receipt)
    }

    pub fn load(&self, effect_id: &str) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        let bytes = fs::read(self.receipt_path(effect_id))?;
        let receipt: ConsequenceReceiptV1 = serde_json::from_slice(&bytes)
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        if receipt.manifest.effect_id != effect_id {
            return Err(ConsequenceError::CorruptReceipt);
        }
        receipt.validate()?;
        Ok(receipt)
    }

    fn receipt_path(&self, effect_id: &str) -> PathBuf {
        self.root
            .join("effects")
            .join(format!("{}.json", hex_hash(effect_id.as_bytes())))
    }

    #[cfg(test)]
    fn hit(&mut self, point: ConsequenceCrashPoint) -> Result<(), ConsequenceError> {
        if self.armed_crash == Some(point) {
            self.armed_crash = None;
            Err(ConsequenceError::InjectedCrash(point))
        } else {
            Ok(())
        }
    }

    #[cfg(not(test))]
    fn hit(&mut self, _point: ConsequenceCrashPoint) -> Result<(), ConsequenceError> {
        Ok(())
    }
}

// Production still compiles the calls to `hit`; this uninhabited-looking enum
// keeps those call sites identical while test builds expose injectable points.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsequenceCrashPoint {
    AfterAuthorized,
    AfterClaimed,
    AfterInFlight,
    AfterInvocation,
    AfterExecuted,
    AfterUnknown,
    AfterLookup,
    AfterReconciled,
}

fn validate_fence(
    fence: &EffectFenceV1,
    current_height: u64,
    achieved: &VerifiedGuaranteeV1,
    authorization: &AcceptedEffectAuthorizationV1,
) -> Result<(), ConsequenceError> {
    let valid = match fence {
        EffectFenceV1::ProtocolHeight {
            configuration_hash,
            minimum_height,
            maximum_height,
        } => {
            (*minimum_height..=*maximum_height).contains(&current_height)
                && achieved.achieved().safety.configuration_hash == Some(*configuration_hash)
        }
        EffectFenceV1::AuthorityEpoch {
            authority_snapshot_hash,
            authority_epoch,
            expires_at_height,
        } => {
            current_height <= *expires_at_height
                && authorization.authority_epoch == *authority_epoch
                && authorization.authority_snapshot_root == *authority_snapshot_hash
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ConsequenceError::FenceExpired)
    }
}

fn claim_root(receipt: &ConsequenceReceiptV1) -> Result<ConsequenceHash, ConsequenceError> {
    derive_claim_root(
        &receipt.manifest,
        receipt.manifest_root,
        receipt.achieved_guarantee_root,
    )
}

fn derive_claim_root(
    manifest: &EffectManifestV1,
    manifest_root: ConsequenceHash,
    achieved_guarantee_root: ConsequenceHash,
) -> Result<ConsequenceHash, ConsequenceError> {
    let encoded = serde_jcs::to_vec(&(
        manifest_root,
        achieved_guarantee_root,
        &manifest.idempotency_key,
        manifest.request_root,
        manifest.predecessor_root,
        manifest.intent_root,
        manifest.expected_outcome_root,
    ))
    .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
    Ok(hash_parts(CLAIM_DOMAIN, &[&encoded]))
}

fn mark_unknown(
    receipt: &mut ConsequenceReceiptV1,
    reason: AmbiguityReasonV1,
    observations: u32,
) -> Result<(), ConsequenceError> {
    let claim_root = receipt
        .state
        .claim_root()
        .ok_or_else(|| ConsequenceError::Invalid("unknown state has no durable claim".into()))?;
    let ambiguity_root = canonical_hash(
        AMBIGUITY_DOMAIN,
        &(receipt.manifest_root, claim_root, &reason, observations),
    )?;
    transition(
        receipt,
        ConsequenceStateV1::Unknown {
            claim_root,
            reason,
            ambiguity_root,
            observations,
        },
    )
}

fn transition(
    receipt: &mut ConsequenceReceiptV1,
    next: ConsequenceStateV1,
) -> Result<(), ConsequenceError> {
    let from = receipt.state.phase();
    let to = next.phase();
    let legal = matches!(
        (from, to),
        (ConsequencePhaseV1::Authorized, ConsequencePhaseV1::Claimed)
            | (ConsequencePhaseV1::Claimed, ConsequencePhaseV1::InFlight)
            | (ConsequencePhaseV1::InFlight, ConsequencePhaseV1::Executed)
            | (ConsequencePhaseV1::InFlight, ConsequencePhaseV1::Unknown)
            | (ConsequencePhaseV1::Executed, ConsequencePhaseV1::Reconciled)
            | (ConsequencePhaseV1::Unknown, ConsequencePhaseV1::Unknown)
            | (ConsequencePhaseV1::Unknown, ConsequencePhaseV1::Reconciled)
    );
    if !legal
        || receipt
            .state
            .claim_root()
            .is_some_and(|current| next.claim_root() != Some(current))
    {
        return Err(ConsequenceError::WrongState(from));
    }
    let evidence_root = state_evidence_root(&next)?;
    receipt.trace.push(ConsequenceTransitionV1 {
        sequence: receipt.trace.len() as u64 + 1,
        from: Some(from),
        to,
        evidence_root,
    });
    receipt.generation = receipt.trace.len() as u64;
    receipt.state = next;
    Ok(())
}

fn validate_trace(trace: &[ConsequenceTransitionV1]) -> Result<(), ConsequenceError> {
    let mut previous = None;
    for (index, step) in trace.iter().enumerate() {
        if step.sequence != index as u64 + 1 || step.from != previous {
            return Err(ConsequenceError::CorruptReceipt);
        }
        let legal = if index == 0 {
            step.from.is_none() && step.to == ConsequencePhaseV1::Authorized
        } else {
            matches!(
                (step.from, step.to),
                (
                    Some(ConsequencePhaseV1::Authorized),
                    ConsequencePhaseV1::Claimed
                ) | (
                    Some(ConsequencePhaseV1::Claimed),
                    ConsequencePhaseV1::InFlight
                ) | (
                    Some(ConsequencePhaseV1::InFlight),
                    ConsequencePhaseV1::Executed
                ) | (
                    Some(ConsequencePhaseV1::InFlight),
                    ConsequencePhaseV1::Unknown
                ) | (
                    Some(ConsequencePhaseV1::Executed),
                    ConsequencePhaseV1::Reconciled
                ) | (
                    Some(ConsequencePhaseV1::Unknown),
                    ConsequencePhaseV1::Unknown
                ) | (
                    Some(ConsequencePhaseV1::Unknown),
                    ConsequencePhaseV1::Reconciled
                )
            )
        };
        if !legal {
            return Err(ConsequenceError::CorruptReceipt);
        }
        previous = Some(step.to);
    }
    Ok(())
}

fn validate_state(
    manifest: &EffectManifestV1,
    achieved_guarantee_root: ConsequenceHash,
    state: &ConsequenceStateV1,
) -> Result<(), ConsequenceError> {
    let manifest_root = manifest.commitment().map_err(type_error)?;
    let expected_claim = derive_claim_root(manifest, manifest_root, achieved_guarantee_root)?;
    match state {
        ConsequenceStateV1::Authorized {
            authorization_root,
            achieved_guarantee_root: state_guarantee_root,
        } => {
            if *state_guarantee_root != achieved_guarantee_root || *authorization_root == [0; 32] {
                return Err(ConsequenceError::CorruptReceipt);
            }
        }
        ConsequenceStateV1::Claimed { claim_root }
        | ConsequenceStateV1::InFlight { claim_root } => {
            if *claim_root != expected_claim {
                return Err(ConsequenceError::CorruptReceipt);
            }
        }
        ConsequenceStateV1::Unknown {
            claim_root,
            reason,
            ambiguity_root,
            observations,
        } => {
            if *claim_root != expected_claim
                || canonical_hash(
                    AMBIGUITY_DOMAIN,
                    &(manifest_root, claim_root, reason, observations),
                )? != *ambiguity_root
            {
                return Err(ConsequenceError::CorruptReceipt);
            }
        }
        ConsequenceStateV1::Executed {
            claim_root,
            resource_record,
            resource_record_root,
            ..
        } => {
            if *claim_root != expected_claim {
                return Err(ConsequenceError::CorruptReceipt);
            }
            validate_resource_record(manifest, resource_record)?;
            if resource_record.commitment().map_err(type_error)? != *resource_record_root {
                return Err(ConsequenceError::CorruptReceipt);
            }
        }
        ConsequenceStateV1::Reconciled {
            claim_root,
            resolution,
            reconciliation_root,
            ..
        } => {
            if *claim_root != expected_claim {
                return Err(ConsequenceError::CorruptReceipt);
            }
            if let ReconciliationResolutionV1::Executed {
                resource_record,
                resource_record_root,
            } = resolution
            {
                validate_resource_record(manifest, resource_record)?;
                if resource_record.commitment().map_err(type_error)? != *resource_record_root {
                    return Err(ConsequenceError::CorruptReceipt);
                }
            }
            if *reconciliation_root == [0; 32] {
                return Err(ConsequenceError::CorruptReceipt);
            }
        }
    }
    Ok(())
}

fn validate_resource_record(
    manifest: &EffectManifestV1,
    record: &ExternalResourceRecordV1,
) -> Result<(), ConsequenceError> {
    record.validate().map_err(type_error)?;
    if record_violation_kind(manifest, record).is_some() {
        return Err(ConsequenceError::UnattributedResourceConflict);
    }
    Ok(())
}

fn record_violation_kind(
    manifest: &EffectManifestV1,
    record: &ExternalResourceRecordV1,
) -> Option<ResourceViolationKindV1> {
    if record.resource_id != manifest.resource_id
        || record.idempotency_key != manifest.idempotency_key
    {
        Some(ResourceViolationKindV1::ScopeMismatch)
    } else if record.request_root != manifest.request_root {
        Some(ResourceViolationKindV1::RequestSubstitution)
    } else if record.predecessor_root != manifest.predecessor_root {
        Some(ResourceViolationKindV1::PredecessorSubstitution)
    } else if record.outcome_root != manifest.expected_outcome_root {
        Some(ResourceViolationKindV1::OutcomeSubstitution)
    } else {
        None
    }
}

fn validate_live_resource_record(
    manifest: &EffectManifestV1,
    record: &ExternalResourceRecordV1,
    verifier: &dyn ExternalResourceV1,
) -> Result<(), ConsequenceError> {
    record.validate().map_err(type_error)?;
    if record_violation_kind(manifest, record).is_some() {
        resource_conflict(manifest, record.clone(), verifier)
    } else {
        Ok(())
    }
}

fn resource_conflict<T>(
    manifest: &EffectManifestV1,
    observed: ExternalResourceRecordV1,
    verifier: &dyn ExternalResourceV1,
) -> Result<T, ConsequenceError> {
    observed.validate().map_err(type_error)?;
    let Some(kind) = record_violation_kind(manifest, &observed) else {
        return Err(ConsequenceError::ReplayConflict);
    };
    if observed.evidence.is_none() || !verifier.verify_record_evidence(&observed) {
        return Err(ConsequenceError::UnattributedResourceConflict);
    }
    let manifest_root = manifest.commitment().map_err(type_error)?;
    let verifier_profile_root = manifest.resource_profile.commitment().map_err(type_error)?;
    let proof_root = violation_root(manifest_root, &observed, &kind, verifier_profile_root)?;
    let proof = ResourceViolationEvidenceV1 {
        manifest_root,
        observed,
        kind,
        verifier_profile_root,
        proof_root,
    };
    proof.verify_with(manifest, verifier)?;
    Err(ConsequenceError::TransferableViolation(proof))
}

fn violation_root(
    manifest_root: ConsequenceHash,
    observed: &ExternalResourceRecordV1,
    kind: &ResourceViolationKindV1,
    verifier_profile_root: ConsequenceHash,
) -> Result<ConsequenceHash, ConsequenceError> {
    canonical_hash(
        VIOLATION_DOMAIN,
        &(manifest_root, observed, kind, verifier_profile_root),
    )
}

fn reconciliation_root(
    receipt: &ConsequenceReceiptV1,
    resolution: &ReconciliationResolutionV1,
) -> Result<ConsequenceHash, ConsequenceError> {
    canonical_hash(
        RECONCILIATION_DOMAIN,
        &(
            receipt.manifest_root,
            receipt.state.claim_root(),
            resolution,
            &receipt.manifest.reconciliation,
        ),
    )
}

fn state_evidence_root(state: &ConsequenceStateV1) -> Result<ConsequenceHash, ConsequenceError> {
    canonical_hash(b"ioi::aft::consequence-state::v1\0", state)
}

fn receipt_root(receipt: &ConsequenceReceiptV1) -> Result<ConsequenceHash, ConsequenceError> {
    let mut clone = receipt.clone();
    clone.receipt_root = [0; 32];
    canonical_hash(RECEIPT_DOMAIN, &clone)
}

fn persist_receipt(
    path: &Path,
    receipt: &mut ConsequenceReceiptV1,
) -> Result<(), ConsequenceError> {
    receipt.receipt_root = [0; 32];
    receipt.receipt_root = receipt_root(receipt)?;
    receipt.validate()?;
    let bytes =
        serde_jcs::to_vec(receipt).map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
    atomic_write(path, &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ConsequenceError> {
    let parent = path
        .parent()
        .ok_or_else(|| ConsequenceError::Invalid("receipt path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConsequenceError::Invalid("receipt path has no filename".into()))?;
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

fn canonical_hash<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<ConsequenceHash, ConsequenceError> {
    let bytes =
        serde_jcs::to_vec(value).map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
    Ok(hash_parts(domain, &[&bytes]))
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> ConsequenceHash {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hex_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn format_hash(hash: ConsequenceHash) -> String {
    format!(
        "sha256:{}",
        hash.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn type_error(error: impl std::fmt::Display) -> ConsequenceError {
    ConsequenceError::Invalid(error.to_string())
}

#[cfg(test)]
mod tests;
