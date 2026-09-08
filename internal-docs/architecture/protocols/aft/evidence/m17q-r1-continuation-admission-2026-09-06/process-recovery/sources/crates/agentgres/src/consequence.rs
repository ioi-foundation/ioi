//! Durable effect-native consequence execution.
//!
//! The local claim is flushed before any external invocation. Once an
//! invocation can have started, restart and retry are reconciliation-only:
//! they query the same atomic idempotency register and never blindly invoke
//! the mutation again.

use crate::recognized_effect::CommittedRecognizedEffect;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use fs2::FileExt;
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaPublicKey, MldsaSignature};
use ioi_types::app::consensus::{CertificateOnlyGuaranteeVerifierV1, VerifiedGuaranteeV1};
use ioi_types::app::{
    account_id_from_key_material, ConsequenceHash, EffectAuthorizationModeV1, EffectFenceV1,
    EffectManifestV1, ExternalResourceProfileV1, ExternalResourceRecordV1,
    QuvConsequenceStorageProfileV0 as StorageProfile, ReconciliationPolicyV1, SignatureSuite,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const RECEIPT_SCHEMA: &str = "ioi.aft-consequence-receipt.v1";
const CLAIM_DOMAIN: &[u8] = b"ioi::aft::consequence-claim::v1\0";
const RECONCILIATION_DOMAIN: &[u8] = b"ioi::aft::consequence-reconciliation::v1\0";
const RECEIPT_DOMAIN: &[u8] = b"ioi::aft::consequence-receipt::v1\0";
const AMBIGUITY_DOMAIN: &[u8] = b"ioi::aft::consequence-ambiguity::v1\0";
const VIOLATION_DOMAIN: &[u8] = b"ioi::aft::consequence-violation::v1\0";
const ONLINE_AUDIT_EVIDENCE_DOMAIN: &[u8] = b"ioi::aft::online-authorization-audit::v1\0";
const ONLINE_AUDIT_MAX_BYTES: usize = StorageProfile::AUDIT_MAX_BYTES as usize;
const QUV_PROFILE_V0: &str = "aft_quv_v0";

mod receipt_reservation;
mod resource_reservation;

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
        Self::from_committed_with_resource_contract(committed, manifest)
            .map(|(authorization, _)| authorization)
    }

    /// Reverify the runtime bundle and the exact modeled resource contract,
    /// returning both the opaque assurance input and its inseparable
    /// Agentgres authorization. The externalization coordinate describes the
    /// bound atomic contract; execution evidence is added only after T10 runs.
    pub fn from_committed_with_resource_contract(
        committed: &CommittedRecognizedEffect,
        manifest: &EffectManifestV1,
    ) -> Result<(Self, VerifiedGuaranteeV1), ConsequenceError> {
        manifest.validate().map_err(type_error)?;
        let manifest_root = manifest.commitment().map_err(type_error)?;
        let expected_manifest_text = format_hash(manifest_root);
        if committed.record.effect_manifest_root.as_deref() != Some(expected_manifest_text.as_str())
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
        let mut achieved = claim.assurance;
        achieved.externalization = manifest
            .resource_profile
            .advertised_externalization()
            .map_err(type_error)?;
        achieved.crypto.externalization_pq = manifest.resource_profile.externalization_pq;
        achieved.crypto.end_to_end_pq = achieved.crypto.consensus_pq
            && achieved.crypto.channel_pq
            && achieved.crypto.externalization_pq;
        achieved
            .constituent_hashes
            .insert(manifest.resource_profile.commitment().map_err(type_error)?);
        achieved.theorem_ids.insert("T10-resource-contract".into());
        let verified = CertificateOnlyGuaranteeVerifierV1::verify(&[achieved])
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        let achieved_guarantee_root = verified
            .achieved()
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
        let authorization = Self {
            effect_id: manifest.effect_id.clone(),
            manifest_root,
            achieved_guarantee_root,
            authority_epoch: committed.record.authority.authority_epoch,
            authority_snapshot_root,
            authorization_receipt_root,
        };
        Ok((authorization, verified))
    }
}

/// Process-local result of an online authorization operation. This is not a
/// portable finality receipt. The implementation producing it is responsible
/// for freshness and for consuming its own non-replayable session state.
#[derive(Debug, PartialEq, Eq)]
pub struct OnlineEffectAuthorizationBindingV1 {
    pub mode: EffectAuthorizationModeV1,
    pub payload_hash: ConsequenceHash,
    pub configuration_root: ConsequenceHash,
    pub conflict_domain_hash: ConsequenceHash,
    pub conflict_slot: u64,
    pub policy_root: ConsequenceHash,
    pub predecessor: ConsequenceHash,
    pub authority_mode: ioi_types::app::QuvAuthorityModeV0,
}

impl OnlineEffectAuthorizationBindingV1 {
    /// Derive a requirement before storage preparation. This is not evidence
    /// of candidate validity, live QUV, current membership or effect authority.
    pub fn from_manifest(manifest: &EffectManifestV1) -> Result<Self, ConsequenceError> {
        manifest.validate().map_err(type_error)?;
        if manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0 {
            return Err(ConsequenceError::UnexpectedOnlineAuthorization);
        }
        manifest_online_requirement(manifest, manifest.commitment().map_err(type_error)?)
    }
}

/// Durable evidence that an executor reports having observed an online
/// authorization. It is intentionally incapable of authorizing another
/// executor: the portable-finality bit is fixed false and Agentgres accepts
/// this object only together with a live process-local continuation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnlineEffectAuthorizationAuditV1 {
    pub profile: String,
    pub portable_final_receipt: bool,
    pub binding: OnlineEffectAuthorizationAuditBindingV1,
    pub verifier_nonce: ConsequenceHash,
    #[serde(with = "serde_bytes")]
    pub protocol_evidence: Vec<u8>,
    pub protocol_evidence_hash: ConsequenceHash,
}

/// Serializable copy of the context binding. Keeping this distinct from the
/// process-local binding prevents audit bytes from implementing the immediate
/// authorization trait by accident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnlineEffectAuthorizationAuditBindingV1 {
    pub mode: EffectAuthorizationModeV1,
    pub payload_hash: ConsequenceHash,
    pub configuration_root: ConsequenceHash,
    pub conflict_domain_hash: ConsequenceHash,
    pub conflict_slot: u64,
    pub policy_root: ConsequenceHash,
    pub predecessor: ConsequenceHash,
    pub authority_mode: ioi_types::app::QuvAuthorityModeV0,
}

impl From<&OnlineEffectAuthorizationBindingV1> for OnlineEffectAuthorizationAuditBindingV1 {
    fn from(binding: &OnlineEffectAuthorizationBindingV1) -> Self {
        Self {
            mode: binding.mode,
            payload_hash: binding.payload_hash,
            configuration_root: binding.configuration_root,
            conflict_domain_hash: binding.conflict_domain_hash,
            conflict_slot: binding.conflict_slot,
            policy_root: binding.policy_root,
            predecessor: binding.predecessor,
            authority_mode: binding.authority_mode,
        }
    }
}

/// Output consumed atomically by Agentgres at the online-to-effect boundary.
pub struct ConsumedOnlineEffectAuthorizationV1 {
    pub binding: OnlineEffectAuthorizationBindingV1,
    pub audit: OnlineEffectAuthorizationAuditV1,
    /// Monotonic process-local continuation deadline. This is deliberately
    /// not serializable and cannot become portable timing evidence.
    pub expires_at: Instant,
}

struct OnlineClaimContext {
    binding: OnlineEffectAuthorizationBindingV1,
    expires_at: Instant,
    current_height: u64,
}

/// A single-use, process-local authorization continuation. Implementations
/// must perform any freshness check while consuming `self`.
pub trait ImmediateOnlineEffectAuthorizationV1 {
    fn consume(self) -> Result<ConsumedOnlineEffectAuthorizationV1, ConsequenceError>;
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
    /// Non-authorizing record of the executor's own online operation. It is
    /// absent before that operation and for portable-authorized effects.
    pub online_authorization_audit: Option<OnlineEffectAuthorizationAuditV1>,
    /// Durable reservations made before reconciliation lookup. Zero is omitted
    /// to preserve the canonical encoding of receipts written before this field.
    #[serde(default, skip_serializing_if = "is_zero_reconciliation_attempts")]
    pub reconciliation_attempts: u32,
    pub state: ConsequenceStateV1,
    pub trace: Vec<ConsequenceTransitionV1>,
    pub generation: u64,
    pub receipt_root: ConsequenceHash,
}

fn is_zero_reconciliation_attempts(value: &u32) -> bool {
    *value == 0
}

impl ConsequenceReceiptV1 {
    pub fn validate(&self) -> Result<(), ConsequenceError> {
        if self.trace.len() as u64 > receipt_trace_limit(&self.manifest) {
            return Err(ConsequenceError::CorruptReceipt);
        }
        match self.manifest.reconciliation {
            ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations,
            } if self.reconciliation_attempts > maximum_observations => {
                return Err(ConsequenceError::CorruptReceipt);
            }
            ReconciliationPolicyV1::NoSafeReconciliation if self.reconciliation_attempts != 0 => {
                return Err(ConsequenceError::CorruptReceipt);
            }
            _ => {}
        }
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
        validate_online_audit_shape(self)?;
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

    /// Prepare capacity before the executor's live authorization operation.
    /// The default grants no storage guarantee for other adapters.
    fn prepare(&mut self, _manifest: &EffectManifestV1) -> Result<(), ConsequenceError> {
        Ok(())
    }

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

const DURABLE_PQ_REGISTER_ADAPTER_ID: &str = "ioi-durable-pq-register";
const DURABLE_PQ_REGISTER_ADAPTER_VERSION: &str = "v1";
const DURABLE_PQ_REGISTER_PROFILE_ID: &str = "resource-profile://ioi/durable-pq-register/v1";
const DURABLE_PQ_REGISTER_EVIDENCE_SCHEMA: &str = "ioi.aft-pq-resource-evidence.v1";
const DURABLE_PQ_REGISTER_SIGNATURE_DOMAIN: &[u8] = b"ioi::aft::durable-pq-register-evidence::v1\0";
// The fixed ML-DSA-44 envelope contains two <=512-byte tokens, three
// 32-byte hashes, one u64, fixed JSON syntax, and base64 key/signature bytes.
// Conservative JSON escaping and fixed-field headroom fit below 16 KiB.
const PQ_REGISTER_EVIDENCE_MAX_BYTES: usize = StorageProfile::PQ_EVIDENCE_MAX_BYTES as usize;
// The outer JSON stores evidence as byte integers (at most four bytes each).
const PQ_REGISTER_RECORD_MAX_BYTES: usize = StorageProfile::PQ_RECORD_MAX_BYTES as usize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurablePqRegisterStatementV1 {
    schema: String,
    record: ExternalResourceRecordV1,
    endpoint_public_key_base64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurablePqRegisterEvidenceV1 {
    statement: DurablePqRegisterStatementV1,
    signature_base64: String,
}

/// File-backed atomic put-if-absent resource with an ML-DSA-authenticated
/// endpoint statement. Separate executor processes coordinate through the
/// resource lock and observe one shared register value.
pub struct DurablePqAtomicRegisterV1 {
    root: PathBuf,
    profile: ExternalResourceProfileV1,
    endpoint: MldsaKeyPair,
    failed: bool,
}

impl DurablePqAtomicRegisterV1 {
    pub fn profile_for(
        endpoint: &MldsaKeyPair,
    ) -> Result<ExternalResourceProfileV1, ConsequenceError> {
        let public = endpoint.public_key().to_bytes();
        if public.len() != 1312 {
            return Err(ConsequenceError::Invalid(
                "resource endpoint requires ML-DSA-44".into(),
            ));
        }
        let endpoint_pq_key_hash = account_id_from_key_material(SignatureSuite::ML_DSA_44, &public)
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        let profile = ExternalResourceProfileV1 {
            adapter_id: DURABLE_PQ_REGISTER_ADAPTER_ID.into(),
            adapter_version: DURABLE_PQ_REGISTER_ADAPTER_VERSION.into(),
            resource_profile_id: DURABLE_PQ_REGISTER_PROFILE_ID.into(),
            contract: ioi_types::app::ExternalResourceContractV1::AtomicPutIfAbsent,
            externalization_pq: true,
            endpoint_pq_key_hash: Some(endpoint_pq_key_hash),
        };
        profile.validate().map_err(type_error)?;
        Ok(profile)
    }

    pub fn open(root: impl AsRef<Path>, endpoint: MldsaKeyPair) -> Result<Self, ConsequenceError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("records"))?;
        let profile = Self::profile_for(&endpoint)?;
        resource_reservation::private_open(&root.join("resource.lock"), true)?.sync_all()?;
        resource_reservation::sync_ancestry(&root.join("records"))?;
        Ok(Self {
            root,
            profile,
            endpoint,
            failed: false,
        })
    }

    fn lock(&self) -> Result<File, ConsequenceError> {
        if self.failed {
            return Err(ConsequenceError::ResourceRequiresReopen);
        }
        let lock = resource_reservation::private_open(&self.root.join("resource.lock"), false)?;
        FileExt::lock_exclusive(&lock)?;
        Ok(lock)
    }

    fn record_path(&self, resource_id: &str, idempotency_key: &str) -> PathBuf {
        let digest = hash_parts(
            b"ioi::aft::durable-pq-register-key::v1\0",
            &[resource_id.as_bytes(), idempotency_key.as_bytes()],
        );
        self.root
            .join("records")
            .join(format!("{}.json", hex::encode(digest)))
    }

    fn read_record(
        &self,
        resource_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ExternalResourceRecordV1>, ConsequenceError> {
        let path = self.record_path(resource_id, idempotency_key);
        let file = match resource_reservation::private_open(&path, false) {
            Ok(file) => file,
            Err(ConsequenceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        if file.metadata()?.len() > PQ_REGISTER_RECORD_MAX_BYTES as u64 {
            return Err(ConsequenceError::CorruptReceipt);
        }
        let mut bytes = Vec::new();
        file.take(PQ_REGISTER_RECORD_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > PQ_REGISTER_RECORD_MAX_BYTES {
            return Err(ConsequenceError::CorruptReceipt);
        }
        let record: ExternalResourceRecordV1 = serde_json::from_slice(&bytes)
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        if record
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.len() > PQ_REGISTER_EVIDENCE_MAX_BYTES)
        {
            return Err(ConsequenceError::CorruptReceipt);
        }
        let canonical = serde_jcs::to_vec(&record)
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        let initialized_padding = bytes.len() == PQ_REGISTER_RECORD_MAX_BYTES
            && bytes.starts_with(&canonical)
            && bytes[canonical.len()..].iter().all(|byte| *byte == b' ');
        if canonical != bytes && !initialized_padding {
            return Err(ConsequenceError::Invalid(
                "external resource record is not canonical JCS".into(),
            ));
        }
        record.validate().map_err(type_error)?;
        if record.resource_id != resource_id
            || record.idempotency_key != idempotency_key
            || !self.verify_record_evidence(&record)
        {
            return Err(ConsequenceError::CorruptReceipt);
        }
        Ok(Some(record))
    }

    fn sign_record(
        &self,
        mut record: ExternalResourceRecordV1,
    ) -> Result<ExternalResourceRecordV1, ConsequenceError> {
        let statement = DurablePqRegisterStatementV1 {
            schema: DURABLE_PQ_REGISTER_EVIDENCE_SCHEMA.into(),
            record: record.clone(),
            endpoint_public_key_base64: BASE64.encode(self.endpoint.public_key().to_bytes()),
        };
        let mut message = DURABLE_PQ_REGISTER_SIGNATURE_DOMAIN.to_vec();
        message.extend(
            serde_jcs::to_vec(&statement)
                .map_err(|error| ConsequenceError::Invalid(error.to_string()))?,
        );
        let evidence = DurablePqRegisterEvidenceV1 {
            statement,
            signature_base64: BASE64.encode(
                self.endpoint
                    .sign(&message)
                    .map_err(|error| ConsequenceError::Invalid(error.to_string()))?
                    .to_bytes(),
            ),
        };
        let evidence = serde_jcs::to_vec(&evidence)
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        if evidence.len() > PQ_REGISTER_EVIDENCE_MAX_BYTES {
            return Err(ConsequenceError::Invalid(
                "resource evidence exceeds its derived format bound".into(),
            ));
        }
        record.evidence_hash = Some(canonical_hash(
            b"ioi::aft::external-resource-evidence::v1\0",
            &evidence,
        )?);
        record.evidence = Some(evidence);
        record.validate().map_err(type_error)?;
        Ok(record)
    }
}

impl ExternalResourceV1 for DurablePqAtomicRegisterV1 {
    fn profile(&self) -> &ExternalResourceProfileV1 {
        &self.profile
    }

    fn prepare(&mut self, manifest: &EffectManifestV1) -> Result<(), ConsequenceError> {
        manifest.validate().map_err(type_error)?;
        if manifest.resource_profile != self.profile {
            return Err(ConsequenceError::ProfileMismatch);
        }
        let _lock = self.lock()?;
        if let Some(record) = self.read_record(&manifest.resource_id, &manifest.idempotency_key)? {
            if record.resource_id != manifest.resource_id
                || record.idempotency_key != manifest.idempotency_key
                || !self.verify_record_evidence(&record)
            {
                return Err(ConsequenceError::CorruptReceipt);
            }
            return Ok(());
        }
        resource_reservation::prepare(
            &self.record_path(&manifest.resource_id, &manifest.idempotency_key),
        )
    }

    fn invoke_atomic(
        &mut self,
        manifest: &EffectManifestV1,
    ) -> Result<AtomicMutationResultV1, ResourceInvocationErrorV1> {
        manifest
            .validate()
            .map_err(|error| ResourceInvocationErrorV1::DefinitiveRejection(error.to_string()))?;
        if manifest.resource_profile != self.profile {
            return Err(ResourceInvocationErrorV1::DefinitiveRejection(
                "resource profile mismatch".into(),
            ));
        }
        if manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0 {
            self.prepare(manifest)
                .map_err(|_| ResourceInvocationErrorV1::Ambiguous)?;
        }
        let _lock = self
            .lock()
            .map_err(|_| ResourceInvocationErrorV1::Ambiguous)?;
        if let Some(existing) = self
            .read_record(&manifest.resource_id, &manifest.idempotency_key)
            .map_err(|_| ResourceInvocationErrorV1::Ambiguous)?
        {
            if existing.request_root == manifest.request_root
                && existing.predecessor_root == manifest.predecessor_root
                && existing.outcome_root == manifest.expected_outcome_root
            {
                return Ok(AtomicMutationResultV1::Existing(existing));
            }
            return Err(ResourceInvocationErrorV1::Conflict(existing));
        }
        let record = self
            .sign_record(ExternalResourceRecordV1 {
                resource_id: manifest.resource_id.clone(),
                idempotency_key: manifest.idempotency_key.clone(),
                request_root: manifest.request_root,
                predecessor_root: manifest.predecessor_root,
                outcome_root: manifest.expected_outcome_root,
                mutation_sequence: 1,
                evidence: None,
                evidence_hash: None,
            })
            .map_err(|_| ResourceInvocationErrorV1::Ambiguous)?;
        let bytes = serde_jcs::to_vec(&record).map_err(|_| ResourceInvocationErrorV1::Ambiguous)?;
        if resource_reservation::commit(
            &self.record_path(&manifest.resource_id, &manifest.idempotency_key),
            &bytes,
        )
        .is_err()
        {
            self.failed = true;
            return Err(ResourceInvocationErrorV1::Ambiguous);
        }
        Ok(AtomicMutationResultV1::Inserted(record))
    }

    fn lookup(
        &mut self,
        resource_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ExternalResourceRecordV1>, ResourceLookupErrorV1> {
        let _lock = self.lock().map_err(|_| ResourceLookupErrorV1::Ambiguous)?;
        self.read_record(resource_id, idempotency_key)
            .map_err(|_| ResourceLookupErrorV1::Ambiguous)
    }

    fn verify_record_evidence(&self, record: &ExternalResourceRecordV1) -> bool {
        let (Some(evidence), Some(expected_hash)) = (&record.evidence, record.evidence_hash) else {
            return false;
        };
        if evidence.len() > PQ_REGISTER_EVIDENCE_MAX_BYTES {
            return false;
        }
        if canonical_hash(b"ioi::aft::external-resource-evidence::v1\0", evidence).ok()
            != Some(expected_hash)
        {
            return false;
        }
        let Ok(envelope) = serde_json::from_slice::<DurablePqRegisterEvidenceV1>(evidence) else {
            return false;
        };
        if serde_jcs::to_vec(&envelope).ok().as_deref() != Some(evidence.as_slice()) {
            return false;
        }
        let mut unsigned = record.clone();
        unsigned.evidence = None;
        unsigned.evidence_hash = None;
        if envelope.statement.schema != DURABLE_PQ_REGISTER_EVIDENCE_SCHEMA
            || envelope.statement.record != unsigned
        {
            return false;
        }
        let Ok(public_bytes) = BASE64.decode(&envelope.statement.endpoint_public_key_base64) else {
            return false;
        };
        if public_bytes.len() != 1312 {
            return false;
        }
        if account_id_from_key_material(SignatureSuite::ML_DSA_44, &public_bytes).ok()
            != self.profile.endpoint_pq_key_hash
        {
            return false;
        }
        let (Ok(public), Ok(signature)) = (
            MldsaPublicKey::from_bytes(&public_bytes),
            BASE64
                .decode(&envelope.signature_base64)
                .ok()
                .and_then(|bytes| MldsaSignature::from_bytes(&bytes).ok())
                .ok_or(()),
        ) else {
            return false;
        };
        let mut message = DURABLE_PQ_REGISTER_SIGNATURE_DOMAIN.to_vec();
        let Ok(statement) = serde_jcs::to_vec(&envelope.statement) else {
            return false;
        };
        message.extend(statement);
        public.verify(&message, &signature).is_ok()
    }
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
    OnlineAuthorizationRequired,
    UnexpectedOnlineAuthorization,
    InvalidOnlineAuthorization,
    WrongState(ConsequencePhaseV1),
    Ambiguous,
    ReconciliationExhausted,
    DefinitiveRejection(String),
    UnattributedResourceConflict,
    TransferableViolation(ResourceViolationEvidenceV1),
    InvalidViolationEvidence,
    CorruptReceipt,
    StoreBusy,
    ResourceCapacityNotPrepared,
    ResourceRequiresReopen,
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
    AfterLookupReserved,
    AfterLookup,
    AfterReconciled,
}

/// Single-owner durable consequence state. The held file lock prevents two
/// local clones from issuing the external call concurrently.
pub struct ConsequenceStore {
    root: PathBuf,
    _lock: File,
    failed: bool,
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
        lock.sync_all()?;
        resource_reservation::sync_ancestry(&root.join("effects"))?;
        Ok(Self {
            root,
            _lock: lock,
            failed: false,
            #[cfg(test)]
            armed_crash: None,
        })
    }

    /// Whether this store already holds durable state for an effect. This is
    /// existence only; callers must use `load` before relying on its contents.
    pub fn contains(&self, effect_id: &str) -> bool {
        self.receipt_path(effect_id).exists()
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
        self.authorize_inner(manifest, achieved, authorization, current_height, false)
    }

    /// Prepare an online effect for either fresh execution or result retrieval.
    /// Expiry may be ignored only for an existing non-executable receipt; all
    /// committed admission and fence identity checks remain mandatory.
    pub fn prepare_online_effect(
        &mut self,
        manifest: EffectManifestV1,
        achieved: &VerifiedGuaranteeV1,
        authorization: &AcceptedEffectAuthorizationV1,
        current_height: u64,
    ) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        if manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0 {
            return Err(ConsequenceError::UnexpectedOnlineAuthorization);
        }
        self.authorize_inner(manifest, achieved, authorization, current_height, true)
    }

    /// Check exact candidate binding and, for executable state, the caller's
    /// rooted candidate/head preflight before any per-effect storage mutation.
    /// The callback grants no live authority; the executor must still run QUV.
    /// Existing non-executable results retain lookup-only readmission semantics.
    pub async fn prepare_online_effect_checked<F>(
        &mut self,
        manifest: EffectManifestV1,
        achieved: &VerifiedGuaranteeV1,
        authorization: &AcceptedEffectAuthorizationV1,
        current_height: u64,
        candidate_binding: OnlineEffectAuthorizationBindingV1,
        preflight: F,
    ) -> Result<bool, ConsequenceError>
    where
        F: std::future::Future<Output = Result<(), ConsequenceError>>,
    {
        if OnlineEffectAuthorizationBindingV1::from_manifest(&manifest)? != candidate_binding {
            return Err(ConsequenceError::InvalidOnlineAuthorization);
        }
        let effect_id = manifest.effect_id.clone();
        let needs_live = if self.contains(&effect_id) {
            matches!(
                self.load(&effect_id)?.state,
                ConsequenceStateV1::Authorized { .. } | ConsequenceStateV1::Claimed { .. }
            )
        } else {
            true
        };
        if needs_live {
            preflight.await?;
        }
        self.prepare_online_effect(manifest, achieved, authorization, current_height)?;
        self.prepare_online_storage(&effect_id)?;
        Ok(needs_live)
    }

    /// Reserve receipt data after admission rederivation and before beginning
    /// the executor's live operation. Revalidation after QUV must not call this.
    pub fn prepare_online_storage(&mut self, effect_id: &str) -> Result<(), ConsequenceError> {
        let receipt = self.load(effect_id)?;
        if let Some(bound) = online_receipt_byte_bound(&receipt.manifest)? {
            if let Err(error) = receipt_reservation::prepare(&self.receipt_path(effect_id), bound) {
                self.failed = true;
                return Err(error);
            }
        }
        Ok(())
    }

    fn persist(
        &mut self,
        path: &Path,
        receipt: &mut ConsequenceReceiptV1,
    ) -> Result<(), ConsequenceError> {
        if self.failed {
            return Err(ConsequenceError::ResourceRequiresReopen);
        }
        if let Err(error) = persist_receipt(path, receipt) {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }

    fn authorize_inner(
        &mut self,
        manifest: EffectManifestV1,
        achieved: &VerifiedGuaranteeV1,
        authorization: &AcceptedEffectAuthorizationV1,
        current_height: u64,
        allow_existing_result: bool,
    ) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        manifest.validate().map_err(type_error)?;
        let path = self.receipt_path(&manifest.effect_id);
        let existing = if path.exists() {
            Some(self.load(&manifest.effect_id)?)
        } else {
            None
        };
        let allow_expired_result = allow_existing_result
            && existing.as_ref().is_some_and(|receipt| {
                receipt.manifest.authorization_mode
                    == EffectAuthorizationModeV1::OnlineQueryUnanimityV0
                    && !matches!(
                        receipt.state,
                        ConsequenceStateV1::Authorized { .. } | ConsequenceStateV1::Claimed { .. }
                    )
            });
        validate_fence(
            &manifest,
            current_height,
            achieved,
            authorization,
            allow_expired_result,
        )?;
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
        if let Some(existing) = existing {
            // The initial authorization remains committed by the first trace
            // entry after Claim replaces the state variant. A retry must match
            // today's independently derived admission to that exact entry.
            let expected_authorization_evidence =
                state_evidence_root(&ConsequenceStateV1::Authorized {
                    authorization_root: authorization.authorization_receipt_root,
                    achieved_guarantee_root,
                })?;
            if existing.manifest_root == manifest_root
                && existing.achieved_guarantee_root == achieved_guarantee_root
                && (manifest.authorization_mode
                    != EffectAuthorizationModeV1::OnlineQueryUnanimityV0
                    || existing
                        .trace
                        .first()
                        .is_some_and(|step| step.evidence_root == expected_authorization_evidence))
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
            online_authorization_audit: None,
            reconciliation_attempts: 0,
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
        self.persist(&path, &mut receipt)?;
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
        self.execute_after_online_authorization(effect_id, resource, None)
    }

    /// Execute an `online_query_unanimity_v0` effect only as the immediate
    /// continuation of the executor's own online authorization operation.
    pub fn execute_with_online_authorization<A: ImmediateOnlineEffectAuthorizationV1>(
        &mut self,
        effect_id: &str,
        resource: &mut dyn ExternalResourceV1,
        authorization: A,
        current_height: u64,
    ) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        let receipt = self.load(effect_id)?;
        if receipt.manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0
        {
            return Err(ConsequenceError::UnexpectedOnlineAuthorization);
        }
        if !matches!(
            receipt.state,
            ConsequenceStateV1::Authorized { .. } | ConsequenceStateV1::Claimed { .. }
        ) {
            return Err(ConsequenceError::WrongState(receipt.state.phase()));
        }
        let consumed = authorization.consume()?;
        validate_online_authorization(&receipt, &consumed.binding)?;
        validate_online_audit(&consumed.audit, &consumed.binding)?;
        validate_online_execution_fence(&receipt.manifest, current_height)?;
        let mut receipt = receipt;
        receipt.online_authorization_audit = Some(consumed.audit);
        self.persist(&self.receipt_path(effect_id), &mut receipt)?;
        self.execute_after_online_authorization(
            effect_id,
            resource,
            Some(OnlineClaimContext {
                binding: consumed.binding,
                expires_at: consumed.expires_at,
                current_height,
            }),
        )
    }

    /// Return the exact online binding an executor must satisfy before it
    /// starts a network operation. This is a requirement, never evidence that
    /// the operation happened, and grants no authority by itself.
    pub fn online_authorization_requirement(
        &self,
        effect_id: &str,
    ) -> Result<OnlineEffectAuthorizationBindingV1, ConsequenceError> {
        let receipt = self.load(effect_id)?;
        if receipt.manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0
        {
            return Err(ConsequenceError::UnexpectedOnlineAuthorization);
        }
        if !matches!(
            receipt.state,
            ConsequenceStateV1::Authorized { .. } | ConsequenceStateV1::Claimed { .. }
        ) {
            return Err(ConsequenceError::WrongState(receipt.state.phase()));
        }
        online_authorization_requirement(&receipt)
    }

    /// Inspect the durable online binding in any phase. This grants no
    /// execution authority; callers must independently validate admission.
    pub fn online_effect_binding(
        &self,
        effect_id: &str,
    ) -> Result<OnlineEffectAuthorizationBindingV1, ConsequenceError> {
        let receipt = self.load(effect_id)?;
        if receipt.manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0
        {
            return Err(ConsequenceError::UnexpectedOnlineAuthorization);
        }
        online_authorization_requirement(&receipt)
    }

    /// Return a recorded outcome or perform lookup-only reconciliation. Call
    /// after revalidating committed admission and the requested candidate.
    /// None means a fresh live operation is still required; this method never
    /// invokes the resource mutation operation or consumes a continuation.
    pub fn online_retry_result(
        &mut self,
        effect_id: &str,
        resource: &mut dyn ExternalResourceV1,
    ) -> Result<Option<ConsequenceReceiptV1>, ConsequenceError> {
        let receipt = self.load(effect_id)?;
        if receipt.manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0
        {
            return Err(ConsequenceError::UnexpectedOnlineAuthorization);
        }
        if resource.profile() != &receipt.manifest.resource_profile {
            return Err(ConsequenceError::ProfileMismatch);
        }
        match receipt.state {
            ConsequenceStateV1::Authorized { .. } | ConsequenceStateV1::Claimed { .. } => Ok(None),
            ConsequenceStateV1::Executed { .. } | ConsequenceStateV1::Reconciled { .. } => {
                let expected = match &receipt.state {
                    ConsequenceStateV1::Executed {
                        resource_record, ..
                    }
                    | ConsequenceStateV1::Reconciled {
                        resolution:
                            ReconciliationResolutionV1::Executed {
                                resource_record, ..
                            },
                        ..
                    } => Some(resource_record),
                    _ => None,
                };
                let observed = resource
                    .lookup(
                        &receipt.manifest.resource_id,
                        &receipt.manifest.idempotency_key,
                    )
                    .map_err(|error| match error {
                        ResourceLookupErrorV1::Ambiguous => ConsequenceError::Ambiguous,
                        ResourceLookupErrorV1::Conflict(_) => ConsequenceError::ReplayConflict,
                    })?;
                if observed.as_ref() != expected {
                    // A stored receipt alone is insufficient to report an
                    // external outcome. Do not rewrite it or attribute blame.
                    return Err(ConsequenceError::ReplayConflict);
                }
                Ok(Some(receipt))
            }
            ConsequenceStateV1::InFlight { .. } | ConsequenceStateV1::Unknown { .. } => {
                self.reconcile(effect_id, resource).map(Some)
            }
        }
    }

    fn execute_after_online_authorization(
        &mut self,
        effect_id: &str,
        resource: &mut dyn ExternalResourceV1,
        online: Option<OnlineClaimContext>,
    ) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        let mut receipt = self.load(effect_id)?;
        match (receipt.manifest.authorization_mode, online.is_some()) {
            (EffectAuthorizationModeV1::OnlineQueryUnanimityV0, false) => {
                return Err(ConsequenceError::OnlineAuthorizationRequired)
            }
            (EffectAuthorizationModeV1::Portable, true) => {
                return Err(ConsequenceError::UnexpectedOnlineAuthorization)
            }
            _ => {}
        }
        if resource.profile() != &receipt.manifest.resource_profile {
            return Err(ConsequenceError::ProfileMismatch);
        }
        if !resource.profile().contract.supports_at_most_once() {
            return Err(ConsequenceError::UnsafeResourceContract);
        }
        if let Some(context) = &online {
            // Check the receipt actually used for the claim/call, including
            // retries, against the consumed process-local binding.
            validate_online_authorization(&receipt, &context.binding)?;
            validate_online_execution_fence(&receipt.manifest, context.current_height)?;
        }
        if matches!(receipt.state, ConsequenceStateV1::Authorized { .. }) {
            let claim_root = claim_root(&receipt)?;
            if online
                .as_ref()
                .is_some_and(|context| Instant::now() > context.expires_at)
            {
                return Err(ConsequenceError::InvalidOnlineAuthorization);
            }
            transition(&mut receipt, ConsequenceStateV1::Claimed { claim_root })?;
            self.persist(&self.receipt_path(effect_id), &mut receipt)?;
            self.hit(ConsequenceCrashPoint::AfterClaimed)?;
        }
        let claim_root = match receipt.state {
            ConsequenceStateV1::Claimed { claim_root } => claim_root,
            _ => return Err(ConsequenceError::WrongState(receipt.state.phase())),
        };
        if online
            .as_ref()
            .is_some_and(|context| Instant::now() > context.expires_at)
        {
            return Err(ConsequenceError::InvalidOnlineAuthorization);
        }
        transition(&mut receipt, ConsequenceStateV1::InFlight { claim_root })?;
        self.persist(&self.receipt_path(effect_id), &mut receipt)?;
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
                self.persist(&self.receipt_path(effect_id), &mut receipt)?;
                self.hit(ConsequenceCrashPoint::AfterExecuted)?;
                Ok(receipt)
            }
            Err(ResourceInvocationErrorV1::Ambiguous) => {
                mark_unknown(
                    &mut receipt,
                    AmbiguityReasonV1::InvocationResultAmbiguous,
                    0,
                )?;
                self.persist(&self.receipt_path(effect_id), &mut receipt)?;
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
                self.persist(&self.receipt_path(effect_id), &mut receipt)?;
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
            self.persist(&self.receipt_path(effect_id), &mut receipt)?;
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
        let attempts = receipt.reconciliation_attempts.max(observations);
        if attempts >= maximum_observations {
            return Err(ConsequenceError::ReconciliationExhausted);
        }
        receipt.reconciliation_attempts = attempts + 1;
        self.persist(&self.receipt_path(effect_id), &mut receipt)?;
        self.hit(ConsequenceCrashPoint::AfterLookupReserved)?;
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
                if matches!(receipt.state, ConsequenceStateV1::Unknown { .. }) {
                    mark_unknown(
                        &mut receipt,
                        AmbiguityReasonV1::ReconciliationLookupAmbiguous,
                        observations + 1,
                    )?;
                    self.persist(&self.receipt_path(effect_id), &mut receipt)?;
                }
                return if receipt.reconciliation_attempts >= maximum_observations {
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
        self.persist(&self.receipt_path(effect_id), &mut receipt)?;
        self.hit(ConsequenceCrashPoint::AfterReconciled)?;
        Ok(receipt)
    }

    pub fn load(&self, effect_id: &str) -> Result<ConsequenceReceiptV1, ConsequenceError> {
        if self.failed {
            return Err(ConsequenceError::ResourceRequiresReopen);
        }
        let (bytes, stored_capacity) = receipt_reservation::read(&self.receipt_path(effect_id))?;
        let receipt: ConsequenceReceiptV1 = serde_json::from_slice(&bytes)
            .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
        if receipt.manifest.effect_id != effect_id {
            return Err(ConsequenceError::CorruptReceipt);
        }
        receipt.validate()?;
        receipt_reservation::validate_capacity(
            stored_capacity,
            online_receipt_byte_bound(&receipt.manifest)?,
        )?;
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
    AfterLookupReserved,
    AfterLookup,
    AfterReconciled,
}

fn validate_fence(
    manifest: &EffectManifestV1,
    current_height: u64,
    achieved: &VerifiedGuaranteeV1,
    authorization: &AcceptedEffectAuthorizationV1,
    allow_expired_result: bool,
) -> Result<(), ConsequenceError> {
    let valid = match &manifest.fence {
        EffectFenceV1::ProtocolHeight {
            configuration_hash,
            minimum_height,
            maximum_height,
        } => {
            current_height >= *minimum_height
                && (current_height <= *maximum_height || allow_expired_result)
                && (manifest.authorization_mode
                    == EffectAuthorizationModeV1::OnlineQueryUnanimityV0
                    || achieved.achieved().safety.configuration_hash == Some(*configuration_hash))
        }
        EffectFenceV1::AuthorityEpoch {
            authority_snapshot_hash,
            authority_epoch,
            expires_at_height,
        } => {
            (current_height <= *expires_at_height || allow_expired_result)
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

fn validate_online_authorization(
    receipt: &ConsequenceReceiptV1,
    binding: &OnlineEffectAuthorizationBindingV1,
) -> Result<(), ConsequenceError> {
    if *binding != online_authorization_requirement(receipt)? {
        return Err(ConsequenceError::InvalidOnlineAuthorization);
    }
    Ok(())
}

fn validate_online_execution_fence(
    manifest: &EffectManifestV1,
    current_height: u64,
) -> Result<(), ConsequenceError> {
    let live = match manifest.fence {
        EffectFenceV1::ProtocolHeight {
            minimum_height,
            maximum_height,
            ..
        } => (minimum_height..=maximum_height).contains(&current_height),
        EffectFenceV1::AuthorityEpoch {
            expires_at_height, ..
        } => current_height <= expires_at_height,
    };
    if live {
        Ok(())
    } else {
        Err(ConsequenceError::FenceExpired)
    }
}

/// Domain-separated commitment used by protocol implementations when they
/// place their raw, non-authorizing online evidence into an Agentgres audit
/// record.
pub fn online_authorization_audit_evidence_hash(
    evidence: &[u8],
) -> Result<ConsequenceHash, ConsequenceError> {
    if evidence.is_empty() || evidence.len() > ONLINE_AUDIT_MAX_BYTES {
        return Err(ConsequenceError::InvalidOnlineAuthorization);
    }
    canonical_hash(ONLINE_AUDIT_EVIDENCE_DOMAIN, &evidence)
}

fn validate_online_audit(
    audit: &OnlineEffectAuthorizationAuditV1,
    binding: &OnlineEffectAuthorizationBindingV1,
) -> Result<(), ConsequenceError> {
    if audit.profile != QUV_PROFILE_V0
        || audit.portable_final_receipt
        || audit.verifier_nonce == [0; 32]
        || audit.binding != OnlineEffectAuthorizationAuditBindingV1::from(binding)
        || online_authorization_audit_evidence_hash(&audit.protocol_evidence)?
            != audit.protocol_evidence_hash
    {
        return Err(ConsequenceError::InvalidOnlineAuthorization);
    }
    Ok(())
}

fn validate_online_audit_shape(receipt: &ConsequenceReceiptV1) -> Result<(), ConsequenceError> {
    match (
        receipt.manifest.authorization_mode,
        receipt.online_authorization_audit.as_ref(),
        receipt.state.phase(),
    ) {
        (EffectAuthorizationModeV1::Portable, None, _) => Ok(()),
        (
            EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
            None,
            ConsequencePhaseV1::Authorized,
        ) => Ok(()),
        (EffectAuthorizationModeV1::OnlineQueryUnanimityV0, Some(audit), _) => {
            let binding = online_authorization_requirement(receipt)?;
            validate_online_audit(audit, &binding)
        }
        _ => Err(ConsequenceError::CorruptReceipt),
    }
}

fn online_authorization_requirement(
    receipt: &ConsequenceReceiptV1,
) -> Result<OnlineEffectAuthorizationBindingV1, ConsequenceError> {
    manifest_online_requirement(&receipt.manifest, receipt.manifest_root)
}

fn manifest_online_requirement(
    manifest: &EffectManifestV1,
    manifest_root: ConsequenceHash,
) -> Result<OnlineEffectAuthorizationBindingV1, ConsequenceError> {
    let expected_configuration = match manifest.fence {
        EffectFenceV1::ProtocolHeight {
            configuration_hash, ..
        } => configuration_hash,
        EffectFenceV1::AuthorityEpoch { .. } => manifest
            .required_guarantees
            .configuration_hash
            .ok_or(ConsequenceError::InvalidOnlineAuthorization)?,
    };
    let domain = manifest.conflict_domain_commitment().map_err(type_error)?;
    Ok(OnlineEffectAuthorizationBindingV1 {
        mode: EffectAuthorizationModeV1::OnlineQueryUnanimityV0,
        payload_hash: manifest_root,
        configuration_root: expected_configuration,
        conflict_domain_hash: domain,
        conflict_slot: manifest.conflict_slot,
        policy_root: manifest
            .online_authorization_policy_root
            .ok_or(ConsequenceError::InvalidOnlineAuthorization)?,
        predecessor: manifest
            .online_authorization_predecessor
            .ok_or(ConsequenceError::InvalidOnlineAuthorization)?,
        authority_mode: manifest
            .online_authorization_authority_mode
            .ok_or(ConsequenceError::InvalidOnlineAuthorization)?,
    })
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

/// Authorized, Claimed, InFlight and one execution/ambiguity entry, followed
/// by at most one trace entry per rooted reconciliation observation. No new
/// quota is introduced: this is a consequence of the existing state machine.
fn receipt_trace_limit(manifest: &EffectManifestV1) -> u64 {
    StorageProfile::TRACE_BASE_ENTRIES
        + match manifest.reconciliation {
            ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations,
            } => u64::from(maximum_observations),
            ReconciliationPolicyV1::NoSafeReconciliation => 0,
        }
}

fn is_durable_pq_profile(profile: &ExternalResourceProfileV1) -> bool {
    profile.adapter_id == DURABLE_PQ_REGISTER_ADAPTER_ID
        && profile.adapter_version == DURABLE_PQ_REGISTER_ADAPTER_VERSION
        && profile.resource_profile_id == DURABLE_PQ_REGISTER_PROFILE_ID
        && profile.contract == ioi_types::app::ExternalResourceContractV1::AtomicPutIfAbsent
        && profile.externalization_pq
        && profile.endpoint_pq_key_hash.is_some()
}

/// Encoded lifetime bound for the named production online resource profile.
/// This is input to physical reservation, not a claim that it reserves storage.
/// The exact manifest and observation allowance are retained without reduction.
fn online_receipt_byte_bound(manifest: &EffectManifestV1) -> Result<Option<u64>, ConsequenceError> {
    if manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0
        || !is_durable_pq_profile(&manifest.resource_profile)
    {
        return Ok(None);
    }
    manifest.validate().map_err(type_error)?;
    let manifest_bytes = serde_jcs::to_vec(manifest)
        .map_err(|error| ConsequenceError::Invalid(error.to_string()))?
        .len() as u64;
    // At most four JSON bytes per audit byte, 512 per fixed trace entry,
    // one bounded resource record, and 32 KiB of fixed state/audit/root syntax.
    let observations = match manifest.reconciliation {
        ReconciliationPolicyV1::LookupByIdempotencyKey {
            maximum_observations,
        } => maximum_observations,
        ReconciliationPolicyV1::NoSafeReconciliation => 0,
    };
    let bound = StorageProfile::receipt_encoded_bound(manifest_bytes, observations)
        .ok_or(ConsequenceError::CorruptReceipt)?;
    Ok(Some(bound))
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
    if receipt.trace.len() as u64 >= receipt_trace_limit(&receipt.manifest) {
        return Err(ConsequenceError::CorruptReceipt);
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
    if is_durable_pq_profile(&manifest.resource_profile)
        && record
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.len() > PQ_REGISTER_EVIDENCE_MAX_BYTES)
    {
        return Err(ConsequenceError::CorruptReceipt);
    }
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
    // Match the existing wire object exactly, without cloning its audit bytes
    // or retained trace merely to substitute the self-hash field.
    #[derive(Serialize)]
    struct RootView<'a> {
        schema_version: &'a str,
        manifest: &'a EffectManifestV1,
        manifest_root: ConsequenceHash,
        achieved_guarantee_root: ConsequenceHash,
        online_authorization_audit: &'a Option<OnlineEffectAuthorizationAuditV1>,
        #[serde(skip_serializing_if = "is_zero_reconciliation_attempts")]
        reconciliation_attempts: u32,
        state: &'a ConsequenceStateV1,
        trace: &'a [ConsequenceTransitionV1],
        generation: u64,
        receipt_root: ConsequenceHash,
    }
    canonical_hash(
        RECEIPT_DOMAIN,
        &RootView {
            schema_version: &receipt.schema_version,
            manifest: &receipt.manifest,
            manifest_root: receipt.manifest_root,
            achieved_guarantee_root: receipt.achieved_guarantee_root,
            online_authorization_audit: &receipt.online_authorization_audit,
            reconciliation_attempts: receipt.reconciliation_attempts,
            state: &receipt.state,
            trace: &receipt.trace,
            generation: receipt.generation,
            receipt_root: [0; 32],
        },
    )
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
    if let Some(bound) = online_receipt_byte_bound(&receipt.manifest)? {
        if bytes.len() as u64 > bound {
            return Err(ConsequenceError::CorruptReceipt);
        }
        if path.exists() {
            return receipt_reservation::commit(path, &bytes, bound);
        }
        if receipt.generation != 1 || receipt.online_authorization_audit.is_some() {
            return Err(ConsequenceError::ResourceCapacityNotPrepared);
        }
    }
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
    struct DigestWriter<'a>(&'a mut Sha256);
    impl Write for DigestWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(domain);
    // JCS still buffers object entries for key sorting. This removes the
    // additional complete output Vec, not every serializer allocation.
    serde_jcs::to_writer(DigestWriter(&mut hasher), value)
        .map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
    Ok(hasher.finalize().into())
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
