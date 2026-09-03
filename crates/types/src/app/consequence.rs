//! Effect-native consequence manifests and portable externalization evidence.
//!
//! These types deliberately stop at a declared atomic resource contract. An
//! adapter label or successful network response is not evidence of
//! at-most-once mutation.

use crate::app::consensus::{
    ExternalizationCoordinateV1, ExternalizationModeV1, GuaranteeRequirementsV1,
};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Domain separator for effect-manifest commitments.
pub const EFFECT_MANIFEST_V1_DOMAIN: &[u8] = b"ioi::aft::effect-manifest::v1\0";
/// Domain separator for adapter/resource-profile commitments.
pub const RESOURCE_PROFILE_V1_DOMAIN: &[u8] = b"ioi::aft::external-resource-profile::v1\0";
/// Domain separator for external-resource record commitments.
pub const RESOURCE_RECORD_V1_DOMAIN: &[u8] = b"ioi::aft::external-resource-record::v1\0";
/// Domain separator for textual conflict-domain identities.
pub const CONFLICT_DOMAIN_ID_V1_DOMAIN: &[u8] = b"ioi::aft::conflict-domain-id::v1\0";

/// Canonical 32-byte SHA-256 commitment used by consequence contracts.
pub type ConsequenceHash = [u8; 32];

/// Wire version for an effect manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectManifestVersionV1 {
    /// Initial consequence-consensus manifest.
    V1,
}

/// One key in the complete declared read or write footprint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResourceKeyV1 {
    /// Canonical resource-relative key.
    pub key: String,
    /// Exact version/root observed by authorization, or `None` for a declared
    /// absent key.
    pub predecessor: Option<ConsequenceHash>,
}

/// The atomic operation the external endpoint promises for one idempotency
/// key. Unsupported adapters remain representable so they can advertise a
/// truthful false coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalResourceContractV1 {
    /// Endpoint exposes no atomic deduplication primitive.
    UnsupportedBestEffort,
    /// Endpoint atomically inserts the first value for an idempotency key.
    AtomicPutIfAbsent,
    /// Endpoint atomically compares predecessor and installs the first value.
    AtomicCompareAndSet,
}

impl ExternalResourceContractV1 {
    /// Whether the contract can support the modeled at-most-once theorem.
    pub fn supports_at_most_once(self) -> bool {
        matches!(self, Self::AtomicPutIfAbsent | Self::AtomicCompareAndSet)
    }
}

/// Adapter plus resource semantics. Its canonical commitment is the profile
/// identity consumed by the guarantee vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalResourceProfileV1 {
    /// Stable adapter implementation identity.
    pub adapter_id: String,
    /// Exact adapter contract version.
    pub adapter_version: String,
    /// Stable external-resource semantic profile identity.
    pub resource_profile_id: String,
    /// Atomic mutation primitive supplied by the endpoint.
    pub contract: ExternalResourceContractV1,
    /// True only when the complete adapter/endpoint verification chain is PQ.
    pub externalization_pq: bool,
    /// Rooted ML-DSA endpoint identity required when `externalization_pq` is
    /// true. The portable verifier checks the exact key and response evidence;
    /// a boolean profile label cannot authenticate an endpoint by itself.
    pub endpoint_pq_key_hash: Option<ConsequenceHash>,
}

impl ExternalResourceProfileV1 {
    /// Validate canonical profile shape.
    pub fn validate(&self) -> Result<(), ConsequenceTypeError> {
        validate_token("adapter_id", &self.adapter_id)?;
        validate_token("adapter_version", &self.adapter_version)?;
        validate_token("resource_profile_id", &self.resource_profile_id)?;
        if self.externalization_pq
            != self
                .endpoint_pq_key_hash
                .is_some_and(|commitment| commitment != [0; 32])
        {
            return Err(ConsequenceTypeError::InvalidExternalizationPqBinding);
        }
        Ok(())
    }

    /// Compute the canonical profile commitment.
    pub fn commitment(&self) -> Result<ConsequenceHash, ConsequenceTypeError> {
        self.validate()?;
        commitment(RESOURCE_PROFILE_V1_DOMAIN, self)
    }

    /// The exact externalization coordinate this profile may advertise. The
    /// runtime still has to bind the same profile and produce execution and
    /// reconciliation evidence.
    pub fn advertised_externalization(
        &self,
    ) -> Result<ExternalizationCoordinateV1, ConsequenceTypeError> {
        let at_most_once = self.contract.supports_at_most_once();
        Ok(ExternalizationCoordinateV1 {
            mode: if at_most_once {
                ExternalizationModeV1::IdempotencyRegister
            } else {
                ExternalizationModeV1::BestEffort
            },
            at_most_once,
            adapter_profile_hash: Some(self.commitment()?),
        })
    }
}

/// Height or authority-epoch fence bounding an effect authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectFenceV1 {
    /// Authorization is valid only within one inclusive protocol-height range.
    ProtocolHeight {
        /// Exact consensus configuration commitment.
        configuration_hash: ConsequenceHash,
        /// First permitted protocol height.
        minimum_height: u64,
        /// Last permitted protocol height.
        maximum_height: u64,
    },
    /// Authorization is bound to an external authority epoch and expiry.
    AuthorityEpoch {
        /// Commitment to the exact authority snapshot.
        authority_snapshot_hash: ConsequenceHash,
        /// Monotonic authority epoch.
        authority_epoch: u64,
        /// Last protocol height at which execution may be claimed.
        expires_at_height: u64,
    },
}

/// How an ambiguous external invocation may be resolved without replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReconciliationPolicyV1 {
    /// Query the same atomic register. A bound is carried for operational
    /// escalation, never as permission to invoke the mutation again.
    LookupByIdempotencyKey {
        /// Maximum inconclusive lookups before operator escalation.
        maximum_observations: u32,
    },
    /// The adapter cannot safely resolve an ambiguous invocation.
    NoSafeReconciliation,
}

/// Authorization object for one externally visible consequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectManifestV1 {
    /// Wire schema discriminator.
    pub schema_version: EffectManifestVersionV1,
    /// Stable authorization/effect identity.
    pub effect_id: String,
    /// Exact external resource identity.
    pub resource_id: String,
    /// Independent conflict-domain identity.
    pub conflict_domain_id: String,
    /// Complete declared resource read footprint.
    pub read_set: Vec<EffectResourceKeyV1>,
    /// Complete declared resource write footprint.
    pub write_set: Vec<EffectResourceKeyV1>,
    /// Stable key used for mutation and every reconciliation lookup.
    pub idempotency_key: String,
    /// Commitment to exact canonical request bytes.
    pub request_root: ConsequenceHash,
    /// Commitment to the authorized predecessor state.
    pub predecessor_root: ConsequenceHash,
    /// Commitment to the governing intent.
    pub intent_root: ConsequenceHash,
    /// Commitment to the only successful outcome authorized.
    pub expected_outcome_root: ConsequenceHash,
    /// Exact adapter and endpoint semantic profile.
    pub resource_profile: ExternalResourceProfileV1,
    /// Minimum assurance required before execution.
    pub required_guarantees: GuaranteeRequirementsV1,
    /// Height or authority fence bounding the authorization.
    pub fence: EffectFenceV1,
    /// Ambiguity-resolution policy.
    pub reconciliation: ReconciliationPolicyV1,
    /// Whether replay could cause an irreversible duplicate consequence.
    pub irreversible: bool,
}

impl EffectManifestV1 {
    /// Validate canonical manifest shape and safe reconciliation requirements.
    pub fn validate(&self) -> Result<(), ConsequenceTypeError> {
        validate_token("effect_id", &self.effect_id)?;
        validate_token("resource_id", &self.resource_id)?;
        validate_token("conflict_domain_id", &self.conflict_domain_id)?;
        validate_token("idempotency_key", &self.idempotency_key)?;
        self.resource_profile.validate()?;
        validate_resource_set("read_set", &self.read_set, true)?;
        validate_resource_set("write_set", &self.write_set, false)?;
        let reads: BTreeSet<_> = self.read_set.iter().map(|entry| &entry.key).collect();
        if self
            .write_set
            .iter()
            .any(|entry| reads.contains(&entry.key))
        {
            return Err(ConsequenceTypeError::OverlappingReadWriteSet);
        }
        if let Some(required) = self.required_guarantees.conflict_domain_hash {
            if required != self.conflict_domain_commitment()? {
                return Err(ConsequenceTypeError::RequiredConflictDomainMismatch);
            }
        }
        match self.fence {
            EffectFenceV1::ProtocolHeight {
                minimum_height,
                maximum_height,
                ..
            } if minimum_height == 0 || maximum_height < minimum_height => {
                return Err(ConsequenceTypeError::InvalidFence)
            }
            EffectFenceV1::AuthorityEpoch {
                authority_epoch,
                expires_at_height,
                ..
            } if authority_epoch == 0 || expires_at_height == 0 => {
                return Err(ConsequenceTypeError::InvalidFence)
            }
            _ => {}
        }
        if matches!(
            self.reconciliation,
            ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations: 0
            }
        ) {
            return Err(ConsequenceTypeError::InvalidReconciliationPolicy);
        }
        if self.irreversible
            && self.resource_profile.contract.supports_at_most_once()
            && !matches!(
                self.reconciliation,
                ReconciliationPolicyV1::LookupByIdempotencyKey { .. }
            )
        {
            return Err(ConsequenceTypeError::InvalidReconciliationPolicy);
        }
        Ok(())
    }

    /// Encode the manifest as RFC 8785/JCS bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConsequenceTypeError> {
        self.validate()?;
        serde_jcs::to_vec(self)
            .map_err(|error| ConsequenceTypeError::CanonicalEncoding(error.to_string()))
    }

    /// Compute the domain-separated manifest commitment.
    pub fn commitment(&self) -> Result<ConsequenceHash, ConsequenceTypeError> {
        self.validate()?;
        commitment(EFFECT_MANIFEST_V1_DOMAIN, self)
    }

    /// Commit the human-readable conflict-domain identity into the safety
    /// coordinate namespace.
    pub fn conflict_domain_commitment(&self) -> Result<ConsequenceHash, ConsequenceTypeError> {
        conflict_domain_id_commitment(&self.conflict_domain_id)
    }
}

/// Domain-separated commitment shared by finality and consequence evidence.
pub fn conflict_domain_id_commitment(
    conflict_domain_id: &str,
) -> Result<ConsequenceHash, ConsequenceTypeError> {
    validate_token("conflict_domain_id", conflict_domain_id)?;
    let mut material =
        Vec::with_capacity(CONFLICT_DOMAIN_ID_V1_DOMAIN.len() + conflict_domain_id.len());
    material.extend_from_slice(CONFLICT_DOMAIN_ID_V1_DOMAIN);
    material.extend_from_slice(conflict_domain_id.as_bytes());
    let digest = DcryptSha256::digest(&material)
        .map_err(|error| ConsequenceTypeError::CommitmentHash(error.to_string()))?;
    digest.as_ref().try_into().map_err(|_| {
        ConsequenceTypeError::CommitmentHash("SHA-256 returned non-32-byte digest".into())
    })
}

/// Atomic register value returned by mutation and lookup. Signed or otherwise
/// verifiable endpoint evidence is optional; its absence must not be described
/// as attributable fault evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalResourceRecordV1 {
    /// Exact resource whose register was observed.
    pub resource_id: String,
    /// Stable register key.
    pub idempotency_key: String,
    /// Request commitment stored by the atomic resource.
    pub request_root: ConsequenceHash,
    /// Predecessor commitment checked by the atomic resource.
    pub predecessor_root: ConsequenceHash,
    /// Observed outcome commitment.
    pub outcome_root: ConsequenceHash,
    /// Resource-defined nonzero mutation sequence.
    pub mutation_sequence: u64,
    /// Optional signed or independently verifiable endpoint evidence.
    pub evidence: Option<Vec<u8>>,
    /// Commitment to `evidence`, present if and only if evidence is present.
    pub evidence_hash: Option<ConsequenceHash>,
}

impl ExternalResourceRecordV1 {
    /// Validate record scope and optional evidence commitment.
    pub fn validate(&self) -> Result<(), ConsequenceTypeError> {
        validate_token("resource_id", &self.resource_id)?;
        validate_token("idempotency_key", &self.idempotency_key)?;
        if self.mutation_sequence == 0 || self.evidence.is_some() != self.evidence_hash.is_some() {
            return Err(ConsequenceTypeError::InvalidResourceRecord);
        }
        if let (Some(evidence), Some(expected)) = (&self.evidence, self.evidence_hash) {
            if commitment(b"ioi::aft::external-resource-evidence::v1\0", evidence)? != expected {
                return Err(ConsequenceTypeError::InvalidResourceRecord);
            }
        }
        Ok(())
    }

    /// Compute the canonical resource-record commitment.
    pub fn commitment(&self) -> Result<ConsequenceHash, ConsequenceTypeError> {
        self.validate()?;
        commitment(RESOURCE_RECORD_V1_DOMAIN, self)
    }
}

/// Fail-closed manifest, profile, and evidence errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsequenceTypeError {
    /// One identity field is empty, non-canonical, or too long.
    #[error("{0} is not a canonical non-empty token")]
    InvalidToken(&'static str),
    /// A read/write set is not strictly sorted.
    #[error("{0} is not sorted and duplicate-free")]
    NonCanonicalResourceSet(&'static str),
    /// No mutation target was declared.
    #[error("write_set must contain at least one resource key")]
    EmptyWriteSet,
    /// One key ambiguously appears as both read-only and writable.
    #[error("one resource key appears in both read_set and write_set")]
    OverlappingReadWriteSet,
    /// Height/epoch bounds are empty or reversed.
    #[error("effect authority/height fence is invalid")]
    InvalidFence,
    /// Reconciliation cannot safely resolve the declared atomic operation.
    #[error("effect reconciliation policy is invalid for the resource contract")]
    InvalidReconciliationPolicy,
    /// Required safety scope does not name this manifest's conflict domain.
    #[error("required guarantee conflict domain does not match the manifest")]
    RequiredConflictDomainMismatch,
    /// A PQ label omitted its exact rooted endpoint key, or a classical
    /// profile attempted to carry one.
    #[error("externalization_pq must exactly match a nonzero rooted endpoint key")]
    InvalidExternalizationPqBinding,
    /// Resource record shape or evidence commitment is invalid.
    #[error("external resource record is malformed or its evidence commitment is wrong")]
    InvalidResourceRecord,
    /// RFC 8785/JCS encoding failed.
    #[error("canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    /// Commitment hashing failed.
    #[error("SHA-256 commitment failed: {0}")]
    CommitmentHash(String),
}

fn validate_token(name: &'static str, value: &str) -> Result<(), ConsequenceTypeError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ConsequenceTypeError::InvalidToken(name))
    } else {
        Ok(())
    }
}

fn validate_resource_set(
    name: &'static str,
    entries: &[EffectResourceKeyV1],
    allow_empty: bool,
) -> Result<(), ConsequenceTypeError> {
    if !allow_empty && entries.is_empty() {
        return Err(ConsequenceTypeError::EmptyWriteSet);
    }
    for entry in entries {
        validate_token("resource_key", &entry.key)?;
    }
    if entries.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ConsequenceTypeError::NonCanonicalResourceSet(name));
    }
    Ok(())
}

fn commitment<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ConsequenceHash, ConsequenceTypeError> {
    let canonical = serde_jcs::to_vec(value)
        .map_err(|error| ConsequenceTypeError::CanonicalEncoding(error.to_string()))?;
    let mut material = Vec::with_capacity(domain.len() + canonical.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(&canonical);
    let digest = DcryptSha256::digest(&material)
        .map_err(|error| ConsequenceTypeError::CommitmentHash(error.to_string()))?;
    digest.as_ref().try_into().map_err(|_| {
        ConsequenceTypeError::CommitmentHash("SHA-256 returned non-32-byte digest".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(contract: ExternalResourceContractV1) -> ExternalResourceProfileV1 {
        ExternalResourceProfileV1 {
            adapter_id: "adapter://bank-transfer".into(),
            adapter_version: "v1".into(),
            resource_profile_id: "resource-profile://atomic-register-v1".into(),
            contract,
            externalization_pq: true,
            endpoint_pq_key_hash: Some([9; 32]),
        }
    }

    fn manifest(contract: ExternalResourceContractV1) -> EffectManifestV1 {
        EffectManifestV1 {
            schema_version: EffectManifestVersionV1::V1,
            effect_id: "effect-1".into(),
            resource_id: "resource://ledger/account-a".into(),
            conflict_domain_id: "domain://account-a".into(),
            read_set: vec![EffectResourceKeyV1 {
                key: "balance/source".into(),
                predecessor: Some([1; 32]),
            }],
            write_set: vec![EffectResourceKeyV1 {
                key: "transfer/42".into(),
                predecessor: None,
            }],
            idempotency_key: "transfer-42".into(),
            request_root: [2; 32],
            predecessor_root: [3; 32],
            intent_root: [4; 32],
            expected_outcome_root: [5; 32],
            resource_profile: profile(contract),
            required_guarantees: GuaranteeRequirementsV1 {
                minimum_externalization: Some(ExternalizationModeV1::IdempotencyRegister),
                require_at_most_once: true,
                ..Default::default()
            },
            fence: EffectFenceV1::ProtocolHeight {
                configuration_hash: [6; 32],
                minimum_height: 8,
                maximum_height: 8,
            },
            reconciliation: ReconciliationPolicyV1::LookupByIdempotencyKey {
                maximum_observations: 3,
            },
            irreversible: true,
        }
    }

    #[test]
    fn manifest_binds_every_effect_boundary_and_is_canonical() {
        let manifest = manifest(ExternalResourceContractV1::AtomicPutIfAbsent);
        let root = manifest.commitment().unwrap();
        assert_eq!(root, manifest.clone().commitment().unwrap());
        let mut mutated = manifest;
        mutated.expected_outcome_root[0] ^= 1;
        assert_ne!(root, mutated.commitment().unwrap());
    }

    #[test]
    fn unsupported_resource_truthfully_advertises_no_at_most_once_guarantee() {
        let coordinate = profile(ExternalResourceContractV1::UnsupportedBestEffort)
            .advertised_externalization()
            .unwrap();
        assert_eq!(coordinate.mode, ExternalizationModeV1::BestEffort);
        assert!(!coordinate.at_most_once);
    }

    #[test]
    fn externalization_pq_requires_exactly_one_nonzero_rooted_endpoint_key() {
        let mut resource = profile(ExternalResourceContractV1::AtomicPutIfAbsent);
        resource.endpoint_pq_key_hash = None;
        assert_eq!(
            resource.validate(),
            Err(ConsequenceTypeError::InvalidExternalizationPqBinding)
        );

        resource.endpoint_pq_key_hash = Some([0; 32]);
        assert_eq!(
            resource.validate(),
            Err(ConsequenceTypeError::InvalidExternalizationPqBinding)
        );

        resource.externalization_pq = false;
        resource.endpoint_pq_key_hash = Some([9; 32]);
        assert_eq!(
            resource.validate(),
            Err(ConsequenceTypeError::InvalidExternalizationPqBinding)
        );

        resource.endpoint_pq_key_hash = None;
        assert_eq!(resource.validate(), Ok(()));
    }

    #[test]
    fn irreversible_atomic_effect_requires_safe_reconciliation() {
        let mut manifest = manifest(ExternalResourceContractV1::AtomicCompareAndSet);
        manifest.reconciliation = ReconciliationPolicyV1::NoSafeReconciliation;
        assert_eq!(
            manifest.validate(),
            Err(ConsequenceTypeError::InvalidReconciliationPolicy)
        );
    }

    #[test]
    fn resource_sets_are_sorted_disjoint_and_duplicate_free() {
        let mut manifest = manifest(ExternalResourceContractV1::AtomicPutIfAbsent);
        manifest.write_set.push(manifest.write_set[0].clone());
        assert_eq!(
            manifest.validate(),
            Err(ConsequenceTypeError::NonCanonicalResourceSet("write_set"))
        );
    }
}
