//! Portable receipt hash-chain checkpoints and offline inclusion/consistency verification.
//!
//! Version 1 deliberately uses a linear, domain-separated hash chain. It is not a
//! Merkle tree or RFC 6962 proof. Inclusion witnesses carry the prefix root and all
//! later leaf hashes; consistency witnesses carry every appended leaf hash.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::generated::architecture_contracts::{
    architecture_contract_schema_hash, validate_architecture_contract, AuthorityKeySetV1,
    AuthorityRevocationSnapshotV1, ReceiptCheckpointV1, ReceiptProofBundleV1,
};
use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;

/// Registered ReceiptEnvelope v1 contract.
pub const RECEIPT_ENVELOPE_V1_CONTRACT_ID: &str = "schema://ioi/foundations/receipt-envelope/v1";
/// Registered signed receipt checkpoint contract.
pub const RECEIPT_CHECKPOINT_V1_CONTRACT_ID: &str =
    "schema://ioi/foundations/receipt-checkpoint/v1";
/// Registered offline receipt proof export contract.
pub const RECEIPT_PROOF_BUNDLE_V1_CONTRACT_ID: &str =
    "schema://ioi/foundations/receipt-proof-bundle/v1";
/// Domain/version identity for the append-only accumulator.
pub const RECEIPT_ACCUMULATOR_V1: &str = "ioi.receipt-hash-chain-jcs-sha256.v1";
/// Domain/version identity for exact ReceiptEnvelope body hashing.
pub const RECEIPT_BODY_HASH_PROFILE_V1: &str = "ioi.receipt-envelope-jcs-sha256.v1";
/// Unambiguous prefix for indexed receipt leaves.
pub const RECEIPT_LEAF_V1_PREFIX: &[u8] = b"IOI-RECEIPT-ACCUMULATOR-LEAF-V1\0";
/// Unambiguous prefix for accumulator transitions.
pub const RECEIPT_STEP_V1_PREFIX: &[u8] = b"IOI-RECEIPT-ACCUMULATOR-STEP-V1\0";
/// Unambiguous empty accumulator value.
pub const RECEIPT_EMPTY_V1_PREFIX: &[u8] = b"IOI-RECEIPT-ACCUMULATOR-EMPTY-V1\0";
/// Unambiguous prefix for receipt checkpoint signatures.
pub const RECEIPT_CHECKPOINT_V1_SIGNING_PREFIX: &[u8] = b"IOI-RECEIPT-CHECKPOINT-V1\0";
/// Unambiguous prefix for ReceiptProofBundle v1 manifest signatures.
pub const RECEIPT_PROOF_BUNDLE_V1_SIGNING_PREFIX: &[u8] = b"IOI-RECEIPT-PROOF-BUNDLE-MANIFEST-V1\0";
const REVOCATION_V1_SIGNING_PREFIX: &[u8] = b"IOI-AUTHORITY-REVOCATION-SNAPSHOT-V1\0";
const AUTHORITY_KEY_SET_V1_CONTRACT_ID: &str = "schema://ioi/foundations/authority-key-set/v1";
const AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID: &str =
    "schema://ioi/foundations/authority-revocation-snapshot/v1";

/// Stable fail-closed classifications returned by the shared verifier and CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptProofErrorCode {
    /// A registered closed schema or invariant rejected the artifact.
    Structural,
    /// A registry schema hash was absent or mismatched.
    SchemaHash,
    /// The exact ReceiptEnvelope JCS hash was mismatched.
    ReceiptBodyHash,
    /// An indexed accumulator leaf was mismatched.
    LeafHash,
    /// The linear inclusion witness did not produce the signed root.
    Inclusion,
    /// The checkpoint body or full artifact hash was mismatched.
    CheckpointHash,
    /// The prior checkpoint linkage or append-only witness was inconsistent.
    Consistency,
    /// The proof export manifest hash was mismatched.
    ManifestHash,
    /// An Ed25519 signature was invalid.
    Signature,
    /// A supplied key set did not bind the checkpoint issuer/version.
    KeySet,
    /// The referenced signing key was absent.
    KeyUnknown,
    /// The signing key was revoked.
    KeyRevoked,
    /// The key set or signing key was outside its accepted validity window.
    KeyStale,
    /// The signed revocation snapshot was missing, stale, or older than declared.
    SnapshotStale,
    /// Trusted-input refs in the manifest did not bind supplied artifacts.
    TrustedInput,
}

impl ReceiptProofErrorCode {
    /// Machine-readable verifier code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::SchemaHash => "schema_hash",
            Self::ReceiptBodyHash => "receipt_body_hash",
            Self::LeafHash => "leaf_hash",
            Self::Inclusion => "inclusion",
            Self::CheckpointHash => "checkpoint_hash",
            Self::Consistency => "consistency",
            Self::ManifestHash => "manifest_hash",
            Self::Signature => "signature",
            Self::KeySet => "key_set",
            Self::KeyUnknown => "key_unknown",
            Self::KeyRevoked => "key_revoked",
            Self::KeyStale => "key_stale",
            Self::SnapshotStale => "snapshot_stale",
            Self::TrustedInput => "trusted_input",
        }
    }
}

/// Detailed portable receipt-proof verification failure.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{code}: {detail}", code = .code.as_str())]
pub struct ReceiptProofError {
    /// Stable failure class.
    pub code: ReceiptProofErrorCode,
    /// Human-readable failure detail.
    pub detail: String,
}

impl ReceiptProofError {
    fn new(code: ReceiptProofErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Trusted local inputs required for offline receipt-proof verification.
pub struct ReceiptProofVerificationContext<'a> {
    /// Trusted caller-provided Unix time in seconds.
    pub now: u64,
    /// Maximum accepted revocation-snapshot age in seconds.
    pub max_snapshot_staleness_seconds: u64,
    /// Locally trusted checkpoint-issuer key set.
    pub key_set: &'a AuthorityKeySetV1,
    /// Signed bounded-freshness key-revocation snapshot.
    pub revocation_snapshot: &'a AuthorityRevocationSnapshotV1,
}

fn structural<T: Serialize>(contract_id: &str, value: &T) -> Result<(), ReceiptProofError> {
    let value = serde_json::to_value(value).map_err(|error| {
        ReceiptProofError::new(ReceiptProofErrorCode::Structural, error.to_string())
    })?;
    validate_architecture_contract(contract_id, &value)
        .map_err(|detail| ReceiptProofError::new(ReceiptProofErrorCode::Structural, detail))
}

fn sha256_bytes(bytes: &[u8], code: ReceiptProofErrorCode) -> Result<String, ReceiptProofError> {
    let digest =
        Sha256::digest(bytes).map_err(|error| ReceiptProofError::new(code, error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn sha256_jcs<T: Serialize>(
    value: &T,
    code: ReceiptProofErrorCode,
) -> Result<String, ReceiptProofError> {
    let canonical = serde_jcs::to_vec(value)
        .map_err(|error| ReceiptProofError::new(code, error.to_string()))?;
    sha256_bytes(&canonical, code)
}

fn prefixed_jcs_hash<T: Serialize>(
    prefix: &[u8],
    value: &T,
    code: ReceiptProofErrorCode,
) -> Result<String, ReceiptProofError> {
    let mut bytes = prefix.to_vec();
    bytes.extend(
        serde_jcs::to_vec(value)
            .map_err(|error| ReceiptProofError::new(code, error.to_string()))?,
    );
    sha256_bytes(&bytes, code)
}

fn unsigned_value<T: Serialize>(
    value: &T,
    fields: &[&str],
    code: ReceiptProofErrorCode,
) -> Result<Value, ReceiptProofError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| ReceiptProofError::new(code, error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        ReceiptProofError::new(code, "portable proof artifact must be a JSON object")
    })?;
    for field in fields {
        object.remove(*field);
    }
    Ok(value)
}

/// Computes the RFC 8785 JCS SHA-256 hash of one exact ReceiptEnvelope value.
pub fn receipt_envelope_v1_body_hash(receipt: &Value) -> Result<String, ReceiptProofError> {
    sha256_jcs(receipt, ReceiptProofErrorCode::ReceiptBodyHash)
}

/// Computes the domain-separated indexed leaf for one ReceiptEnvelope body hash.
pub fn receipt_accumulator_v1_leaf_hash(
    receipt_body_hash: &str,
    receipt_schema_hash: &str,
    leaf_index: u64,
) -> Result<String, ReceiptProofError> {
    prefixed_jcs_hash(
        RECEIPT_LEAF_V1_PREFIX,
        &json!({
            "domain": "ioi.receipt-accumulator-leaf.v1",
            "leaf_index": leaf_index,
            "receipt_body_hash": receipt_body_hash,
            "receipt_contract_id": RECEIPT_ENVELOPE_V1_CONTRACT_ID,
            "receipt_schema_hash": receipt_schema_hash,
        }),
        ReceiptProofErrorCode::LeafHash,
    )
}

/// Returns the fixed empty root for the v1 receipt hash chain.
pub fn receipt_accumulator_v1_empty_root() -> Result<String, ReceiptProofError> {
    sha256_bytes(RECEIPT_EMPTY_V1_PREFIX, ReceiptProofErrorCode::Consistency)
}

/// Applies one domain-separated append transition to a v1 receipt hash chain.
pub fn receipt_accumulator_v1_step(
    previous_root: &str,
    leaf_hash: &str,
) -> Result<String, ReceiptProofError> {
    prefixed_jcs_hash(
        RECEIPT_STEP_V1_PREFIX,
        &json!({"leaf_hash": leaf_hash, "previous_root": previous_root}),
        ReceiptProofErrorCode::Consistency,
    )
}

fn accumulate<'a>(
    initial_root: &str,
    leaves: impl IntoIterator<Item = &'a String>,
) -> Result<String, ReceiptProofError> {
    leaves
        .into_iter()
        .try_fold(initial_root.to_string(), |root, leaf| {
            receipt_accumulator_v1_step(&root, leaf)
        })
}

fn checkpoint_body_hash(checkpoint: &ReceiptCheckpointV1) -> Result<String, ReceiptProofError> {
    sha256_jcs(
        &unsigned_value(
            checkpoint,
            &[
                "body_hash",
                "signature_suite",
                "signature_key_id",
                "signature",
            ],
            ReceiptProofErrorCode::CheckpointHash,
        )?,
        ReceiptProofErrorCode::CheckpointHash,
    )
}

/// Computes the full signed checkpoint artifact hash used by the successor link.
pub fn receipt_checkpoint_v1_artifact_hash(
    checkpoint: &ReceiptCheckpointV1,
) -> Result<String, ReceiptProofError> {
    sha256_jcs(checkpoint, ReceiptProofErrorCode::CheckpointHash)
}

/// Produces the exact domain-separated bytes signed by a ReceiptCheckpoint v1.
pub fn receipt_checkpoint_v1_signing_bytes(
    checkpoint: &ReceiptCheckpointV1,
) -> Result<Vec<u8>, ReceiptProofError> {
    let material = json!({
        "accumulator_algorithm": checkpoint.accumulator_algorithm,
        "accumulator_root": checkpoint.accumulator_root,
        "accumulator_size": checkpoint.accumulator_size,
        "body_hash": checkpoint.body_hash,
        "schema_hash": checkpoint.schema_hash,
        "signature_domain": checkpoint.signature_domain,
    });
    let mut bytes = RECEIPT_CHECKPOINT_V1_SIGNING_PREFIX.to_vec();
    bytes.extend(serde_jcs::to_vec(&material).map_err(|error| {
        ReceiptProofError::new(ReceiptProofErrorCode::Signature, error.to_string())
    })?);
    Ok(bytes)
}

fn verify_ed25519(
    public_key: &str,
    signature: &str,
    message: &[u8],
) -> Result<(), ReceiptProofError> {
    let public_key = URL_SAFE_NO_PAD.decode(public_key).map_err(|_| {
        ReceiptProofError::new(
            ReceiptProofErrorCode::KeyUnknown,
            "invalid base64url public key",
        )
    })?;
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| {
        ReceiptProofError::new(
            ReceiptProofErrorCode::Signature,
            "invalid base64url signature",
        )
    })?;
    let public_key = Ed25519PublicKey::from_bytes(&public_key).map_err(|error| {
        ReceiptProofError::new(ReceiptProofErrorCode::KeyUnknown, error.to_string())
    })?;
    let signature = Ed25519Signature::from_bytes(&signature).map_err(|error| {
        ReceiptProofError::new(ReceiptProofErrorCode::Signature, error.to_string())
    })?;
    public_key.verify(message, &signature).map_err(|error| {
        ReceiptProofError::new(ReceiptProofErrorCode::Signature, error.to_string())
    })
}

fn snapshot_body_hash(
    snapshot: &AuthorityRevocationSnapshotV1,
) -> Result<String, ReceiptProofError> {
    sha256_jcs(
        &unsigned_value(
            snapshot,
            &[
                "body_hash",
                "signature_suite",
                "signature_key_id",
                "signature",
            ],
            ReceiptProofErrorCode::SnapshotStale,
        )?,
        ReceiptProofErrorCode::SnapshotStale,
    )
}

fn snapshot_signing_bytes(
    snapshot: &AuthorityRevocationSnapshotV1,
) -> Result<Vec<u8>, ReceiptProofError> {
    let material = json!({
        "body_hash": snapshot.body_hash,
        "signature_domain": snapshot.signature_domain,
    });
    let mut bytes = REVOCATION_V1_SIGNING_PREFIX.to_vec();
    bytes.extend(serde_jcs::to_vec(&material).map_err(|error| {
        ReceiptProofError::new(ReceiptProofErrorCode::Signature, error.to_string())
    })?);
    Ok(bytes)
}

fn key_material<'a>(
    key_set: &'a AuthorityKeySetV1,
    key_id: &str,
    at: u64,
) -> Result<&'a str, ReceiptProofError> {
    let key = key_set
        .keys
        .iter()
        .find(|candidate| candidate.key_id == key_id)
        .ok_or_else(|| {
            ReceiptProofError::new(ReceiptProofErrorCode::KeyUnknown, "signing key is absent")
        })?;
    if key.status == "revoked" {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeyRevoked,
            "signing key is revoked in the trusted key set",
        ));
    }
    if key.signature_suite != "ed25519" {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeyUnknown,
            "signing key suite is not ed25519",
        ));
    }
    if at < key.not_before || at > key.expires_at {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeyStale,
            "signing key was not valid at checkpoint issuance",
        ));
    }
    Ok(&key.public_key)
}

fn verify_snapshot(context: &ReceiptProofVerificationContext<'_>) -> Result<(), ReceiptProofError> {
    structural(AUTHORITY_KEY_SET_V1_CONTRACT_ID, context.key_set)?;
    structural(
        AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID,
        context.revocation_snapshot,
    )?;
    let snapshot = context.revocation_snapshot;
    let key_set = context.key_set;
    if snapshot.issuer_id != key_set.issuer_id
        || snapshot.issuer_key_set_ref != key_set.key_set_id
        || snapshot.issuer_key_set_version > key_set.version
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeySet,
            "revocation snapshot does not bind the trusted key set",
        ));
    }
    if key_set.issued_at > context.now || key_set.expires_at < context.now {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeyStale,
            "trusted issuer key set is outside its validity window",
        ));
    }
    if snapshot.issued_at > context.now
        || snapshot.expires_at < context.now
        || context.now.saturating_sub(snapshot.issued_at) > context.max_snapshot_staleness_seconds
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::SnapshotStale,
            "revocation snapshot exceeds the trusted freshness bound",
        ));
    }
    if snapshot_body_hash(snapshot)? != snapshot.body_hash {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::SnapshotStale,
            "revocation snapshot body hash mismatch",
        ));
    }
    let public_key = key_material(key_set, &snapshot.signature_key_id, snapshot.issued_at)?;
    verify_ed25519(
        public_key,
        &snapshot.signature,
        &snapshot_signing_bytes(snapshot)?,
    )
}

fn verify_checkpoint(
    checkpoint: &ReceiptCheckpointV1,
    context: &ReceiptProofVerificationContext<'_>,
) -> Result<(), ReceiptProofError> {
    structural(RECEIPT_CHECKPOINT_V1_CONTRACT_ID, checkpoint)?;
    let expected_checkpoint_schema =
        architecture_contract_schema_hash(RECEIPT_CHECKPOINT_V1_CONTRACT_ID).ok_or_else(|| {
            ReceiptProofError::new(
                ReceiptProofErrorCode::SchemaHash,
                "checkpoint schema hash unavailable",
            )
        })?;
    let expected_receipt_schema =
        architecture_contract_schema_hash(RECEIPT_ENVELOPE_V1_CONTRACT_ID).ok_or_else(|| {
            ReceiptProofError::new(
                ReceiptProofErrorCode::SchemaHash,
                "receipt schema hash unavailable",
            )
        })?;
    if checkpoint.schema_hash != expected_checkpoint_schema
        || checkpoint.receipt_schema_hash != expected_receipt_schema
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::SchemaHash,
            "checkpoint schema binding mismatch",
        ));
    }
    if checkpoint_body_hash(checkpoint)? != checkpoint.body_hash {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::CheckpointHash,
            "checkpoint body hash mismatch",
        ));
    }
    let previous_fields = [
        checkpoint.previous_checkpoint_ref.is_some(),
        checkpoint.previous_checkpoint_hash.is_some(),
        checkpoint.previous_accumulator_size.is_some(),
        checkpoint.previous_accumulator_root.is_some(),
    ];
    if previous_fields.iter().any(|present| *present)
        && !previous_fields.iter().all(|present| *present)
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::Consistency,
            "checkpoint previous-link tuple is only partially populated",
        ));
    }
    if checkpoint.signature_key_id != checkpoint.issuer_key_id
        || checkpoint.issuer_id != context.key_set.issuer_id
        || checkpoint.issuer_key_set_ref != context.key_set.key_set_id
        || checkpoint.issuer_key_set_version > context.key_set.version
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeySet,
            "checkpoint issuer/key-set binding mismatch",
        ));
    }
    verify_snapshot(context)?;
    if context
        .revocation_snapshot
        .revoked_key_ids
        .contains(&checkpoint.signature_key_id)
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeyRevoked,
            "checkpoint signing key is revoked",
        ));
    }
    let public_key = key_material(
        context.key_set,
        &checkpoint.signature_key_id,
        checkpoint.issued_at,
    )?;
    verify_ed25519(
        public_key,
        &checkpoint.signature,
        &receipt_checkpoint_v1_signing_bytes(checkpoint)?,
    )
}

fn bundle_manifest_hash(bundle: &ReceiptProofBundleV1) -> Result<String, ReceiptProofError> {
    sha256_jcs(
        &unsigned_value(
            bundle,
            &[
                "manifest_hash",
                "manifest_signature_suite",
                "manifest_signature_key_id",
                "manifest_signature",
            ],
            ReceiptProofErrorCode::ManifestHash,
        )?,
        ReceiptProofErrorCode::ManifestHash,
    )
}

fn bundle_manifest_signing_bytes(
    bundle: &ReceiptProofBundleV1,
) -> Result<Vec<u8>, ReceiptProofError> {
    let material = json!({
        "bundle_schema_hash": bundle.bundle_schema_hash,
        "manifest_domain": bundle.manifest_domain,
        "manifest_hash": bundle.manifest_hash,
    });
    let mut bytes = RECEIPT_PROOF_BUNDLE_V1_SIGNING_PREFIX.to_vec();
    bytes.extend(serde_jcs::to_vec(&material).map_err(|error| {
        ReceiptProofError::new(ReceiptProofErrorCode::Signature, error.to_string())
    })?);
    Ok(bytes)
}

/// Verifies one complete ReceiptProofBundle using only caller-supplied local trust inputs.
pub fn verify_receipt_proof_bundle_v1(
    bundle: &ReceiptProofBundleV1,
    context: &ReceiptProofVerificationContext<'_>,
) -> Result<(), ReceiptProofError> {
    structural(RECEIPT_PROOF_BUNDLE_V1_CONTRACT_ID, bundle)?;
    let expected_bundle_schema = architecture_contract_schema_hash(
        RECEIPT_PROOF_BUNDLE_V1_CONTRACT_ID,
    )
    .ok_or_else(|| {
        ReceiptProofError::new(
            ReceiptProofErrorCode::SchemaHash,
            "bundle schema hash unavailable",
        )
    })?;
    let expected_receipt_schema =
        architecture_contract_schema_hash(RECEIPT_ENVELOPE_V1_CONTRACT_ID).ok_or_else(|| {
            ReceiptProofError::new(
                ReceiptProofErrorCode::SchemaHash,
                "receipt schema hash unavailable",
            )
        })?;
    if bundle.bundle_schema_hash != expected_bundle_schema
        || bundle.receipt_schema_hash != expected_receipt_schema
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::SchemaHash,
            "proof-bundle schema binding mismatch",
        ));
    }
    validate_architecture_contract(RECEIPT_ENVELOPE_V1_CONTRACT_ID, &bundle.receipt)
        .map_err(|detail| ReceiptProofError::new(ReceiptProofErrorCode::Structural, detail))?;
    if receipt_envelope_v1_body_hash(&bundle.receipt)? != bundle.receipt_body_hash {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::ReceiptBodyHash,
            "exact ReceiptEnvelope JCS hash mismatch",
        ));
    }
    let expected_leaf = receipt_accumulator_v1_leaf_hash(
        &bundle.receipt_body_hash,
        &bundle.receipt_schema_hash,
        bundle.leaf.leaf_index,
    )?;
    if expected_leaf != bundle.leaf.leaf_hash {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::LeafHash,
            "indexed receipt leaf hash mismatch",
        ));
    }
    let checkpoint: ReceiptCheckpointV1 = serde_json::from_value(bundle.checkpoint.clone())
        .map_err(|error| {
            ReceiptProofError::new(ReceiptProofErrorCode::Structural, error.to_string())
        })?;
    if checkpoint.receipt_schema_hash != bundle.receipt_schema_hash {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::SchemaHash,
            "checkpoint and proof bundle bind different receipt schemas",
        ));
    }
    if bundle.leaf.leaf_index >= checkpoint.accumulator_size {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::Inclusion,
            "leaf index is outside the checkpoint accumulator",
        ));
    }
    let expected_suffix = checkpoint
        .accumulator_size
        .saturating_sub(bundle.leaf.leaf_index)
        .saturating_sub(1);
    if bundle.inclusion_proof.suffix_leaf_hashes.len() as u64 != expected_suffix {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::Inclusion,
            "inclusion witness has the wrong suffix length",
        ));
    }
    let included =
        receipt_accumulator_v1_step(&bundle.inclusion_proof.prefix_root, &bundle.leaf.leaf_hash)?;
    let included = accumulate(&included, &bundle.inclusion_proof.suffix_leaf_hashes)?;
    if included != checkpoint.accumulator_root {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::Inclusion,
            "inclusion witness does not produce the signed checkpoint root",
        ));
    }
    verify_checkpoint(&checkpoint, context)?;

    let previous = bundle
        .previous_checkpoint
        .as_ref()
        .map(|value| serde_json::from_value::<ReceiptCheckpointV1>(value.clone()))
        .transpose()
        .map_err(|error| {
            ReceiptProofError::new(ReceiptProofErrorCode::Structural, error.to_string())
        })?;
    match previous.as_ref() {
        Some(previous) => {
            verify_checkpoint(previous, context)?;
            let previous_hash = receipt_checkpoint_v1_artifact_hash(previous)?;
            if checkpoint.previous_checkpoint_ref.as_deref()
                != Some(previous.checkpoint_id.as_str())
                || checkpoint.previous_checkpoint_hash.as_deref() != Some(previous_hash.as_str())
                || checkpoint.previous_accumulator_size != Some(previous.accumulator_size)
                || checkpoint.previous_accumulator_root.as_deref()
                    != Some(previous.accumulator_root.as_str())
                || previous.receipt_log_id != checkpoint.receipt_log_id
                || previous.accumulator_size >= checkpoint.accumulator_size
            {
                return Err(ReceiptProofError::new(
                    ReceiptProofErrorCode::Consistency,
                    "current checkpoint does not bind the supplied predecessor",
                ));
            }
            if bundle.consistency_proof.from_size != previous.accumulator_size
                || bundle.consistency_proof.from_root != previous.accumulator_root
            {
                return Err(ReceiptProofError::new(
                    ReceiptProofErrorCode::Consistency,
                    "consistency witness does not start at the signed predecessor",
                ));
            }
        }
        None => {
            if checkpoint.previous_checkpoint_ref.is_some()
                || checkpoint.previous_checkpoint_hash.is_some()
                || checkpoint.previous_accumulator_size.is_some()
                || checkpoint.previous_accumulator_root.is_some()
                || bundle.consistency_proof.from_size != 0
                || bundle.consistency_proof.from_root != receipt_accumulator_v1_empty_root()?
            {
                return Err(ReceiptProofError::new(
                    ReceiptProofErrorCode::Consistency,
                    "genesis proof has a predecessor or non-empty starting root",
                ));
            }
        }
    }
    let expected_extension = checkpoint
        .accumulator_size
        .checked_sub(bundle.consistency_proof.from_size)
        .ok_or_else(|| {
            ReceiptProofError::new(
                ReceiptProofErrorCode::Consistency,
                "checkpoint size regressed",
            )
        })?;
    if bundle.consistency_proof.extension_leaf_hashes.len() as u64 != expected_extension {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::Consistency,
            "append-only witness has the wrong extension length",
        ));
    }
    let consistent = accumulate(
        &bundle.consistency_proof.from_root,
        &bundle.consistency_proof.extension_leaf_hashes,
    )?;
    if consistent != checkpoint.accumulator_root {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::Consistency,
            "append-only witness does not produce the signed current root",
        ));
    }
    if bundle.trusted_input_refs.key_set_ref != context.key_set.key_set_id
        || bundle.trusted_input_refs.key_set_version > context.key_set.version
        || bundle.trusted_input_refs.revocation_snapshot_ref
            != context.revocation_snapshot.snapshot_id
        || bundle.trusted_input_refs.revocation_epoch != context.revocation_snapshot.epoch
    {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::TrustedInput,
            "manifest trusted-input refs do not bind supplied verifier inputs",
        ));
    }
    if bundle_manifest_hash(bundle)? != bundle.manifest_hash {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::ManifestHash,
            "proof export manifest hash mismatch",
        ));
    }
    if bundle.manifest_signature_key_id != checkpoint.signature_key_id {
        return Err(ReceiptProofError::new(
            ReceiptProofErrorCode::KeySet,
            "manifest and checkpoint must use the same enrolled signer in v1",
        ));
    }
    let manifest_public_key = key_material(
        context.key_set,
        &bundle.manifest_signature_key_id,
        checkpoint.issued_at,
    )?;
    verify_ed25519(
        manifest_public_key,
        &bundle.manifest_signature,
        &bundle_manifest_signing_bytes(bundle)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    const BUNDLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/receipt-proof-bundle-v1/positive-offline.json"
    ));
    const KEY_SET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-active.json"
    ));
    const SNAPSHOT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-revocation-snapshot-v1/positive-current.json"
    ));
    const REVOKED_SNAPSHOT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/receipt-proof/revoked-signer-snapshot.json"
    ));
    const DELEGATOR_KEYS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-delegator.json"
    ));
    const NOW: u64 = 1_784_203_300;

    fn parse<T: DeserializeOwned>(value: &str) -> T {
        serde_json::from_str(value).expect("golden fixture parses")
    }

    fn verify(
        bundle: &ReceiptProofBundleV1,
        key_set: &AuthorityKeySetV1,
        snapshot: &AuthorityRevocationSnapshotV1,
        now: u64,
    ) -> Result<(), ReceiptProofError> {
        verify_receipt_proof_bundle_v1(
            bundle,
            &ReceiptProofVerificationContext {
                now,
                max_snapshot_staleness_seconds: 300,
                key_set,
                revocation_snapshot: snapshot,
            },
        )
    }

    fn assert_code(result: Result<(), ReceiptProofError>, code: ReceiptProofErrorCode) {
        assert_eq!(result.expect_err("proof must fail closed").code, code);
    }

    #[test]
    fn golden_receipt_inclusion_and_checkpoint_consistency_verify_offline() {
        let bundle = parse(BUNDLE);
        let keys = parse(KEY_SET);
        let snapshot = parse(SNAPSHOT);
        verify(&bundle, &keys, &snapshot, NOW).expect("golden proof verifies");
    }

    #[test]
    fn receipt_type_domain_version_leaf_and_inclusion_tampering_fail_closed() {
        let bundle: ReceiptProofBundleV1 = parse(BUNDLE);
        let keys = parse(KEY_SET);
        let snapshot = parse(SNAPSHOT);

        let mut receipt = bundle.clone();
        receipt.receipt["receipt_type"] = json!("foreign_receipt");
        assert_code(
            verify(&receipt, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::ReceiptBodyHash,
        );

        let mut version = bundle.clone();
        version.schema_version = json!("ioi.foundations.receipt-proof-bundle.v2");
        assert_code(
            verify(&version, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::Structural,
        );

        let mut domain = bundle.clone();
        domain.leaf.domain = json!("ioi.foreign-leaf.v1");
        assert_code(
            verify(&domain, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::Structural,
        );

        let mut leaf = bundle.clone();
        leaf.leaf.leaf_hash = format!("sha256:{}", "a".repeat(64));
        assert_code(
            verify(&leaf, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::LeafHash,
        );

        let mut index = bundle.clone();
        index.leaf.leaf_index = 0;
        index.inclusion_proof.leaf_index = 0;
        assert_code(
            verify(&index, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::LeafHash,
        );

        let mut inclusion = bundle.clone();
        inclusion.inclusion_proof.prefix_root = format!("sha256:{}", "b".repeat(64));
        assert_code(
            verify(&inclusion, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::Inclusion,
        );

        let mut missing = serde_json::to_value(&bundle).expect("serialize bundle");
        missing
            .as_object_mut()
            .expect("bundle object")
            .remove("inclusion_proof");
        assert!(serde_json::from_value::<ReceiptProofBundleV1>(missing).is_err());
    }

    #[test]
    fn checkpoint_chain_manifest_and_signature_tampering_fail_closed() {
        let bundle: ReceiptProofBundleV1 = parse(BUNDLE);
        let keys = parse(KEY_SET);
        let snapshot = parse(SNAPSHOT);

        let mut consistency = bundle.clone();
        consistency.consistency_proof.extension_leaf_hashes[0] =
            format!("sha256:{}", "c".repeat(64));
        assert_code(
            verify(&consistency, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::Consistency,
        );

        let mut split_view = bundle.clone();
        split_view.consistency_proof.from_root = format!("sha256:{}", "d".repeat(64));
        assert_code(
            verify(&split_view, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::Consistency,
        );

        let mut signature = bundle.clone();
        signature.checkpoint["signature"] = json!("A".repeat(86));
        assert_code(
            verify(&signature, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::Signature,
        );

        let mut manifest = bundle.clone();
        manifest.verification_instructions.steps[0] = "Trust without verification.".to_string();
        assert_code(
            verify(&manifest, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::ManifestHash,
        );

        let mut manifest_signature = bundle.clone();
        manifest_signature.manifest_signature = "A".repeat(86);
        assert_code(
            verify(&manifest_signature, &keys, &snapshot, NOW),
            ReceiptProofErrorCode::Signature,
        );
    }

    #[test]
    fn unknown_revoked_stale_and_wrong_signers_fail_closed() {
        let bundle: ReceiptProofBundleV1 = parse(BUNDLE);
        let keys: AuthorityKeySetV1 = parse(KEY_SET);
        let snapshot: AuthorityRevocationSnapshotV1 = parse(SNAPSHOT);
        let revoked: AuthorityRevocationSnapshotV1 = parse(REVOKED_SNAPSHOT);
        let delegator: AuthorityKeySetV1 = parse(DELEGATOR_KEYS);

        let mut unknown = keys.clone();
        unknown.keys[0].key_id = "key://acme/security/unknown".to_string();
        assert_code(
            verify(&bundle, &unknown, &snapshot, NOW),
            ReceiptProofErrorCode::KeyUnknown,
        );
        assert_code(
            verify(&bundle, &keys, &revoked, NOW),
            ReceiptProofErrorCode::KeyRevoked,
        );
        assert_code(
            verify(&bundle, &keys, &snapshot, snapshot.expires_at + 1),
            ReceiptProofErrorCode::SnapshotStale,
        );
        let mut stale_key = keys.clone();
        stale_key.keys[0].expires_at = 1_784_203_200;
        assert_code(
            verify(&bundle, &stale_key, &snapshot, NOW),
            ReceiptProofErrorCode::KeyStale,
        );
        assert_code(
            verify(&bundle, &delegator, &snapshot, NOW),
            ReceiptProofErrorCode::KeySet,
        );
    }
}
