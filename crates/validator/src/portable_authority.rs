//! Portable AuthorityGrantEnvelope v2 signing and offline verification.
//!
//! The verifier consumes an already trusted, locally resolved issuer key set. Network
//! discovery and trust-root acquisition intentionally remain outside this module; once
//! resolved, key rotation, grant time, holder/audience, delegation attenuation, and a
//! bounded-freshness revocation snapshot are enforced fail closed.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::generated::architecture_contracts::{
    architecture_contract_schema_hash, validate_architecture_contract, AuthorityGrantEnvelopeV2,
    AuthorityKeySetV1, AuthorityRevocationSnapshotV1,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use thiserror::Error;

/// Registry identifier for the portable AuthorityGrantEnvelope successor.
pub const AUTHORITY_GRANT_V2_CONTRACT_ID: &str =
    "schema://ioi/foundations/authority-grant-envelope/v2";
/// Registry identifier for issuer key-set discovery/rotation inputs.
pub const AUTHORITY_KEY_SET_V1_CONTRACT_ID: &str = "schema://ioi/foundations/authority-key-set/v1";
/// Registry identifier for bounded-freshness revocation inputs.
pub const AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID: &str =
    "schema://ioi/foundations/authority-revocation-snapshot/v1";
/// Unambiguous prefix applied before the JCS grant signing material.
pub const AUTHORITY_GRANT_V2_SIGNING_PREFIX: &[u8] = b"IOI-AUTHORITY-GRANT-ENVELOPE-V2\0";
/// Unambiguous prefix applied before the JCS revocation-snapshot signing material.
pub const AUTHORITY_REVOCATION_V1_SIGNING_PREFIX: &[u8] = b"IOI-AUTHORITY-REVOCATION-SNAPSHOT-V1\0";

/// Stable fail-closed classifications exposed by the portable verifier and CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableAuthorityErrorCode {
    /// JSON does not satisfy its registered closed schema or invariant profile.
    Structural,
    /// The grant does not bind the generated schema hash.
    SchemaHash,
    /// The JCS body hash is wrong.
    BodyHash,
    /// An Ed25519 signature is invalid.
    Signature,
    /// The signing domain is wrong.
    SignatureDomain,
    /// A signing key is absent, mismatched, invalid, or revoked.
    SignatureKey,
    /// The supplied trusted key set is stale or does not bind the issuer.
    KeySet,
    /// A key is explicitly revoked by a current snapshot.
    KeyRevoked,
    /// The verifier audience does not match.
    Audience,
    /// The verifier holder identity/key does not match.
    Holder,
    /// The grant or key is not active at the verification time.
    Time,
    /// The grant is explicitly revoked.
    Revocation,
    /// The revocation snapshot exceeds its declared or policy staleness bound.
    RevocationSnapshotStale,
    /// A delegated grant lacks its parent proof.
    ParentRequired,
    /// The declared parent reference/hash does not bind the supplied parent.
    ParentLink,
    /// A delegated child widens authority relative to its parent.
    ParentAttenuation,
    /// The parent proof chain contains a cycle.
    ParentCycle,
}

impl PortableAuthorityErrorCode {
    /// Machine-readable lowercase verifier code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::SchemaHash => "schema_hash",
            Self::BodyHash => "body_hash",
            Self::Signature => "signature",
            Self::SignatureDomain => "signature_domain",
            Self::SignatureKey => "signature_key",
            Self::KeySet => "key_set",
            Self::KeyRevoked => "key_revoked",
            Self::Audience => "audience",
            Self::Holder => "holder",
            Self::Time => "time",
            Self::Revocation => "revocation",
            Self::RevocationSnapshotStale => "revocation_snapshot_stale",
            Self::ParentRequired => "parent_required",
            Self::ParentLink => "parent_link",
            Self::ParentAttenuation => "parent_attenuation",
            Self::ParentCycle => "parent_cycle",
        }
    }
}

/// Detailed portable-authority verification failure.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{code}: {detail}", code = .code.as_str())]
pub struct PortableAuthorityError {
    /// Stable error classification.
    pub code: PortableAuthorityErrorCode,
    /// Human-readable failure detail.
    pub detail: String,
}

impl PortableAuthorityError {
    fn new(code: PortableAuthorityErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// One recursively verifiable parent delegation proof.
pub struct PortableAuthorityParentProof<'a> {
    /// Parent grant artifact.
    pub grant: &'a AuthorityGrantEnvelopeV2,
    /// Trusted key set used to verify the parent issuer.
    pub key_set: &'a AuthorityKeySetV1,
    /// Fresh revocation snapshot used to verify the parent.
    pub revocation_snapshot: &'a AuthorityRevocationSnapshotV1,
    /// Optional next parent in the delegation chain.
    pub parent: Option<&'a PortableAuthorityParentProof<'a>>,
}

/// Context that turns a portable artifact into a verification decision.
pub struct PortableAuthorityVerificationContext<'a> {
    /// Exact audience expected by the consuming boundary.
    pub expected_audience: &'a str,
    /// Exact holder identity expected by the consuming boundary.
    pub expected_holder_id: &'a str,
    /// Exact holder key expected by the consuming boundary.
    pub expected_holder_key_id: &'a str,
    /// Current Unix time in seconds supplied by the trusted caller.
    pub now: u64,
    /// Maximum accepted age of a revocation snapshot in seconds.
    pub max_snapshot_staleness_seconds: u64,
    /// Trusted locally resolved issuer key set.
    pub key_set: &'a AuthorityKeySetV1,
    /// Signed revocation snapshot for the issuer.
    pub revocation_snapshot: &'a AuthorityRevocationSnapshotV1,
    /// Parent proof required for a delegated child.
    pub parent: Option<&'a PortableAuthorityParentProof<'a>>,
}

fn structural<T: Serialize>(contract_id: &str, value: &T) -> Result<(), PortableAuthorityError> {
    let value = serde_json::to_value(value).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::Structural, error.to_string())
    })?;
    validate_architecture_contract(contract_id, &value).map_err(|detail| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::Structural, detail)
    })
}

fn sha256_jcs<T: Serialize>(value: &T) -> Result<String, PortableAuthorityError> {
    let canonical = serde_jcs::to_vec(value).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::BodyHash, error.to_string())
    })?;
    let digest = Sha256::digest(&canonical).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::BodyHash, error.to_string())
    })?;
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn unsigned_value<T: Serialize>(
    value: &T,
    fields: &[&str],
) -> Result<Value, PortableAuthorityError> {
    let mut value = serde_json::to_value(value).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::Structural, error.to_string())
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        PortableAuthorityError::new(
            PortableAuthorityErrorCode::Structural,
            "portable authority artifact must be a JSON object",
        )
    })?;
    for field in fields {
        object.remove(*field);
    }
    Ok(value)
}

fn grant_body_hash(grant: &AuthorityGrantEnvelopeV2) -> Result<String, PortableAuthorityError> {
    sha256_jcs(&unsigned_value(
        grant,
        &[
            "body_hash",
            "signature_suite",
            "signature_key_id",
            "signature",
        ],
    )?)
}

fn snapshot_body_hash(
    snapshot: &AuthorityRevocationSnapshotV1,
) -> Result<String, PortableAuthorityError> {
    sha256_jcs(&unsigned_value(
        snapshot,
        &[
            "body_hash",
            "signature_suite",
            "signature_key_id",
            "signature",
        ],
    )?)
}

/// Produces the exact domain-separated JCS bytes signed by AuthorityGrantEnvelope v2.
pub fn authority_grant_v2_signing_bytes(
    grant: &AuthorityGrantEnvelopeV2,
) -> Result<Vec<u8>, PortableAuthorityError> {
    let material = json!({
        "body_hash": grant.body_hash,
        "schema_hash": grant.schema_hash,
        "signature_domain": grant.signature_domain,
    });
    let mut bytes = AUTHORITY_GRANT_V2_SIGNING_PREFIX.to_vec();
    bytes.extend(serde_jcs::to_vec(&material).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::Signature, error.to_string())
    })?);
    Ok(bytes)
}

/// Produces the exact domain-separated JCS bytes signed by a revocation snapshot.
pub fn authority_revocation_v1_signing_bytes(
    snapshot: &AuthorityRevocationSnapshotV1,
) -> Result<Vec<u8>, PortableAuthorityError> {
    let material = json!({
        "body_hash": snapshot.body_hash,
        "signature_domain": snapshot.signature_domain,
    });
    let mut bytes = AUTHORITY_REVOCATION_V1_SIGNING_PREFIX.to_vec();
    bytes.extend(serde_jcs::to_vec(&material).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::Signature, error.to_string())
    })?);
    Ok(bytes)
}

fn verify_ed25519(
    public_key: &str,
    signature: &str,
    message: &[u8],
) -> Result<(), PortableAuthorityError> {
    let public_key = URL_SAFE_NO_PAD.decode(public_key).map_err(|_| {
        PortableAuthorityError::new(
            PortableAuthorityErrorCode::SignatureKey,
            "public key is not unpadded base64url",
        )
    })?;
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| {
        PortableAuthorityError::new(
            PortableAuthorityErrorCode::Signature,
            "signature is not unpadded base64url",
        )
    })?;
    let public_key = Ed25519PublicKey::from_bytes(&public_key).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::SignatureKey, error.to_string())
    })?;
    let signature = Ed25519Signature::from_bytes(&signature).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::Signature, error.to_string())
    })?;
    public_key.verify(message, &signature).map_err(|error| {
        PortableAuthorityError::new(PortableAuthorityErrorCode::Signature, error.to_string())
    })
}

fn key_material(
    key_set: &AuthorityKeySetV1,
    key_id: &str,
    at: u64,
) -> Result<String, PortableAuthorityError> {
    let key = key_set
        .keys
        .iter()
        .find(|candidate| candidate.key_id == key_id)
        .ok_or_else(|| {
            PortableAuthorityError::new(
                PortableAuthorityErrorCode::SignatureKey,
                "signing key is absent from the trusted key set",
            )
        })?;
    if key.signature_suite != "ed25519" || key.status == "revoked" {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::SignatureKey,
            "signing key suite/status is not accepted",
        ));
    }
    if at < key.not_before || at > key.expires_at {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::Time,
            "signing key was not valid when the artifact was issued",
        ));
    }
    Ok(key.public_key.clone())
}

fn verify_snapshot(
    snapshot: &AuthorityRevocationSnapshotV1,
    key_set: &AuthorityKeySetV1,
    now: u64,
    max_staleness: u64,
) -> Result<(), PortableAuthorityError> {
    structural(AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT_ID, snapshot)?;
    if snapshot.signature_domain != "ioi.authority-revocation-snapshot.v1" {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::SignatureDomain,
            "unexpected revocation-snapshot signing domain",
        ));
    }
    if snapshot.issuer_id != key_set.issuer_id
        || snapshot.issuer_key_set_ref != key_set.key_set_id
        || snapshot.issuer_key_set_version > key_set.version
    {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::KeySet,
            "revocation snapshot does not bind the trusted key set",
        ));
    }
    if snapshot.issued_at > now
        || snapshot.expires_at < now
        || now.saturating_sub(snapshot.issued_at) > max_staleness
    {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::RevocationSnapshotStale,
            "revocation snapshot exceeds its freshness bound",
        ));
    }
    if snapshot_body_hash(snapshot)? != snapshot.body_hash {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::BodyHash,
            "revocation snapshot body hash mismatch",
        ));
    }
    let public_key = key_material(key_set, &snapshot.signature_key_id, snapshot.issued_at)?;
    verify_ed25519(
        &public_key,
        &snapshot.signature,
        &authority_revocation_v1_signing_bytes(snapshot)?,
    )
}

fn is_subset(child: &[String], parent: &[String]) -> bool {
    let parent: HashSet<&str> = parent.iter().map(String::as_str).collect();
    child.iter().all(|value| parent.contains(value.as_str()))
}

fn is_superset(child: &[String], parent: &[String]) -> bool {
    is_subset(parent, child)
}

fn verify_attenuation(
    child: &AuthorityGrantEnvelopeV2,
    parent: &AuthorityGrantEnvelopeV2,
) -> Result<(), PortableAuthorityError> {
    let violation =
        if child.issuer_id != parent.holder_id || child.issuer_key_id != parent.holder_key_id {
            Some("child issuer must be the parent holder")
        } else if !is_subset(&child.authority_scopes, &parent.authority_scopes) {
            Some("child widens authority scopes")
        } else if !is_subset(
            &child.primitive_capability_constraints,
            &parent.primitive_capability_constraints,
        ) {
            Some("child widens primitive capabilities")
        } else if !is_subset(&child.resources, &parent.resources) {
            Some("child widens resources")
        } else if !is_subset(
            &child.risk_restrictions.allowed_risk_classes,
            &parent.risk_restrictions.allowed_risk_classes,
        ) {
            Some("child widens risk classes")
        } else if !is_superset(&child.attenuating_caveats, &parent.attenuating_caveats) {
            Some("child drops an attenuating caveat")
        } else if !is_superset(
            &child.risk_restrictions.approval_required_for,
            &parent.risk_restrictions.approval_required_for,
        ) {
            Some("child drops an approval requirement")
        } else if child.risk_restrictions.max_budget_microusd
            > parent.risk_restrictions.max_budget_microusd
        {
            Some("child widens budget")
        } else if child.risk_restrictions.max_calls > parent.risk_restrictions.max_calls {
            Some("child widens calls")
        } else if child.not_before < parent.not_before || child.expires_at > parent.expires_at {
            Some("child widens validity interval")
        } else if child.revocation_epoch < parent.revocation_epoch {
            Some("child uses an older revocation epoch")
        } else {
            None
        };
    violation.map_or(Ok(()), |detail| {
        Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::ParentAttenuation,
            detail,
        ))
    })
}

fn verify_inner(
    grant: &AuthorityGrantEnvelopeV2,
    context: &PortableAuthorityVerificationContext<'_>,
    seen: &mut HashSet<String>,
) -> Result<(), PortableAuthorityError> {
    if !seen.insert(grant.authority_grant_id.clone()) {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::ParentCycle,
            "grant delegation cycle detected",
        ));
    }
    structural(AUTHORITY_GRANT_V2_CONTRACT_ID, grant)?;
    structural(AUTHORITY_KEY_SET_V1_CONTRACT_ID, context.key_set)?;
    if grant.signature_domain != "ioi.authority-grant-envelope.v2" {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::SignatureDomain,
            "unexpected authority-grant signing domain",
        ));
    }
    let expected_schema_hash = architecture_contract_schema_hash(AUTHORITY_GRANT_V2_CONTRACT_ID)
        .ok_or_else(|| {
            PortableAuthorityError::new(
                PortableAuthorityErrorCode::SchemaHash,
                "registered v2 schema hash is unavailable",
            )
        })?;
    if grant.schema_hash != expected_schema_hash {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::SchemaHash,
            "authority-grant schema hash mismatch",
        ));
    }
    if grant_body_hash(grant)? != grant.body_hash {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::BodyHash,
            "authority-grant body hash mismatch",
        ));
    }
    if grant.signature_key_id != grant.issuer_key_id {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::SignatureKey,
            "signature key must equal issuer key",
        ));
    }
    if grant.audience != context.expected_audience {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::Audience,
            "grant audience mismatch",
        ));
    }
    if grant.holder_id != context.expected_holder_id
        || grant.holder_key_id != context.expected_holder_key_id
    {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::Holder,
            "grant holder binding mismatch",
        ));
    }
    if grant.issued_at > grant.not_before
        || grant.not_before >= grant.expires_at
        || context.now < grant.not_before
        || context.now > grant.expires_at
    {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::Time,
            "grant is not active at verification time",
        ));
    }
    if context.key_set.key_set_type != "ioi.authority-key-set"
        || context.key_set.issuer_id != grant.issuer_id
        || context.key_set.key_set_id != grant.issuer_key_set_ref
        || context.key_set.version < grant.issuer_key_set_version
        || context.key_set.issued_at > context.now
        || context.key_set.expires_at < context.now
    {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::KeySet,
            "issuer key set is missing, stale, or mismatched",
        ));
    }
    let public_key = key_material(context.key_set, &grant.signature_key_id, grant.issued_at)?;
    verify_snapshot(
        context.revocation_snapshot,
        context.key_set,
        context.now,
        context.max_snapshot_staleness_seconds,
    )?;
    if context.revocation_snapshot.epoch < grant.revocation_epoch {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::RevocationSnapshotStale,
            "revocation snapshot predates the grant epoch",
        ));
    }
    if context
        .revocation_snapshot
        .revoked_grant_refs
        .contains(&grant.authority_grant_id)
    {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::Revocation,
            "grant is revoked",
        ));
    }
    if context
        .revocation_snapshot
        .revoked_key_ids
        .contains(&grant.signature_key_id)
    {
        return Err(PortableAuthorityError::new(
            PortableAuthorityErrorCode::KeyRevoked,
            "grant signing key is revoked",
        ));
    }
    verify_ed25519(
        &public_key,
        &grant.signature,
        &authority_grant_v2_signing_bytes(grant)?,
    )?;

    match (&grant.parent_grant, context.parent) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(PortableAuthorityError::new(
                PortableAuthorityErrorCode::ParentLink,
                "root grant supplied an unexpected parent proof",
            ));
        }
        (Some(_), None) => {
            return Err(PortableAuthorityError::new(
                PortableAuthorityErrorCode::ParentRequired,
                "delegated grant requires its parent proof",
            ));
        }
        (Some(parent_link), Some(parent)) => {
            let parent_context = PortableAuthorityVerificationContext {
                expected_audience: &grant.audience,
                expected_holder_id: &grant.issuer_id,
                expected_holder_key_id: &grant.issuer_key_id,
                now: context.now,
                max_snapshot_staleness_seconds: context.max_snapshot_staleness_seconds,
                key_set: parent.key_set,
                revocation_snapshot: parent.revocation_snapshot,
                parent: parent.parent,
            };
            verify_inner(parent.grant, &parent_context, seen)?;
            if parent_link.grant_ref != parent.grant.authority_grant_id
                || parent_link.body_hash != parent.grant.body_hash
            {
                return Err(PortableAuthorityError::new(
                    PortableAuthorityErrorCode::ParentLink,
                    "parent reference/body hash does not bind the supplied parent",
                ));
            }
            verify_attenuation(grant, parent.grant)?;
        }
    }
    Ok(())
}

/// Verifies structure, JCS hashes, signatures, key rotation, time, revocation, and attenuation.
pub fn verify_portable_authority_grant_v2(
    grant: &AuthorityGrantEnvelopeV2,
    context: &PortableAuthorityVerificationContext<'_>,
) -> Result<(), PortableAuthorityError> {
    verify_inner(grant, context, &mut HashSet::new())
}

/// Completes and signs a v2 grant with the existing Ed25519 implementation.
pub fn sign_portable_authority_grant_v2(
    grant: &mut AuthorityGrantEnvelopeV2,
    keypair: &Ed25519KeyPair,
) -> Result<(), PortableAuthorityError> {
    grant.schema_hash = architecture_contract_schema_hash(AUTHORITY_GRANT_V2_CONTRACT_ID)
        .ok_or_else(|| {
            PortableAuthorityError::new(
                PortableAuthorityErrorCode::SchemaHash,
                "registered v2 schema hash is unavailable",
            )
        })?
        .to_string();
    grant.signature_suite = json!("ed25519");
    grant.signature_key_id.clone_from(&grant.issuer_key_id);
    grant.signature.clear();
    grant.body_hash = grant_body_hash(grant)?;
    grant.signature = URL_SAFE_NO_PAD.encode(
        keypair
            .sign(&authority_grant_v2_signing_bytes(grant)?)
            .map_err(|error| {
                PortableAuthorityError::new(
                    PortableAuthorityErrorCode::Signature,
                    error.to_string(),
                )
            })?
            .to_bytes(),
    );
    Ok(())
}

/// Completes and signs a revocation snapshot with the existing Ed25519 implementation.
pub fn sign_authority_revocation_snapshot_v1(
    snapshot: &mut AuthorityRevocationSnapshotV1,
    keypair: &Ed25519KeyPair,
) -> Result<(), PortableAuthorityError> {
    snapshot.signature_suite = json!("ed25519");
    snapshot.signature.clear();
    snapshot.body_hash = snapshot_body_hash(snapshot)?;
    snapshot.signature = URL_SAFE_NO_PAD.encode(
        keypair
            .sign(&authority_revocation_v1_signing_bytes(snapshot)?)
            .map_err(|error| {
                PortableAuthorityError::new(
                    PortableAuthorityErrorCode::Signature,
                    error.to_string(),
                )
            })?
            .to_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    const ROOT_GRANT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/positive-root.json"
    ));
    const CHILD_GRANT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v2/positive-attenuated-child.json"
    ));
    const WIDENED_CHILD: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/portable-authority/adversarial-widened-child.json"
    ));
    const ISSUER_KEYS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-active.json"
    ));
    const DELEGATOR_KEYS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-delegator.json"
    ));
    const ISSUER_SNAPSHOT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-revocation-snapshot-v1/positive-current.json"
    ));
    const DELEGATOR_SNAPSHOT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/architecture/_meta/schemas/fixtures/authority-revocation-snapshot-v1/positive-delegator-current.json"
    ));
    const REVOKED_ROOT_SNAPSHOT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/portable-authority/adversarial-revoked-root.json"
    ));
    const NOW: u64 = 1_784_203_300;

    fn parse<T: DeserializeOwned>(value: &str) -> T {
        serde_json::from_str(value).expect("golden fixture parses")
    }

    fn verify_root(
        grant: &AuthorityGrantEnvelopeV2,
        key_set: &AuthorityKeySetV1,
        snapshot: &AuthorityRevocationSnapshotV1,
        now: u64,
        audience: &str,
        holder_id: &str,
        holder_key_id: &str,
    ) -> Result<(), PortableAuthorityError> {
        verify_portable_authority_grant_v2(
            grant,
            &PortableAuthorityVerificationContext {
                expected_audience: audience,
                expected_holder_id: holder_id,
                expected_holder_key_id: holder_key_id,
                now,
                max_snapshot_staleness_seconds: 300,
                key_set,
                revocation_snapshot: snapshot,
                parent: None,
            },
        )
    }

    fn verify_child(
        grant: &AuthorityGrantEnvelopeV2,
        parent_grant: &AuthorityGrantEnvelopeV2,
        issuer_keys: &AuthorityKeySetV1,
        issuer_snapshot: &AuthorityRevocationSnapshotV1,
        delegator_keys: &AuthorityKeySetV1,
        delegator_snapshot: &AuthorityRevocationSnapshotV1,
    ) -> Result<(), PortableAuthorityError> {
        let parent = PortableAuthorityParentProof {
            grant: parent_grant,
            key_set: issuer_keys,
            revocation_snapshot: issuer_snapshot,
            parent: None,
        };
        verify_portable_authority_grant_v2(
            grant,
            &PortableAuthorityVerificationContext {
                expected_audience: &grant.audience,
                expected_holder_id: &grant.holder_id,
                expected_holder_key_id: &grant.holder_key_id,
                now: NOW,
                max_snapshot_staleness_seconds: 300,
                key_set: delegator_keys,
                revocation_snapshot: delegator_snapshot,
                parent: Some(&parent),
            },
        )
    }

    fn assert_code(result: Result<(), PortableAuthorityError>, code: PortableAuthorityErrorCode) {
        assert_eq!(result.expect_err("verification must fail").code, code);
    }

    #[test]
    fn golden_root_and_attenuated_child_verify_offline() {
        let root: AuthorityGrantEnvelopeV2 = parse(ROOT_GRANT);
        let child: AuthorityGrantEnvelopeV2 = parse(CHILD_GRANT);
        let issuer_keys: AuthorityKeySetV1 = parse(ISSUER_KEYS);
        let delegator_keys: AuthorityKeySetV1 = parse(DELEGATOR_KEYS);
        let issuer_snapshot: AuthorityRevocationSnapshotV1 = parse(ISSUER_SNAPSHOT);
        let delegator_snapshot: AuthorityRevocationSnapshotV1 = parse(DELEGATOR_SNAPSHOT);

        verify_root(
            &root,
            &issuer_keys,
            &issuer_snapshot,
            NOW,
            &root.audience,
            &root.holder_id,
            &root.holder_key_id,
        )
        .expect("golden root verifies");
        verify_child(
            &child,
            &root,
            &issuer_keys,
            &issuer_snapshot,
            &delegator_keys,
            &delegator_snapshot,
        )
        .expect("golden child verifies with its parent proof");
    }

    #[test]
    fn payload_type_domain_and_version_mutations_fail_closed() {
        let root: AuthorityGrantEnvelopeV2 = parse(ROOT_GRANT);
        let issuer_keys: AuthorityKeySetV1 = parse(ISSUER_KEYS);
        let issuer_snapshot: AuthorityRevocationSnapshotV1 = parse(ISSUER_SNAPSHOT);
        let verify = |grant: &AuthorityGrantEnvelopeV2| {
            verify_root(
                grant,
                &issuer_keys,
                &issuer_snapshot,
                NOW,
                &root.audience,
                &root.holder_id,
                &root.holder_key_id,
            )
        };

        let mut payload = root.clone();
        payload.resources[0] = "agentgres://project/foreign/source".to_string();
        assert_code(verify(&payload), PortableAuthorityErrorCode::BodyHash);

        let mut envelope_type = root.clone();
        envelope_type.envelope_type = json!("ioi.receipt");
        assert_code(
            verify(&envelope_type),
            PortableAuthorityErrorCode::Structural,
        );

        let mut domain = root.clone();
        domain.signature_domain = json!("ioi.authority-revocation-snapshot.v1");
        assert_code(verify(&domain), PortableAuthorityErrorCode::Structural);

        let mut version = root.clone();
        version.schema_version = json!("ioi.foundations.authority-grant-envelope.v1");
        assert_code(verify(&version), PortableAuthorityErrorCode::Structural);
    }

    #[test]
    fn audience_holder_key_and_time_bindings_fail_closed() {
        let root: AuthorityGrantEnvelopeV2 = parse(ROOT_GRANT);
        let issuer_keys: AuthorityKeySetV1 = parse(ISSUER_KEYS);
        let issuer_snapshot: AuthorityRevocationSnapshotV1 = parse(ISSUER_SNAPSHOT);

        assert_code(
            verify_root(
                &root,
                &issuer_keys,
                &issuer_snapshot,
                NOW,
                "runtime://acme/foreign/node-1",
                &root.holder_id,
                &root.holder_key_id,
            ),
            PortableAuthorityErrorCode::Audience,
        );
        assert_code(
            verify_root(
                &root,
                &issuer_keys,
                &issuer_snapshot,
                NOW,
                &root.audience,
                "system://acme/foreign",
                &root.holder_key_id,
            ),
            PortableAuthorityErrorCode::Holder,
        );
        assert_code(
            verify_root(
                &root,
                &issuer_keys,
                &issuer_snapshot,
                NOW,
                &root.audience,
                &root.holder_id,
                "key://acme/delegator/foreign",
            ),
            PortableAuthorityErrorCode::Holder,
        );

        let mut missing_key = issuer_keys.clone();
        missing_key.keys[0].key_id = "key://acme/security/missing".to_string();
        assert_code(
            verify_root(
                &root,
                &missing_key,
                &issuer_snapshot,
                NOW,
                &root.audience,
                &root.holder_id,
                &root.holder_key_id,
            ),
            PortableAuthorityErrorCode::SignatureKey,
        );
        assert_code(
            verify_root(
                &root,
                &issuer_keys,
                &issuer_snapshot,
                root.not_before - 1,
                &root.audience,
                &root.holder_id,
                &root.holder_key_id,
            ),
            PortableAuthorityErrorCode::Time,
        );
        assert_code(
            verify_root(
                &root,
                &issuer_keys,
                &issuer_snapshot,
                root.expires_at + 1,
                &root.audience,
                &root.holder_id,
                &root.holder_key_id,
            ),
            PortableAuthorityErrorCode::Time,
        );
    }

    #[test]
    fn revocation_freshness_and_child_widening_fail_closed() {
        let root: AuthorityGrantEnvelopeV2 = parse(ROOT_GRANT);
        let widened: AuthorityGrantEnvelopeV2 = parse(WIDENED_CHILD);
        let issuer_keys: AuthorityKeySetV1 = parse(ISSUER_KEYS);
        let delegator_keys: AuthorityKeySetV1 = parse(DELEGATOR_KEYS);
        let issuer_snapshot: AuthorityRevocationSnapshotV1 = parse(ISSUER_SNAPSHOT);
        let delegator_snapshot: AuthorityRevocationSnapshotV1 = parse(DELEGATOR_SNAPSHOT);
        let revoked: AuthorityRevocationSnapshotV1 = parse(REVOKED_ROOT_SNAPSHOT);

        assert_code(
            verify_root(
                &root,
                &issuer_keys,
                &revoked,
                NOW,
                &root.audience,
                &root.holder_id,
                &root.holder_key_id,
            ),
            PortableAuthorityErrorCode::Revocation,
        );
        assert_code(
            verify_root(
                &root,
                &issuer_keys,
                &issuer_snapshot,
                issuer_snapshot.expires_at + 1,
                &root.audience,
                &root.holder_id,
                &root.holder_key_id,
            ),
            PortableAuthorityErrorCode::RevocationSnapshotStale,
        );
        assert_code(
            verify_child(
                &widened,
                &root,
                &issuer_keys,
                &issuer_snapshot,
                &delegator_keys,
                &delegator_snapshot,
            ),
            PortableAuthorityErrorCode::ParentAttenuation,
        );
    }
}
