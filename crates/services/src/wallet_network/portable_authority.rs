//! Offline verification for registered portable authority-grant v3 chains.
//!
//! The verifier deliberately consumes raw JSON values. Generated architecture projections are
//! safe parsing aids, but serializing a constructed projection does not rerun the registered
//! cross-field invariants. Hashes and signatures therefore bind the exact closed value that was
//! validated, never a reconstructed struct.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::generated::architecture_contracts::{
    architecture_contract_schema_hash, validate_architecture_contract,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const AUTHORITY_GRANT_V3_CONTRACT: &str =
    "schema://ioi/foundations/authority-grant-envelope/v3";
pub const AUTHORITY_KEY_SET_V1_CONTRACT: &str = "schema://ioi/foundations/authority-key-set/v1";
pub const AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT: &str =
    "schema://ioi/foundations/authority-revocation-snapshot/v1";
pub const AUTHORITY_EFFECT_ADMISSION_RECEIPT_V2_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/authority-effect-admission-receipt/v2";

const GRANT_V3_DOMAIN: &[u8] = b"IOI-AUTHORITY-GRANT-ENVELOPE-V3\0";
const REVOCATION_SNAPSHOT_V1_DOMAIN: &[u8] = b"IOI-AUTHORITY-REVOCATION-SNAPSHOT-V1\0";
const EFFECT_ADMISSION_BODY_V2_DOMAIN: &[u8] = b"IOI-AUTHORITY-EFFECT-ADMISSION-BODY-V2\0";
const EFFECT_ADMISSION_RECEIPT_V2_DOMAIN: &[u8] = b"IOI-AUTHORITY-EFFECT-ADMISSION-RECEIPT-V2\0";

/// Stable machine refusal names required by the portable-authority negative corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableAuthorityRefusalCode {
    MalformedGrant,
    MalformedKeySet,
    MalformedRevocationSnapshot,
    SchemaMismatch,
    BodyHashMismatch,
    SignatureMismatch,
    UntrustedIssuer,
    InactiveKey,
    StaleKeySet,
    MissingRevocationSnapshot,
    InvalidRevocationSnapshot,
    StaleRevocationSnapshot,
    StaleAncestorState,
    RevokedGrant,
    RevokedKey,
    WrongAudience,
    WrongHolder,
    MissingParentProof,
    ParentLinkMismatch,
    WrongIssuer,
    WidenedChild,
    DelegationCycle,
    Replay,
    DelegationClosureMissing,
    RedelegationForbidden,
    DepthExhausted,
    BudgetExhausted,
    CallsExhausted,
    EffectMismatch,
    ProofMismatch,
    AdmissionReceiptInvalid,
}

impl PortableAuthorityRefusalCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedGrant => "malformed_grant",
            Self::MalformedKeySet => "malformed_key_set",
            Self::MalformedRevocationSnapshot => "malformed_revocation_snapshot",
            Self::SchemaMismatch => "schema_mismatch",
            Self::BodyHashMismatch => "body_hash_mismatch",
            Self::SignatureMismatch => "signature_mismatch",
            Self::UntrustedIssuer => "untrusted_issuer",
            Self::InactiveKey => "inactive_key",
            Self::StaleKeySet => "stale_key_set",
            Self::MissingRevocationSnapshot => "missing_revocation_snapshot",
            Self::InvalidRevocationSnapshot => "invalid_revocation_snapshot",
            Self::StaleRevocationSnapshot => "stale_revocation_snapshot",
            Self::StaleAncestorState => "stale_ancestor_state",
            Self::RevokedGrant => "revoked_grant",
            Self::RevokedKey => "revoked_key",
            Self::WrongAudience => "wrong_audience",
            Self::WrongHolder => "wrong_holder",
            Self::MissingParentProof => "missing_parent_proof",
            Self::ParentLinkMismatch => "parent_link_mismatch",
            Self::WrongIssuer => "wrong_issuer",
            Self::WidenedChild => "widened_child",
            Self::DelegationCycle => "delegation_cycle",
            Self::Replay => "replay",
            Self::DelegationClosureMissing => "delegation_closure_missing",
            Self::RedelegationForbidden => "redelegation_forbidden",
            Self::DepthExhausted => "depth_exhausted",
            Self::BudgetExhausted => "budget_exhausted",
            Self::CallsExhausted => "calls_exhausted",
            Self::EffectMismatch => "effect_mismatch",
            Self::ProofMismatch => "proof_mismatch",
            Self::AdmissionReceiptInvalid => "admission_receipt_invalid",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{code}: {message}", code = .code.as_str())]
pub struct PortableAuthorityRefusal {
    pub code: PortableAuthorityRefusalCode,
    pub message: String,
}

fn refuse(
    code: PortableAuthorityRefusalCode,
    message: impl Into<String>,
) -> PortableAuthorityRefusal {
    PortableAuthorityRefusal {
        code,
        message: message.into(),
    }
}

/// One entry in a complete, locally trusted descendant-allocation closure.
///
/// This is an admission input, not a wire grant. Callers must construct it only from their
/// admitted owner-scoped allocation ledger. Treating request-carried entries as trusted would
/// let a caller hide siblings and manufacture budget.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableAuthorityDescendantAllocation {
    pub grant_ref: String,
    pub body_hash: String,
    pub max_budget_microusd: u64,
    pub max_calls: u64,
}

/// Closed-world delegation facts supplied by a locally trusted authority owner.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedPortableAuthorityDelegationClosure {
    /// Maximum number of child hops accepted from the root.
    pub max_depth: usize,
    /// Grants whose holders are permitted to issue a child.
    pub can_redelegate: BTreeSet<String>,
    /// Complete strict-descendant allocation set for every ancestor grant.
    pub descendants_by_ancestor: BTreeMap<String, Vec<PortableAuthorityDescendantAllocation>>,
}

/// Caller-supplied, fully offline verification inputs.
pub struct PortableAuthorityVerificationInput<'a> {
    /// Complete grant chain in root-to-leaf order.
    pub grant_chain: &'a [Value],
    /// Locally trusted issuer key sets. Network discovery is intentionally outside this API.
    pub trusted_key_sets: &'a [Value],
    /// Signed revocation snapshots available offline.
    pub revocation_snapshots: &'a [Value],
    /// Current verifier time in Unix seconds.
    pub now: u64,
    /// Maximum accepted age from snapshot issuance, in addition to its signed expiry.
    pub max_snapshot_age_seconds: u64,
    pub expected_audience: &'a str,
    pub expected_holder_id: &'a str,
    pub expected_holder_key_id: &'a str,
    /// Previously consumed leaf grant refs at this policy-enforcement point.
    pub consumed_grant_refs: &'a BTreeSet<String>,
    /// Required for any delegated chain. Root-only grants do not need allocation closure.
    pub delegation_closure: Option<&'a TrustedPortableAuthorityDelegationClosure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedPortableAuthorityV3 {
    pub authority_grant_ref: String,
    pub authority_grant_hash: String,
    pub holder_id: String,
    pub holder_key_id: String,
    pub audience: String,
    pub authority_scopes: Vec<String>,
    pub primitive_capability_constraints: Vec<String>,
    pub resources: Vec<String>,
    pub max_budget_microusd: u64,
    pub max_calls: u64,
    pub ancestor_grant_refs: Vec<String>,
    pub revocation_snapshot_refs: Vec<String>,
    pub revocation_snapshots: Vec<VerifiedAuthorityRevocationSnapshotV1>,
    /// Private construction seal: only this module's cryptographic verifier can mint the token.
    verification_seal: PortableAuthorityVerificationSeal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct PortableAuthorityVerificationSeal;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedAuthorityRevocationSnapshotV1 {
    pub snapshot_ref: String,
    pub body_hash: String,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityEffectAdmissionProof<'a> {
    ExactEquality,
    BatchMembership {
        proof_ref: &'a str,
        proof_hash: &'a str,
    },
    StandingConstraint {
        evaluation_ref: &'a str,
        evaluation_hash: &'a str,
    },
}

/// Exact admitted inputs the daemon PEP uses to mint one immutable pre-invocation receipt.
pub struct AuthorityEffectAdmissionReceiptV2Input<'a> {
    pub receipt_id: &'a str,
    pub policy_enforcement_point_ref: &'a str,
    pub verified_grant: &'a VerifiedPortableAuthorityV3,
    /// The exact raw leaf value that produced `verified_grant`.
    pub leaf_grant: &'a Value,
    pub actual_effect_ref: &'a str,
    pub actual_effect_hash: &'a str,
    pub decision_profile_ref: &'a str,
    pub policy_hash: &'a str,
    pub temporal_verification_profile_ref: &'a str,
    pub temporal_verification_profile_hash: &'a str,
    pub temporal_validity_evaluation_ref: &'a str,
    pub temporal_validity_evaluation_hash: &'a str,
    /// `online_fresh` or `bounded_offline`; admitted receipts cannot claim weaker posture.
    pub temporal_posture: &'a str,
    pub continuity_floor_evidence_refs: &'a [String],
    pub principal_authority_revalidation_receipt_ref: Option<&'a str>,
    pub principal_authority_revalidation_receipt_hash: Option<&'a str>,
    pub proof: AuthorityEffectAdmissionProof<'a>,
    pub decided_at: &'a str,
}

/// Sealed pre-invocation receipt produced only from a cryptographically verified v3 leaf.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VerifiedAuthorityEffectAdmissionReceiptV2 {
    receipt: Value,
    verification_seal: PortableAuthorityVerificationSeal,
}

impl VerifiedAuthorityEffectAdmissionReceiptV2 {
    pub fn as_value(&self) -> &Value {
        &self.receipt
    }

    pub fn into_value(self) -> Value {
        self.receipt
    }

    pub fn receipt_hash(&self) -> &str {
        self.receipt["receipt_hash"]
            .as_str()
            .expect("sealed admission receipt has a registered receipt_hash")
    }
}

fn required_str<'a>(
    value: &'a Value,
    pointer: &str,
    code: PortableAuthorityRefusalCode,
) -> Result<&'a str, PortableAuthorityRefusal> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| refuse(code, format!("missing or invalid {pointer}")))
}

fn required_u64(
    value: &Value,
    pointer: &str,
    code: PortableAuthorityRefusalCode,
) -> Result<u64, PortableAuthorityRefusal> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| refuse(code, format!("missing or invalid {pointer}")))
}

fn string_set(
    value: &Value,
    pointer: &str,
    code: PortableAuthorityRefusalCode,
) -> Result<BTreeSet<String>, PortableAuthorityRefusal> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| refuse(code, format!("missing or invalid {pointer}")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| refuse(code, format!("non-string entry in {pointer}")))
        })
        .collect()
}

fn sha256_ref(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn jcs(
    value: &Value,
    code: PortableAuthorityRefusalCode,
) -> Result<Vec<u8>, PortableAuthorityRefusal> {
    serde_jcs::to_vec(value)
        .map_err(|error| refuse(code, format!("JCS canonicalization failed: {error}")))
}

pub fn authority_grant_v3_body_hash(value: &Value) -> Result<String, PortableAuthorityRefusal> {
    let mut body = value.clone();
    let object = body.as_object_mut().ok_or_else(|| {
        refuse(
            PortableAuthorityRefusalCode::MalformedGrant,
            "grant must be one JSON object",
        )
    })?;
    object.remove("body_hash");
    object.remove("signature");
    let mut material = GRANT_V3_DOMAIN.to_vec();
    material.extend(jcs(&body, PortableAuthorityRefusalCode::MalformedGrant)?);
    Ok(sha256_ref(&material))
}

pub fn authority_grant_v3_signature_preimage(
    value: &Value,
) -> Result<Vec<u8>, PortableAuthorityRefusal> {
    let material = json!({
        "body_hash": required_str(value, "/body_hash", PortableAuthorityRefusalCode::MalformedGrant)?,
        "schema_hash": required_str(value, "/schema_hash", PortableAuthorityRefusalCode::MalformedGrant)?,
        "signature_domain": required_str(value, "/signature_domain", PortableAuthorityRefusalCode::MalformedGrant)?,
    });
    let mut preimage = GRANT_V3_DOMAIN.to_vec();
    preimage.extend(jcs(
        &material,
        PortableAuthorityRefusalCode::MalformedGrant,
    )?);
    Ok(preimage)
}

fn snapshot_body_hash(value: &Value) -> Result<String, PortableAuthorityRefusal> {
    let mut body = value.clone();
    let object = body.as_object_mut().ok_or_else(|| {
        refuse(
            PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
            "revocation snapshot must be one JSON object",
        )
    })?;
    for field in [
        "body_hash",
        "signature_suite",
        "signature_key_id",
        "signature",
    ] {
        object.remove(field);
    }
    Ok(sha256_ref(&jcs(
        &body,
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?))
}

fn snapshot_signature_preimage(value: &Value) -> Result<Vec<u8>, PortableAuthorityRefusal> {
    let material = json!({
        "body_hash": required_str(value, "/body_hash", PortableAuthorityRefusalCode::MalformedRevocationSnapshot)?,
        "signature_domain": required_str(value, "/signature_domain", PortableAuthorityRefusalCode::MalformedRevocationSnapshot)?,
    });
    let mut preimage = REVOCATION_SNAPSHOT_V1_DOMAIN.to_vec();
    preimage.extend(jcs(
        &material,
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?);
    Ok(preimage)
}

fn verify_ed25519(
    public_key: &str,
    signature: &str,
    message: &[u8],
    code: PortableAuthorityRefusalCode,
) -> Result<(), PortableAuthorityRefusal> {
    let public_key = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|error| refuse(code, format!("public key is not base64url: {error}")))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|error| refuse(code, format!("signature is not base64url: {error}")))?;
    let public_key = Ed25519PublicKey::from_bytes(&public_key)
        .map_err(|error| refuse(code, format!("invalid Ed25519 key: {error}")))?;
    let signature = Ed25519Signature::from_bytes(&signature)
        .map_err(|error| refuse(code, format!("invalid Ed25519 signature: {error}")))?;
    public_key
        .verify(message, &signature)
        .map_err(|_| refuse(code, "Ed25519 verification failed"))
}

fn validate_registered(
    contract: &str,
    value: &Value,
    code: PortableAuthorityRefusalCode,
) -> Result<(), PortableAuthorityRefusal> {
    validate_architecture_contract(contract, value)
        .map_err(|error| refuse(code, format!("registered contract refused value: {error}")))
}

fn issuer_key_set<'a>(
    grant: &Value,
    key_sets: &'a [Value],
    now: u64,
) -> Result<(&'a Value, &'a Value), PortableAuthorityRefusal> {
    let issuer = required_str(
        grant,
        "/issuer_id",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let key_set_ref = required_str(
        grant,
        "/issuer_key_set_ref",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let version = required_u64(
        grant,
        "/issuer_key_set_version",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let key_id = required_str(
        grant,
        "/issuer_key_id",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let key_set = key_sets
        .iter()
        .find(|candidate| {
            candidate.get("issuer_id").and_then(Value::as_str) == Some(issuer)
                && candidate.get("key_set_id").and_then(Value::as_str) == Some(key_set_ref)
                && candidate.get("version").and_then(Value::as_u64) == Some(version)
        })
        .ok_or_else(|| {
            refuse(
                PortableAuthorityRefusalCode::UntrustedIssuer,
                format!("no locally trusted key set for {issuer} {key_set_ref} v{version}"),
            )
        })?;
    validate_registered(
        AUTHORITY_KEY_SET_V1_CONTRACT,
        key_set,
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    let issued_at = required_u64(
        key_set,
        "/issued_at",
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    let expires_at = required_u64(
        key_set,
        "/expires_at",
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    if now < issued_at || now > expires_at {
        return Err(refuse(
            PortableAuthorityRefusalCode::StaleKeySet,
            format!("key set {key_set_ref} is not current at {now}"),
        ));
    }
    let key = key_set
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| {
            keys.iter()
                .find(|candidate| candidate.get("key_id").and_then(Value::as_str) == Some(key_id))
        })
        .ok_or_else(|| {
            refuse(
                PortableAuthorityRefusalCode::InactiveKey,
                format!("issuer key {key_id} is absent"),
            )
        })?;
    let grant_issued_at = required_u64(
        grant,
        "/issued_at",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let key_not_before = required_u64(
        key,
        "/not_before",
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    let key_expires_at = required_u64(
        key,
        "/expires_at",
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    if key.get("status").and_then(Value::as_str) != Some("active")
        || grant_issued_at < key_not_before
        || grant_issued_at > key_expires_at
        || grant_issued_at > now
        || now > key_expires_at
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::InactiveKey,
            format!("issuer key {key_id} is not active for consequential use"),
        ));
    }
    Ok((key_set, key))
}

fn verify_revocation_snapshot(
    grant: &Value,
    key_set: &Value,
    issuer_key: &Value,
    snapshots: &[Value],
    now: u64,
    max_age: u64,
    ancestor: bool,
) -> Result<VerifiedAuthorityRevocationSnapshotV1, PortableAuthorityRefusal> {
    let issuer = required_str(
        grant,
        "/issuer_id",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let key_set_ref = required_str(
        grant,
        "/issuer_key_set_ref",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let version = required_u64(
        grant,
        "/issuer_key_set_version",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let grant_epoch = required_u64(
        grant,
        "/revocation_epoch",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let snapshot = snapshots
        .iter()
        .filter(|candidate| {
            candidate.get("issuer_id").and_then(Value::as_str) == Some(issuer)
                && candidate.get("issuer_key_set_ref").and_then(Value::as_str) == Some(key_set_ref)
                && candidate
                    .get("issuer_key_set_version")
                    .and_then(Value::as_u64)
                    == Some(version)
        })
        .max_by_key(|candidate| candidate.get("epoch").and_then(Value::as_u64).unwrap_or(0))
        .ok_or_else(|| {
            refuse(
                if ancestor {
                    PortableAuthorityRefusalCode::StaleAncestorState
                } else {
                    PortableAuthorityRefusalCode::MissingRevocationSnapshot
                },
                format!("no revocation snapshot for {issuer} {key_set_ref} v{version}"),
            )
        })?;
    validate_registered(
        AUTHORITY_REVOCATION_SNAPSHOT_V1_CONTRACT,
        snapshot,
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?;
    let issued_at = required_u64(
        snapshot,
        "/issued_at",
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?;
    let expires_at = required_u64(
        snapshot,
        "/expires_at",
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?;
    if now < issued_at || now > expires_at || now.saturating_sub(issued_at) > max_age {
        return Err(refuse(
            if ancestor {
                PortableAuthorityRefusalCode::StaleAncestorState
            } else {
                PortableAuthorityRefusalCode::StaleRevocationSnapshot
            },
            "revocation snapshot is outside its admitted freshness bound",
        ));
    }
    let epoch = required_u64(
        snapshot,
        "/epoch",
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?;
    if epoch < grant_epoch {
        return Err(refuse(
            if ancestor {
                PortableAuthorityRefusalCode::StaleAncestorState
            } else {
                PortableAuthorityRefusalCode::StaleRevocationSnapshot
            },
            format!("snapshot epoch {epoch} predates grant epoch {grant_epoch}"),
        ));
    }
    let claimed_hash = required_str(
        snapshot,
        "/body_hash",
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?;
    if snapshot_body_hash(snapshot)? != claimed_hash {
        return Err(refuse(
            PortableAuthorityRefusalCode::InvalidRevocationSnapshot,
            "revocation snapshot body hash does not match its content",
        ));
    }
    let signature_key_id = required_str(
        snapshot,
        "/signature_key_id",
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?;
    let key = key_set
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| {
            keys.iter()
                .find(|key| key.get("key_id").and_then(Value::as_str) == Some(signature_key_id))
        })
        .ok_or_else(|| {
            refuse(
                PortableAuthorityRefusalCode::InvalidRevocationSnapshot,
                "snapshot signature key is absent from its trusted key set",
            )
        })?;
    if key.get("status").and_then(Value::as_str) != Some("active") {
        return Err(refuse(
            PortableAuthorityRefusalCode::InvalidRevocationSnapshot,
            "snapshot signature key is not active",
        ));
    }
    let key_not_before = required_u64(
        key,
        "/not_before",
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    let key_expires_at = required_u64(
        key,
        "/expires_at",
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    if issued_at < key_not_before || issued_at > key_expires_at || now > key_expires_at {
        return Err(refuse(
            PortableAuthorityRefusalCode::InvalidRevocationSnapshot,
            "snapshot signature key is outside its admitted validity interval",
        ));
    }
    verify_ed25519(
        required_str(
            key,
            "/public_key",
            PortableAuthorityRefusalCode::MalformedKeySet,
        )?,
        required_str(
            snapshot,
            "/signature",
            PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
        )?,
        &snapshot_signature_preimage(snapshot)?,
        PortableAuthorityRefusalCode::InvalidRevocationSnapshot,
    )?;
    let grant_ref = required_str(
        grant,
        "/authority_grant_id",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let issuer_key_id = required_str(
        issuer_key,
        "/key_id",
        PortableAuthorityRefusalCode::MalformedKeySet,
    )?;
    if string_set(
        snapshot,
        "/revoked_grant_refs",
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?
    .contains(grant_ref)
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::RevokedGrant,
            format!("grant {grant_ref} is revoked"),
        ));
    }
    if string_set(
        snapshot,
        "/revoked_key_ids",
        PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
    )?
    .contains(issuer_key_id)
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::RevokedKey,
            format!("issuer key {issuer_key_id} is revoked"),
        ));
    }
    Ok(VerifiedAuthorityRevocationSnapshotV1 {
        snapshot_ref: required_str(
            snapshot,
            "/snapshot_id",
            PortableAuthorityRefusalCode::MalformedRevocationSnapshot,
        )?
        .to_owned(),
        body_hash: claimed_hash.to_owned(),
        epoch,
    })
}

fn subset(child: &BTreeSet<String>, parent: &BTreeSet<String>) -> bool {
    child.is_subset(parent)
}

fn verify_attenuation(parent: &Value, child: &Value) -> Result<(), PortableAuthorityRefusal> {
    let parent_scopes = string_set(
        parent,
        "/authority_scopes",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_scopes = string_set(
        child,
        "/authority_scopes",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_caps = string_set(
        parent,
        "/primitive_capability_constraints",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_caps = string_set(
        child,
        "/primitive_capability_constraints",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_resources = string_set(
        parent,
        "/resources",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_resources = string_set(
        child,
        "/resources",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_risks = string_set(
        parent,
        "/risk_restrictions/allowed_risk_classes",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_risks = string_set(
        child,
        "/risk_restrictions/allowed_risk_classes",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_caveats = string_set(
        parent,
        "/attenuating_caveats",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_caveats = string_set(
        child,
        "/attenuating_caveats",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_approvals = string_set(
        parent,
        "/risk_restrictions/approval_required_for",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_approvals = string_set(
        child,
        "/risk_restrictions/approval_required_for",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_budget = required_u64(
        parent,
        "/risk_restrictions/max_budget_microusd",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_budget = required_u64(
        child,
        "/risk_restrictions/max_budget_microusd",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_calls = required_u64(
        parent,
        "/risk_restrictions/max_calls",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_calls = required_u64(
        child,
        "/risk_restrictions/max_calls",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_not_before = required_u64(
        parent,
        "/not_before",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_not_before = required_u64(
        child,
        "/not_before",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_expires = required_u64(
        parent,
        "/expires_at",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_expires = required_u64(
        child,
        "/expires_at",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let parent_epoch = required_u64(
        parent,
        "/revocation_epoch",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let child_epoch = required_u64(
        child,
        "/revocation_epoch",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let same_audience = required_str(
        parent,
        "/audience",
        PortableAuthorityRefusalCode::MalformedGrant,
    )? == required_str(
        child,
        "/audience",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let no_widening = subset(&child_scopes, &parent_scopes)
        && subset(&child_caps, &parent_caps)
        && subset(&child_resources, &parent_resources)
        && subset(&child_risks, &parent_risks)
        && parent_caveats.is_subset(&child_caveats)
        && parent_approvals.is_subset(&child_approvals)
        && child_budget <= parent_budget
        && child_calls <= parent_calls
        && child_not_before >= parent_not_before
        && child_expires <= parent_expires
        && child_epoch >= parent_epoch
        && same_audience;
    let actually_narrower = child_scopes != parent_scopes
        || child_caps != parent_caps
        || child_resources != parent_resources
        || child_risks != parent_risks
        || child_caveats != parent_caveats
        || child_approvals != parent_approvals
        || child_budget < parent_budget
        || child_calls < parent_calls
        || child_not_before > parent_not_before
        || child_expires < parent_expires;
    if !no_widening || !actually_narrower {
        return Err(refuse(
            PortableAuthorityRefusalCode::WidenedChild,
            "delegated child widens or fails to attenuate its parent",
        ));
    }
    Ok(())
}

fn verify_delegation_closure(
    chain: &[Value],
    closure: Option<&TrustedPortableAuthorityDelegationClosure>,
) -> Result<(), PortableAuthorityRefusal> {
    if chain.len() <= 1 {
        return Ok(());
    }
    let closure = closure.ok_or_else(|| {
        refuse(
            PortableAuthorityRefusalCode::DelegationClosureMissing,
            "delegated chains require a locally trusted complete allocation closure",
        )
    })?;
    let depth = chain.len() - 1;
    if depth > closure.max_depth {
        return Err(refuse(
            PortableAuthorityRefusalCode::DepthExhausted,
            format!("delegation depth {depth} exceeds {}", closure.max_depth),
        ));
    }
    for (index, ancestor) in chain[..chain.len() - 1].iter().enumerate() {
        let ancestor_ref = required_str(
            ancestor,
            "/authority_grant_id",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        if !closure.can_redelegate.contains(ancestor_ref) {
            return Err(refuse(
                PortableAuthorityRefusalCode::RedelegationForbidden,
                format!("grant {ancestor_ref} has no admitted re-delegation right"),
            ));
        }
        let allocations = closure
            .descendants_by_ancestor
            .get(ancestor_ref)
            .ok_or_else(|| {
                refuse(
                    PortableAuthorityRefusalCode::DelegationClosureMissing,
                    format!("complete descendants are absent for {ancestor_ref}"),
                )
            })?;
        let mut refs = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        let mut budget_sum = 0u64;
        let mut call_sum = 0u64;
        for allocation in allocations {
            if !refs.insert(allocation.grant_ref.as_str())
                || !hashes.insert(allocation.body_hash.as_str())
            {
                return Err(refuse(
                    PortableAuthorityRefusalCode::Replay,
                    "delegation closure duplicates a grant ref or body hash",
                ));
            }
            budget_sum = budget_sum
                .checked_add(allocation.max_budget_microusd)
                .ok_or_else(|| {
                    refuse(
                        PortableAuthorityRefusalCode::BudgetExhausted,
                        "descendant budget arithmetic overflowed",
                    )
                })?;
            call_sum = call_sum.checked_add(allocation.max_calls).ok_or_else(|| {
                refuse(
                    PortableAuthorityRefusalCode::CallsExhausted,
                    "descendant call arithmetic overflowed",
                )
            })?;
        }
        let ancestor_budget = required_u64(
            ancestor,
            "/risk_restrictions/max_budget_microusd",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        let ancestor_calls = required_u64(
            ancestor,
            "/risk_restrictions/max_calls",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        if budget_sum > ancestor_budget {
            return Err(refuse(PortableAuthorityRefusalCode::BudgetExhausted, format!("descendants allocate {budget_sum} microusd above {ancestor_ref}'s {ancestor_budget}")));
        }
        if call_sum > ancestor_calls {
            return Err(refuse(
                PortableAuthorityRefusalCode::CallsExhausted,
                format!(
                    "descendants allocate {call_sum} calls above {ancestor_ref}'s {ancestor_calls}"
                ),
            ));
        }
        for descendant in &chain[index + 1..] {
            let descendant_ref = required_str(
                descendant,
                "/authority_grant_id",
                PortableAuthorityRefusalCode::MalformedGrant,
            )?;
            let descendant_hash = required_str(
                descendant,
                "/body_hash",
                PortableAuthorityRefusalCode::MalformedGrant,
            )?;
            let descendant_budget = required_u64(
                descendant,
                "/risk_restrictions/max_budget_microusd",
                PortableAuthorityRefusalCode::MalformedGrant,
            )?;
            let descendant_calls = required_u64(
                descendant,
                "/risk_restrictions/max_calls",
                PortableAuthorityRefusalCode::MalformedGrant,
            )?;
            if !allocations.iter().any(|allocation| {
                allocation.grant_ref == descendant_ref
                    && allocation.body_hash == descendant_hash
                    && allocation.max_budget_microusd == descendant_budget
                    && allocation.max_calls == descendant_calls
            }) {
                return Err(refuse(
                    PortableAuthorityRefusalCode::DelegationClosureMissing,
                    format!("{ancestor_ref} closure does not bind descendant {descendant_ref}"),
                ));
            }
        }
    }
    Ok(())
}

/// Verify a complete portable v3 chain without network access.
pub fn verify_portable_authority_v3(
    input: PortableAuthorityVerificationInput<'_>,
) -> Result<VerifiedPortableAuthorityV3, PortableAuthorityRefusal> {
    if input.grant_chain.is_empty() {
        return Err(refuse(
            PortableAuthorityRefusalCode::MalformedGrant,
            "grant chain is empty",
        ));
    }
    let expected_schema_hash = architecture_contract_schema_hash(AUTHORITY_GRANT_V3_CONTRACT)
        .ok_or_else(|| {
            refuse(
                PortableAuthorityRefusalCode::SchemaMismatch,
                "v3 grant contract is not registered",
            )
        })?;
    let mut grant_refs = BTreeSet::new();
    let mut body_hashes = BTreeSet::new();
    let mut verified_snapshots = Vec::with_capacity(input.grant_chain.len());
    for (index, grant) in input.grant_chain.iter().enumerate() {
        validate_registered(
            AUTHORITY_GRANT_V3_CONTRACT,
            grant,
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        let grant_ref = required_str(
            grant,
            "/authority_grant_id",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        let claimed_hash = required_str(
            grant,
            "/body_hash",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        if !grant_refs.insert(grant_ref) || !body_hashes.insert(claimed_hash) {
            return Err(refuse(
                PortableAuthorityRefusalCode::DelegationCycle,
                "grant chain repeats a grant ref or body hash",
            ));
        }
        if required_str(
            grant,
            "/schema_hash",
            PortableAuthorityRefusalCode::MalformedGrant,
        )? != expected_schema_hash
        {
            return Err(refuse(
                PortableAuthorityRefusalCode::SchemaMismatch,
                format!("grant {grant_ref} carries a stale schema hash"),
            ));
        }
        if authority_grant_v3_body_hash(grant)? != claimed_hash {
            return Err(refuse(
                PortableAuthorityRefusalCode::BodyHashMismatch,
                format!("grant {grant_ref} body hash does not match its content"),
            ));
        }
        let not_before = required_u64(
            grant,
            "/not_before",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        let expires_at = required_u64(
            grant,
            "/expires_at",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?;
        if input.now < not_before || input.now > expires_at {
            return Err(refuse(
                if index + 1 == input.grant_chain.len() {
                    PortableAuthorityRefusalCode::MalformedGrant
                } else {
                    PortableAuthorityRefusalCode::StaleAncestorState
                },
                format!("grant {grant_ref} is outside its validity interval"),
            ));
        }
        let (key_set, issuer_key) = issuer_key_set(grant, input.trusted_key_sets, input.now)?;
        verify_ed25519(
            required_str(
                issuer_key,
                "/public_key",
                PortableAuthorityRefusalCode::MalformedKeySet,
            )?,
            required_str(
                grant,
                "/signature",
                PortableAuthorityRefusalCode::MalformedGrant,
            )?,
            &authority_grant_v3_signature_preimage(grant)?,
            PortableAuthorityRefusalCode::SignatureMismatch,
        )?;
        verified_snapshots.push(verify_revocation_snapshot(
            grant,
            key_set,
            issuer_key,
            input.revocation_snapshots,
            input.now,
            input.max_snapshot_age_seconds,
            index + 1 != input.grant_chain.len(),
        )?);
        if index == 0 {
            if !grant.get("parent_grant").is_some_and(Value::is_null) {
                return Err(refuse(
                    PortableAuthorityRefusalCode::ParentLinkMismatch,
                    "root grant names a parent",
                ));
            }
        } else {
            let parent = &input.grant_chain[index - 1];
            let parent_link = grant
                .get("parent_grant")
                .filter(|value| value.is_object())
                .ok_or_else(|| {
                    refuse(
                        PortableAuthorityRefusalCode::MissingParentProof,
                        format!("grant {grant_ref} lacks parent proof"),
                    )
                })?;
            let parent_ref = required_str(
                parent,
                "/authority_grant_id",
                PortableAuthorityRefusalCode::MalformedGrant,
            )?;
            let parent_hash = required_str(
                parent,
                "/body_hash",
                PortableAuthorityRefusalCode::MalformedGrant,
            )?;
            if parent_link.get("grant_ref").and_then(Value::as_str) != Some(parent_ref)
                || parent_link.get("body_hash").and_then(Value::as_str) != Some(parent_hash)
            {
                return Err(refuse(
                    PortableAuthorityRefusalCode::ParentLinkMismatch,
                    format!("grant {grant_ref} does not link the exact previous grant"),
                ));
            }
            if required_str(
                grant,
                "/issuer_id",
                PortableAuthorityRefusalCode::MalformedGrant,
            )? != required_str(
                parent,
                "/holder_id",
                PortableAuthorityRefusalCode::MalformedGrant,
            )? || required_str(
                grant,
                "/issuer_key_id",
                PortableAuthorityRefusalCode::MalformedGrant,
            )? != required_str(
                parent,
                "/holder_key_id",
                PortableAuthorityRefusalCode::MalformedGrant,
            )? {
                return Err(refuse(
                    PortableAuthorityRefusalCode::WrongIssuer,
                    format!("grant {grant_ref} was not issued by its parent holder key"),
                ));
            }
            verify_attenuation(parent, grant)?;
        }
    }
    verify_delegation_closure(input.grant_chain, input.delegation_closure)?;
    let leaf = input.grant_chain.last().expect("non-empty chain checked");
    let leaf_ref = required_str(
        leaf,
        "/authority_grant_id",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    if input.consumed_grant_refs.contains(leaf_ref) {
        return Err(refuse(
            PortableAuthorityRefusalCode::Replay,
            format!("grant {leaf_ref} was already consumed"),
        ));
    }
    if required_str(
        leaf,
        "/audience",
        PortableAuthorityRefusalCode::MalformedGrant,
    )? != input.expected_audience
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::WrongAudience,
            "leaf audience does not match the policy-enforcement point",
        ));
    }
    if required_str(
        leaf,
        "/holder_id",
        PortableAuthorityRefusalCode::MalformedGrant,
    )? != input.expected_holder_id
        || required_str(
            leaf,
            "/holder_key_id",
            PortableAuthorityRefusalCode::MalformedGrant,
        )? != input.expected_holder_key_id
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::WrongHolder,
            "leaf holder tuple does not match the presenter",
        ));
    }
    Ok(VerifiedPortableAuthorityV3 {
        authority_grant_ref: leaf_ref.to_owned(),
        authority_grant_hash: required_str(
            leaf,
            "/body_hash",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?
        .to_owned(),
        holder_id: input.expected_holder_id.to_owned(),
        holder_key_id: input.expected_holder_key_id.to_owned(),
        audience: input.expected_audience.to_owned(),
        authority_scopes: string_set(
            leaf,
            "/authority_scopes",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?
        .into_iter()
        .collect(),
        primitive_capability_constraints: string_set(
            leaf,
            "/primitive_capability_constraints",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?
        .into_iter()
        .collect(),
        resources: string_set(
            leaf,
            "/resources",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?
        .into_iter()
        .collect(),
        max_budget_microusd: required_u64(
            leaf,
            "/risk_restrictions/max_budget_microusd",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?,
        max_calls: required_u64(
            leaf,
            "/risk_restrictions/max_calls",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?,
        ancestor_grant_refs: input.grant_chain[..input.grant_chain.len() - 1]
            .iter()
            .map(|grant| {
                required_str(
                    grant,
                    "/authority_grant_id",
                    PortableAuthorityRefusalCode::MalformedGrant,
                )
                .map(str::to_owned)
            })
            .collect::<Result<_, _>>()?,
        revocation_snapshot_refs: verified_snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_ref.clone())
            .collect(),
        revocation_snapshots: verified_snapshots,
        verification_seal: PortableAuthorityVerificationSeal,
    })
}

pub fn authority_effect_admission_body_v2_hash(
    body: &Value,
) -> Result<String, PortableAuthorityRefusal> {
    let mut material = EFFECT_ADMISSION_BODY_V2_DOMAIN.to_vec();
    material.extend(jcs(
        body,
        PortableAuthorityRefusalCode::AdmissionReceiptInvalid,
    )?);
    Ok(sha256_ref(&material))
}

pub fn authority_effect_admission_receipt_v2_hash(
    schema_version: &str,
    receipt_envelope: &Value,
    body_hash: &str,
) -> Result<String, PortableAuthorityRefusal> {
    let material_value = json!({
        "schema_version": schema_version,
        "receipt_envelope": receipt_envelope,
        "body_hash": body_hash,
    });
    let mut material = EFFECT_ADMISSION_RECEIPT_V2_DOMAIN.to_vec();
    material.extend(jcs(
        &material_value,
        PortableAuthorityRefusalCode::AdmissionReceiptInvalid,
    )?);
    Ok(sha256_ref(&material))
}

/// Construct the immutable v2 admission receipt after portable verification and before invocation.
///
/// This constructor emits admitted receipts only. A refusal is returned as a typed verifier error,
/// and no caller may interpret that error as an admission artifact.
pub fn build_authority_effect_admission_receipt_v2(
    input: AuthorityEffectAdmissionReceiptV2Input<'_>,
) -> Result<VerifiedAuthorityEffectAdmissionReceiptV2, PortableAuthorityRefusal> {
    validate_registered(
        AUTHORITY_GRANT_V3_CONTRACT,
        input.leaf_grant,
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let grant_ref = required_str(
        input.leaf_grant,
        "/authority_grant_id",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let grant_hash = required_str(
        input.leaf_grant,
        "/body_hash",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    if grant_ref != input.verified_grant.authority_grant_ref
        || grant_hash != input.verified_grant.authority_grant_hash
        || authority_grant_v3_body_hash(input.leaf_grant)? != grant_hash
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::AdmissionReceiptInvalid,
            "leaf grant does not match the exact verified v3 result",
        ));
    }
    if input.verified_grant.audience != input.policy_enforcement_point_ref {
        return Err(refuse(
            PortableAuthorityRefusalCode::WrongAudience,
            "verified grant audience is not the receipt policy-enforcement point",
        ));
    }
    let leaf_scopes = string_set(
        input.leaf_grant,
        "/authority_scopes",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let leaf_capabilities = string_set(
        input.leaf_grant,
        "/primitive_capability_constraints",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    if leaf_scopes.iter().cloned().collect::<Vec<_>>() != input.verified_grant.authority_scopes
        || leaf_capabilities.iter().cloned().collect::<Vec<_>>()
            != input.verified_grant.primitive_capability_constraints
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::AdmissionReceiptInvalid,
            "receipt capabilities or scopes differ from the verified leaf",
        ));
    }

    let commitment = input
        .leaf_grant
        .get("request_commitment")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            refuse(
                PortableAuthorityRefusalCode::MalformedGrant,
                "v3 grant lacks request commitment",
            )
        })?;
    let subject = commitment
        .get("authorization_subject")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            refuse(
                PortableAuthorityRefusalCode::MalformedGrant,
                "v3 grant lacks authorization subject",
            )
        })?;
    let subject_kind = required_str(
        commitment,
        "/authorization_subject/kind",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let subject_ref = required_str(
        commitment,
        "/authorization_subject/subject_ref",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let subject_hash = required_str(
        commitment,
        "/authorization_subject/subject_hash",
        PortableAuthorityRefusalCode::MalformedGrant,
    )?;
    let (
        proof_kind,
        membership_proof_ref,
        membership_proof_hash,
        standing_evaluation_ref,
        standing_evaluation_hash,
    ) = match (subject_kind, input.proof) {
        ("exact_effect", AuthorityEffectAdmissionProof::ExactEquality) => {
            if subject_ref != input.actual_effect_ref || subject_hash != input.actual_effect_hash {
                return Err(refuse(
                    PortableAuthorityRefusalCode::EffectMismatch,
                    "daemon-derived exact effect differs from the signed authorization subject",
                ));
            }
            (
                "exact_equality",
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            )
        }
        (
            "batch_manifest",
            AuthorityEffectAdmissionProof::BatchMembership {
                proof_ref,
                proof_hash,
            },
        ) => (
            "batch_membership",
            json!(proof_ref),
            json!(proof_hash),
            Value::Null,
            Value::Null,
        ),
        (
            "standing_envelope",
            AuthorityEffectAdmissionProof::StandingConstraint {
                evaluation_ref,
                evaluation_hash,
            },
        ) => (
            "standing_constraint",
            Value::Null,
            Value::Null,
            json!(evaluation_ref),
            json!(evaluation_hash),
        ),
        _ => {
            return Err(refuse(
                PortableAuthorityRefusalCode::ProofMismatch,
                "authorization subject kind and effect proof do not match",
            ))
        }
    };
    if !matches!(input.temporal_posture, "online_fresh" | "bounded_offline") {
        return Err(refuse(
            PortableAuthorityRefusalCode::AdmissionReceiptInvalid,
            "an admitted receipt requires online_fresh or bounded_offline temporal posture",
        ));
    }
    if input.principal_authority_revalidation_receipt_ref.is_some()
        != input
            .principal_authority_revalidation_receipt_hash
            .is_some()
    {
        return Err(refuse(
            PortableAuthorityRefusalCode::AdmissionReceiptInvalid,
            "principal-authority revalidation ref/hash must be both present or both absent",
        ));
    }
    let snapshot = input
        .verified_grant
        .revocation_snapshots
        .last()
        .ok_or_else(|| {
            refuse(
                PortableAuthorityRefusalCode::MissingRevocationSnapshot,
                "verified grant result lacks its leaf revocation snapshot",
            )
        })?;
    let mut continuity_refs = input.continuity_floor_evidence_refs.to_vec();
    continuity_refs.sort();
    continuity_refs.dedup();
    let body = json!({
        "policy_enforcement_point_ref": input.policy_enforcement_point_ref,
        "authorization_subject": subject,
        "authority_grant_ref": grant_ref,
        "authority_grant_hash": grant_hash,
        "authority_review_receipt_ref": required_str(commitment, "/authority_review_receipt_ref", PortableAuthorityRefusalCode::MalformedGrant)?,
        "authority_review_receipt_hash": required_str(commitment, "/authority_review_receipt_hash", PortableAuthorityRefusalCode::MalformedGrant)?,
        "approval_ceremony_context_ref": required_str(commitment, "/approval_ceremony_context_ref", PortableAuthorityRefusalCode::MalformedGrant)?,
        "approval_ceremony_context_hash": required_str(commitment, "/approval_ceremony_context_hash", PortableAuthorityRefusalCode::MalformedGrant)?,
        "principal_authority_resolution_ref": commitment.get("principal_authority_resolution_ref").cloned().unwrap_or(Value::Null),
        "principal_authority_resolution_hash": commitment.get("principal_authority_resolution_hash").cloned().unwrap_or(Value::Null),
        "principal_authority_revalidation_receipt_ref": input.principal_authority_revalidation_receipt_ref,
        "principal_authority_revalidation_receipt_hash": input.principal_authority_revalidation_receipt_hash,
        "temporal_verification_profile_ref": input.temporal_verification_profile_ref,
        "temporal_verification_profile_hash": input.temporal_verification_profile_hash,
        "temporal_validity_evaluation_ref": input.temporal_validity_evaluation_ref,
        "temporal_validity_evaluation_hash": input.temporal_validity_evaluation_hash,
        "temporal_posture": input.temporal_posture,
        "continuity_floor_evidence_refs": continuity_refs,
        "revocation_evidence_status": "verified",
        "revocation_snapshot_ref": snapshot.snapshot_ref,
        "revocation_snapshot_hash": snapshot.body_hash,
        "revocation_epoch": snapshot.epoch,
        "actual_effect_ref": input.actual_effect_ref,
        "actual_effect_hash": input.actual_effect_hash,
        "decision_profile_ref": input.decision_profile_ref,
        "policy_hash": input.policy_hash,
        "proof_kind": proof_kind,
        "membership_proof_ref": membership_proof_ref,
        "membership_proof_hash": membership_proof_hash,
        "standing_evaluation_ref": standing_evaluation_ref,
        "standing_evaluation_hash": standing_evaluation_hash,
        "decision": "admitted",
        "refusal_code": Value::Null,
        "invoker_called": false,
        "invoker_receipt_ref": Value::Null,
        "effect_receipt_ref": Value::Null,
        "decided_at": input.decided_at,
    });
    let body_hash = authority_effect_admission_body_v2_hash(&body)?;

    let mut boundary_refs = BTreeSet::new();
    for pointer in [
        "/policy_enforcement_point_ref",
        "/authorization_subject/subject_ref",
        "/authority_grant_ref",
        "/authority_review_receipt_ref",
        "/approval_ceremony_context_ref",
        "/principal_authority_resolution_ref",
        "/principal_authority_revalidation_receipt_ref",
        "/temporal_validity_evaluation_ref",
        "/revocation_snapshot_ref",
        "/actual_effect_ref",
        "/membership_proof_ref",
        "/standing_evaluation_ref",
    ] {
        if let Some(reference) = body.pointer(pointer).and_then(Value::as_str) {
            boundary_refs.insert(reference.to_owned());
        }
    }
    for reference in body
        .get("continuity_floor_evidence_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        boundary_refs.insert(reference.to_owned());
    }
    let artifact_refs: Vec<String> = boundary_refs
        .iter()
        .filter(|reference| reference.starts_with("artifact://"))
        .cloned()
        .collect();
    let evidence_bundle_refs: Vec<String> = boundary_refs
        .iter()
        .filter(|reference| {
            reference.starts_with("evidence://")
                || reference.starts_with("assurance-evidence://")
                || reference.starts_with("artifact://")
        })
        .cloned()
        .collect();
    let verification_ref = input
        .principal_authority_revalidation_receipt_ref
        .unwrap_or(required_str(
            commitment,
            "/authority_review_receipt_ref",
            PortableAuthorityRefusalCode::MalformedGrant,
        )?);
    let receipt_envelope = json!({
        "receipt_id": input.receipt_id,
        "receipt_type": "authority_effect_admission",
        "receipt_profile_ref": AUTHORITY_EFFECT_ADMISSION_RECEIPT_V2_CONTRACT,
        "attested_boundary_fact_refs": boundary_refs.into_iter().collect::<Vec<_>>(),
        "claim_scope_ref": AUTHORITY_EFFECT_ADMISSION_RECEIPT_V2_CONTRACT,
        "run_id": Value::Null,
        "task_id": Value::Null,
        "actor_id": input.policy_enforcement_point_ref,
        "input_hash": grant_hash,
        "output_hash": body_hash,
        "policy_hash": input.policy_hash,
        "authority_grant_id": grant_ref,
        "primitive_capabilities": input.verified_grant.primitive_capability_constraints,
        "authority_scopes": input.verified_grant.authority_scopes,
        "artifact_refs": artifact_refs,
        "evidence_bundle_refs": evidence_bundle_refs,
        "verification_ref": verification_ref,
        "acceptance_ref": Value::Null,
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "timestamp": input.decided_at,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
    });
    let receipt_hash = authority_effect_admission_receipt_v2_hash(
        "ioi.components.daemon-runtime.authority-effect-admission-receipt.v2",
        &receipt_envelope,
        &body_hash,
    )?;
    let receipt = json!({
        "schema_version": "ioi.components.daemon-runtime.authority-effect-admission-receipt.v2",
        "receipt_envelope": receipt_envelope,
        "body": body,
        "body_hash": body_hash,
        "receipt_hash": receipt_hash,
    });
    validate_registered(
        AUTHORITY_EFFECT_ADMISSION_RECEIPT_V2_CONTRACT,
        &receipt,
        PortableAuthorityRefusalCode::AdmissionReceiptInvalid,
    )?;
    Ok(VerifiedAuthorityEffectAdmissionReceiptV2 {
        receipt,
        verification_seal: PortableAuthorityVerificationSeal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::SigningKeyPair;
    use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};

    const NOW: u64 = 1_787_587_300;

    fn keypair(seed: u8) -> Ed25519KeyPair {
        let private = Ed25519PrivateKey::from_bytes(&[seed; 32]).expect("private key");
        Ed25519KeyPair::from_private_key(&private).expect("keypair")
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

    fn sign_grant(grant: &mut Value, signer: &Ed25519KeyPair) {
        grant["body_hash"] = json!(authority_grant_v3_body_hash(grant).expect("body hash"));
        let signature = signer
            .sign(&authority_grant_v3_signature_preimage(grant).expect("preimage"))
            .expect("signature");
        grant["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    }

    fn key_set(
        issuer_id: &str,
        key_set_id: &str,
        version: u64,
        key_id: &str,
        signer: &Ed25519KeyPair,
    ) -> Value {
        json!({
            "schema_version": "ioi.foundations.authority-key-set.v1",
            "key_set_type": "ioi.authority-key-set",
            "key_set_id": key_set_id,
            "issuer_id": issuer_id,
            "version": version,
            "issued_at": NOW - 100,
            "expires_at": NOW + 100,
            "keys": [{
                "key_id": key_id,
                "signature_suite": "ed25519",
                "public_key": URL_SAFE_NO_PAD.encode(signer.public_key().to_bytes()),
                "not_before": NOW - 100,
                "expires_at": NOW + 100,
                "status": "active"
            }]
        })
    }

    fn snapshot(
        issuer_id: &str,
        key_set_id: &str,
        version: u64,
        key_id: &str,
        signer: &Ed25519KeyPair,
        revoked_grants: Vec<String>,
    ) -> Value {
        let mut snapshot = json!({
            "schema_version": "ioi.foundations.authority-revocation-snapshot.v1",
            "snapshot_type": "ioi.authority-revocation-snapshot",
            "snapshot_id": format!("snapshot://tests/{version}"),
            "issuer_id": issuer_id,
            "issuer_key_set_ref": key_set_id,
            "issuer_key_set_version": version,
            "epoch": 8,
            "issued_at": NOW - 10,
            "expires_at": NOW + 10,
            "revoked_grant_refs": revoked_grants,
            "revoked_key_ids": [],
            "body_hash": format!("sha256:{}", "0".repeat(64)),
            "signature_domain": "ioi.authority-revocation-snapshot.v1",
            "signature_suite": "ed25519",
            "signature_key_id": key_id,
            "signature": "A".repeat(86)
        });
        snapshot["body_hash"] = json!(snapshot_body_hash(&snapshot).expect("snapshot hash"));
        let signature = signer
            .sign(&snapshot_signature_preimage(&snapshot).expect("snapshot preimage"))
            .expect("snapshot signature");
        snapshot["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        snapshot
    }

    fn root_fixture() -> (Value, Value, Value) {
        let signer = keypair(7);
        let mut grant = fixture("authority-grant-envelope-v3/positive-exact-effect.json");
        grant["schema_hash"] = json!(architecture_contract_schema_hash(
            AUTHORITY_GRANT_V3_CONTRACT
        )
        .expect("registered v3"));
        grant["issued_at"] = json!(NOW - 20);
        grant["not_before"] = json!(NOW - 20);
        grant["expires_at"] = json!(NOW + 20);
        sign_grant(&mut grant, &signer);
        let key_set = key_set(
            grant["issuer_id"].as_str().unwrap(),
            grant["issuer_key_set_ref"].as_str().unwrap(),
            grant["issuer_key_set_version"].as_u64().unwrap(),
            grant["issuer_key_id"].as_str().unwrap(),
            &signer,
        );
        let snapshot = snapshot(
            grant["issuer_id"].as_str().unwrap(),
            grant["issuer_key_set_ref"].as_str().unwrap(),
            grant["issuer_key_set_version"].as_u64().unwrap(),
            grant["issuer_key_id"].as_str().unwrap(),
            &signer,
            Vec::new(),
        );
        (grant, key_set, snapshot)
    }

    fn verify_root(
        grant: &Value,
        key_set: &Value,
        snapshot: &Value,
        expected_audience: &str,
        consumed: &BTreeSet<String>,
    ) -> Result<VerifiedPortableAuthorityV3, PortableAuthorityRefusal> {
        verify_portable_authority_v3(PortableAuthorityVerificationInput {
            grant_chain: std::slice::from_ref(grant),
            trusted_key_sets: std::slice::from_ref(key_set),
            revocation_snapshots: std::slice::from_ref(snapshot),
            now: NOW,
            max_snapshot_age_seconds: 30,
            expected_audience,
            expected_holder_id: grant["holder_id"].as_str().unwrap(),
            expected_holder_key_id: grant["holder_key_id"].as_str().unwrap(),
            consumed_grant_refs: consumed,
            delegation_closure: None,
        })
    }

    fn build_receipt(
        grant: &Value,
        verified: &VerifiedPortableAuthorityV3,
        proof: AuthorityEffectAdmissionProof<'_>,
        actual_effect_ref: &str,
        actual_effect_hash: &str,
    ) -> Result<VerifiedAuthorityEffectAdmissionReceiptV2, PortableAuthorityRefusal> {
        build_authority_effect_admission_receipt_v2(AuthorityEffectAdmissionReceiptV2Input {
            receipt_id: "receipt://tests/portable-admission-1",
            policy_enforcement_point_ref: grant["audience"].as_str().unwrap(),
            verified_grant: verified,
            leaf_grant: grant,
            actual_effect_ref,
            actual_effect_hash,
            decision_profile_ref: "policy://tests/effect-admission/v1",
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            temporal_verification_profile_ref: "policy://tests/time/v1",
            temporal_verification_profile_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            temporal_validity_evaluation_ref: "evidence://tests/time-evaluation-1",
            temporal_validity_evaluation_hash:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            temporal_posture: "bounded_offline",
            continuity_floor_evidence_refs: &["evidence://tests/continuity-floor-1".to_owned()],
            principal_authority_revalidation_receipt_ref: None,
            principal_authority_revalidation_receipt_hash: None,
            proof,
            decided_at: "2026-08-24T15:02:00Z",
        })
    }

    fn assert_code(
        result: Result<VerifiedPortableAuthorityV3, PortableAuthorityRefusal>,
        code: PortableAuthorityRefusalCode,
    ) {
        assert_eq!(result.expect_err("expected refusal").code, code);
    }

    #[test]
    fn root_grant_verifies_fully_offline() {
        let (grant, key_set, current_snapshot) = root_fixture();
        let verified = verify_root(
            &grant,
            &key_set,
            &current_snapshot,
            grant["audience"].as_str().unwrap(),
            &BTreeSet::new(),
        )
        .expect("verified root grant");
        assert_eq!(verified.authority_grant_ref, grant["authority_grant_id"]);
        assert_eq!(verified.authority_grant_hash, grant["body_hash"]);
        assert!(verified.ancestor_grant_refs.is_empty());
        assert_eq!(verified.revocation_snapshot_refs.len(), 1);
    }

    #[test]
    fn admitted_exact_effect_receipt_is_registered_hashed_and_pre_invocation() {
        let (grant, key_set, snapshot) = root_fixture();
        let verified = verify_root(
            &grant,
            &key_set,
            &snapshot,
            grant["audience"].as_str().unwrap(),
            &BTreeSet::new(),
        )
        .expect("verified grant");
        let effect_ref = grant
            .pointer("/request_commitment/authorization_subject/subject_ref")
            .and_then(Value::as_str)
            .unwrap();
        let effect_hash = grant
            .pointer("/request_commitment/authorization_subject/subject_hash")
            .and_then(Value::as_str)
            .unwrap();
        let sealed_receipt = build_receipt(
            &grant,
            &verified,
            AuthorityEffectAdmissionProof::ExactEquality,
            effect_ref,
            effect_hash,
        )
        .expect("admission receipt");
        let receipt = sealed_receipt.as_value();

        validate_architecture_contract(AUTHORITY_EFFECT_ADMISSION_RECEIPT_V2_CONTRACT, &receipt)
            .expect("registered receipt");
        assert_eq!(receipt.pointer("/body/invoker_called"), Some(&json!(false)));
        assert_eq!(
            receipt.pointer("/body/revocation_snapshot_hash"),
            Some(&json!(verified.revocation_snapshots[0].body_hash))
        );
        assert_eq!(
            authority_effect_admission_body_v2_hash(&receipt["body"]).unwrap(),
            receipt["body_hash"]
        );
        assert_eq!(
            authority_effect_admission_receipt_v2_hash(
                receipt["schema_version"].as_str().unwrap(),
                &receipt["receipt_envelope"],
                receipt["body_hash"].as_str().unwrap(),
            )
            .unwrap(),
            receipt["receipt_hash"]
        );
    }

    #[test]
    fn exact_effect_and_subject_proof_substitutions_refuse_before_receipt() {
        let (grant, key_set, snapshot) = root_fixture();
        let verified = verify_root(
            &grant,
            &key_set,
            &snapshot,
            grant["audience"].as_str().unwrap(),
            &BTreeSet::new(),
        )
        .expect("verified grant");
        let effect_ref = grant
            .pointer("/request_commitment/authorization_subject/subject_ref")
            .and_then(Value::as_str)
            .unwrap();
        let effect_hash = grant
            .pointer("/request_commitment/authorization_subject/subject_hash")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(
            build_receipt(
                &grant,
                &verified,
                AuthorityEffectAdmissionProof::ExactEquality,
                effect_ref,
                "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            )
            .expect_err("effect substitution")
            .code,
            PortableAuthorityRefusalCode::EffectMismatch
        );
        assert_eq!(
            build_receipt(
                &grant,
                &verified,
                AuthorityEffectAdmissionProof::BatchMembership {
                    proof_ref: "evidence://tests/membership-1",
                    proof_hash:
                        "sha256:8888888888888888888888888888888888888888888888888888888888888888",
                },
                effect_ref,
                effect_hash,
            )
            .expect_err("proof substitution")
            .code,
            PortableAuthorityRefusalCode::ProofMismatch
        );
    }

    #[test]
    fn batch_and_standing_subjects_emit_only_their_typed_proof() {
        for (kind, subject_ref, proof, expected_kind) in [
            (
                "batch_manifest",
                "artifact://tests/batch-1",
                AuthorityEffectAdmissionProof::BatchMembership {
                    proof_ref: "evidence://tests/membership-1",
                    proof_hash:
                        "sha256:7777777777777777777777777777777777777777777777777777777777777777",
                },
                "batch_membership",
            ),
            (
                "standing_envelope",
                "policy://tests/standing-1",
                AuthorityEffectAdmissionProof::StandingConstraint {
                    evaluation_ref: "receipt://tests/standing-evaluation-1",
                    evaluation_hash:
                        "sha256:6666666666666666666666666666666666666666666666666666666666666666",
                },
                "standing_constraint",
            ),
        ] {
            let (mut grant, key_set, snapshot) = root_fixture();
            grant["request_commitment"]["authorization_subject"]["kind"] = json!(kind);
            grant["request_commitment"]["authorization_subject"]["subject_ref"] =
                json!(subject_ref);
            sign_grant(&mut grant, &keypair(7));
            let verified = verify_root(
                &grant,
                &key_set,
                &snapshot,
                grant["audience"].as_str().unwrap(),
                &BTreeSet::new(),
            )
            .expect("verified typed subject");
            let sealed_receipt = build_receipt(
                &grant,
                &verified,
                proof,
                "effect://tests/actual-1",
                "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            )
            .expect("typed admission receipt");
            let receipt = sealed_receipt.as_value();
            assert_eq!(
                receipt.pointer("/body/proof_kind").and_then(Value::as_str),
                Some(expected_kind)
            );
            assert_eq!(receipt.pointer("/body/invoker_called"), Some(&json!(false)));
        }
    }

    #[test]
    fn body_signature_audience_revocation_and_replay_refuse_by_name() {
        let (grant, key_set, current_snapshot) = root_fixture();
        let mut bad_body = grant.clone();
        bad_body["resources"][0] = json!("deployment://hypervisor/u1/tampered");
        assert_code(
            verify_root(
                &bad_body,
                &key_set,
                &current_snapshot,
                grant["audience"].as_str().unwrap(),
                &BTreeSet::new(),
            ),
            PortableAuthorityRefusalCode::BodyHashMismatch,
        );

        let mut bad_signature = grant.clone();
        bad_signature["signature"] = json!("A".repeat(86));
        assert_code(
            verify_root(
                &bad_signature,
                &key_set,
                &current_snapshot,
                grant["audience"].as_str().unwrap(),
                &BTreeSet::new(),
            ),
            PortableAuthorityRefusalCode::SignatureMismatch,
        );

        assert_code(
            verify_root(
                &grant,
                &key_set,
                &current_snapshot,
                "runtime://wrong/audience",
                &BTreeSet::new(),
            ),
            PortableAuthorityRefusalCode::WrongAudience,
        );

        let signer = keypair(7);
        let revoked = snapshot(
            grant["issuer_id"].as_str().unwrap(),
            grant["issuer_key_set_ref"].as_str().unwrap(),
            grant["issuer_key_set_version"].as_u64().unwrap(),
            grant["issuer_key_id"].as_str().unwrap(),
            &signer,
            vec![grant["authority_grant_id"].as_str().unwrap().to_owned()],
        );
        assert_code(
            verify_root(
                &grant,
                &key_set,
                &revoked,
                grant["audience"].as_str().unwrap(),
                &BTreeSet::new(),
            ),
            PortableAuthorityRefusalCode::RevokedGrant,
        );

        let mut consumed = BTreeSet::new();
        consumed.insert(grant["authority_grant_id"].as_str().unwrap().to_owned());
        assert_code(
            verify_root(
                &grant,
                &key_set,
                &current_snapshot,
                grant["audience"].as_str().unwrap(),
                &consumed,
            ),
            PortableAuthorityRefusalCode::Replay,
        );

        let mut grant_key_expired_at_issue = key_set.clone();
        grant_key_expired_at_issue["keys"][0]["expires_at"] = json!(NOW - 21);
        assert_code(
            verify_root(
                &grant,
                &grant_key_expired_at_issue,
                &current_snapshot,
                grant["audience"].as_str().unwrap(),
                &BTreeSet::new(),
            ),
            PortableAuthorityRefusalCode::InactiveKey,
        );

        let mut snapshot_key_not_yet_valid = key_set.clone();
        let mut snapshot_only_key = snapshot_key_not_yet_valid["keys"][0].clone();
        snapshot_only_key["key_id"] = json!("key://tests/snapshot-only");
        snapshot_only_key["not_before"] = json!(NOW - 5);
        snapshot_key_not_yet_valid["keys"]
            .as_array_mut()
            .unwrap()
            .push(snapshot_only_key);
        let mut snapshot_signed_too_early = current_snapshot.clone();
        snapshot_signed_too_early["signature_key_id"] = json!("key://tests/snapshot-only");
        assert_code(
            verify_root(
                &grant,
                &snapshot_key_not_yet_valid,
                &snapshot_signed_too_early,
                grant["audience"].as_str().unwrap(),
                &BTreeSet::new(),
            ),
            PortableAuthorityRefusalCode::InvalidRevocationSnapshot,
        );
    }

    fn delegated_fixture() -> (
        Vec<Value>,
        Vec<Value>,
        Vec<Value>,
        TrustedPortableAuthorityDelegationClosure,
    ) {
        let (root, root_key_set, root_snapshot) = root_fixture();
        let child_signer = keypair(9);
        let mut child = root.clone();
        child["authority_grant_id"] = json!("grant://wallet/u1/exact-001/child-1");
        child["request_id"] = json!("authority-request://wallet/u1/exact-001/child-1");
        child["request_commitment"]["authority_request_id"] = child["request_id"].clone();
        child["issuer_id"] = root["holder_id"].clone();
        child["issuer_key_set_ref"] = json!("keyset://hypervisor/u1/holder/1");
        child["issuer_key_set_version"] = json!(1);
        child["issuer_key_id"] = root["holder_key_id"].clone();
        child["signature_key_id"] = child["issuer_key_id"].clone();
        child["holder_id"] = json!("worker://hypervisor/u1/exact-worker");
        child["holder_key_id"] = json!("key://hypervisor/u1/exact-worker/1");
        child["issued_at"] = json!(NOW - 10);
        child["not_before"] = json!(NOW - 10);
        child["expires_at"] = json!(NOW + 10);
        child["parent_grant"] = json!({
            "grant_ref": root["authority_grant_id"],
            "body_hash": root["body_hash"],
            "proof_ref": "proof://wallet/u1/exact-001/child-1"
        });
        child["attenuating_caveats"] = json!(["caveat://wallet/u1/child-only"]);
        child["risk_restrictions"]["max_budget_microusd"] = json!(500_000);
        child["risk_restrictions"]["max_calls"] = json!(1);
        sign_grant(&mut child, &child_signer);
        let child_key_set = key_set(
            child["issuer_id"].as_str().unwrap(),
            child["issuer_key_set_ref"].as_str().unwrap(),
            1,
            child["issuer_key_id"].as_str().unwrap(),
            &child_signer,
        );
        let child_snapshot = snapshot(
            child["issuer_id"].as_str().unwrap(),
            child["issuer_key_set_ref"].as_str().unwrap(),
            1,
            child["issuer_key_id"].as_str().unwrap(),
            &child_signer,
            Vec::new(),
        );
        let root_ref = root["authority_grant_id"].as_str().unwrap().to_owned();
        let mut closure = TrustedPortableAuthorityDelegationClosure {
            max_depth: 1,
            can_redelegate: BTreeSet::from([root_ref.clone()]),
            descendants_by_ancestor: BTreeMap::new(),
        };
        closure.descendants_by_ancestor.insert(
            root_ref,
            vec![PortableAuthorityDescendantAllocation {
                grant_ref: child["authority_grant_id"].as_str().unwrap().to_owned(),
                body_hash: child["body_hash"].as_str().unwrap().to_owned(),
                max_budget_microusd: 500_000,
                max_calls: 1,
            }],
        );
        (
            vec![root, child],
            vec![root_key_set, child_key_set],
            vec![root_snapshot, child_snapshot],
            closure,
        )
    }

    fn verify_delegated(
        chain: &[Value],
        key_sets: &[Value],
        snapshots: &[Value],
        closure: Option<&TrustedPortableAuthorityDelegationClosure>,
    ) -> Result<VerifiedPortableAuthorityV3, PortableAuthorityRefusal> {
        let leaf = chain.last().unwrap();
        verify_portable_authority_v3(PortableAuthorityVerificationInput {
            grant_chain: chain,
            trusted_key_sets: key_sets,
            revocation_snapshots: snapshots,
            now: NOW,
            max_snapshot_age_seconds: 30,
            expected_audience: leaf["audience"].as_str().unwrap(),
            expected_holder_id: leaf["holder_id"].as_str().unwrap(),
            expected_holder_key_id: leaf["holder_key_id"].as_str().unwrap(),
            consumed_grant_refs: &BTreeSet::new(),
            delegation_closure: closure,
        })
    }

    #[test]
    fn delegated_chain_requires_and_verifies_complete_allocation_closure() {
        let (chain, key_sets, snapshots, closure) = delegated_fixture();
        assert_code(
            verify_delegated(&chain, &key_sets, &snapshots, None),
            PortableAuthorityRefusalCode::DelegationClosureMissing,
        );
        let verified = verify_delegated(&chain, &key_sets, &snapshots, Some(&closure))
            .expect("verified delegated chain");
        assert_eq!(
            verified.ancestor_grant_refs,
            vec![chain[0]["authority_grant_id"].as_str().unwrap()]
        );
    }

    #[test]
    fn widened_depth_and_cumulative_budget_refuse_by_name() {
        let (chain, key_sets, snapshots, closure) = delegated_fixture();
        let mut widened = chain.clone();
        widened[1]["risk_restrictions"]["max_budget_microusd"] = json!(1_000_001);
        sign_grant(&mut widened[1], &keypair(9));
        assert_code(
            verify_delegated(&widened, &key_sets, &snapshots, Some(&closure)),
            PortableAuthorityRefusalCode::WidenedChild,
        );

        let mut no_depth = closure.clone();
        no_depth.max_depth = 0;
        assert_code(
            verify_delegated(&chain, &key_sets, &snapshots, Some(&no_depth)),
            PortableAuthorityRefusalCode::DepthExhausted,
        );

        let mut over_budget = closure;
        over_budget
            .descendants_by_ancestor
            .values_mut()
            .next()
            .unwrap()
            .push(PortableAuthorityDescendantAllocation {
                grant_ref: "grant://wallet/u1/hidden-sibling".into(),
                body_hash: format!("sha256:{}", "a".repeat(64)),
                max_budget_microusd: 600_000,
                max_calls: 1,
            });
        assert_code(
            verify_delegated(&chain, &key_sets, &snapshots, Some(&over_budget)),
            PortableAuthorityRefusalCode::BudgetExhausted,
        );
    }

    #[test]
    fn cycle_wrong_holder_and_missing_parent_proof_refuse_by_name() {
        let (chain, key_sets, snapshots, closure) = delegated_fixture();
        let cycle = vec![chain[0].clone(), chain[0].clone()];
        assert_code(
            verify_delegated(&cycle, &key_sets, &snapshots, Some(&closure)),
            PortableAuthorityRefusalCode::DelegationCycle,
        );

        let leaf = chain.last().unwrap();
        let wrong_holder = verify_portable_authority_v3(PortableAuthorityVerificationInput {
            grant_chain: &chain,
            trusted_key_sets: &key_sets,
            revocation_snapshots: &snapshots,
            now: NOW,
            max_snapshot_age_seconds: 30,
            expected_audience: leaf["audience"].as_str().unwrap(),
            expected_holder_id: "worker://wrong/holder",
            expected_holder_key_id: leaf["holder_key_id"].as_str().unwrap(),
            consumed_grant_refs: &BTreeSet::new(),
            delegation_closure: Some(&closure),
        });
        assert_code(wrong_holder, PortableAuthorityRefusalCode::WrongHolder);

        let mut missing_parent = chain.clone();
        missing_parent[1]["parent_grant"] = Value::Null;
        sign_grant(&mut missing_parent[1], &keypair(9));
        assert_code(
            verify_delegated(&missing_parent, &key_sets, &snapshots, Some(&closure)),
            PortableAuthorityRefusalCode::MissingParentProof,
        );
    }

    #[test]
    fn stale_and_revoked_ancestor_and_wrong_issuer_refuse_by_name() {
        let (chain, key_sets, snapshots, closure) = delegated_fixture();
        let mut stale_snapshots = snapshots.clone();
        stale_snapshots[0]["expires_at"] = json!(NOW - 1);
        assert_code(
            verify_delegated(&chain, &key_sets, &stale_snapshots, Some(&closure)),
            PortableAuthorityRefusalCode::StaleAncestorState,
        );

        let root_signer = keypair(7);
        let revoked_root_snapshot = snapshot(
            chain[0]["issuer_id"].as_str().unwrap(),
            chain[0]["issuer_key_set_ref"].as_str().unwrap(),
            chain[0]["issuer_key_set_version"].as_u64().unwrap(),
            chain[0]["issuer_key_id"].as_str().unwrap(),
            &root_signer,
            vec![chain[0]["authority_grant_id"].as_str().unwrap().to_owned()],
        );
        let revoked_snapshots = vec![revoked_root_snapshot, snapshots[1].clone()];
        assert_code(
            verify_delegated(&chain, &key_sets, &revoked_snapshots, Some(&closure)),
            PortableAuthorityRefusalCode::RevokedGrant,
        );

        let child_signer = keypair(9);
        let mut wrong_issuer_chain = chain.clone();
        wrong_issuer_chain[1]["issuer_id"] = json!("wallet://wrong/delegator");
        wrong_issuer_chain[1]["issuer_key_set_ref"] = json!("keyset://wrong/delegator/1");
        sign_grant(&mut wrong_issuer_chain[1], &child_signer);
        let wrong_key_set = key_set(
            "wallet://wrong/delegator",
            "keyset://wrong/delegator/1",
            1,
            wrong_issuer_chain[1]["issuer_key_id"].as_str().unwrap(),
            &child_signer,
        );
        let wrong_snapshot = snapshot(
            "wallet://wrong/delegator",
            "keyset://wrong/delegator/1",
            1,
            wrong_issuer_chain[1]["issuer_key_id"].as_str().unwrap(),
            &child_signer,
            Vec::new(),
        );
        let wrong_key_sets = vec![key_sets[0].clone(), wrong_key_set];
        let wrong_snapshots = vec![snapshots[0].clone(), wrong_snapshot];
        assert_code(
            verify_delegated(
                &wrong_issuer_chain,
                &wrong_key_sets,
                &wrong_snapshots,
                Some(&closure),
            ),
            PortableAuthorityRefusalCode::WrongIssuer,
        );
    }

    #[test]
    fn cumulative_calls_and_redelegation_right_refuse_by_name() {
        let (chain, key_sets, snapshots, closure) = delegated_fixture();
        let mut no_right = closure.clone();
        no_right.can_redelegate.clear();
        assert_code(
            verify_delegated(&chain, &key_sets, &snapshots, Some(&no_right)),
            PortableAuthorityRefusalCode::RedelegationForbidden,
        );

        let mut over_calls = closure;
        over_calls
            .descendants_by_ancestor
            .values_mut()
            .next()
            .unwrap()
            .push(PortableAuthorityDescendantAllocation {
                grant_ref: "grant://wallet/u1/hidden-call-sibling".into(),
                body_hash: format!("sha256:{}", "b".repeat(64)),
                max_budget_microusd: 0,
                max_calls: 1,
            });
        assert_code(
            verify_delegated(&chain, &key_sets, &snapshots, Some(&over_calls)),
            PortableAuthorityRefusalCode::CallsExhausted,
        );
    }
}
