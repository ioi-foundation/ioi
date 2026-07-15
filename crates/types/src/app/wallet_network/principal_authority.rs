//! Wallet-owned, root-signed bindings from portable principals to approval authorities.
//!
//! Binding proofs are immutable and content addressed. A mutable wallet service head may point
//! at the latest proof for an exact principal, but rotations and revocations always append a new
//! version. These artifacts identify the signer that a governed grant must use; they do not make
//! the grant optional and do not authorize an action by themselves.

use super::WalletControlPlaneRootRecord;
use crate::app::action::ApprovalAuthority;
use crate::app::{account_id_from_key_material, SignatureProof, SignatureSuite};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version for the first principal-authority binding contract.
pub const PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION: u16 = 1;
/// Domain separator signed by the wallet control root.
pub const PRINCIPAL_AUTHORITY_BINDING_SIGNING_DOMAIN: &str =
    "ioi.wallet-network.principal-authority-binding.v1";
/// Domain separator for the content hash over a complete signed proof.
pub const PRINCIPAL_AUTHORITY_BINDING_PROOF_HASH_DOMAIN: &str =
    "ioi.wallet-network.principal-authority-binding-proof.v1";
/// Canonical content-addressed reference prefix for immutable proofs.
pub const PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX: &str =
    "wallet.network://principal-authority-binding/";
const PRINCIPAL_REF_MAX_BYTES: usize = 300;

/// Structural or cryptographic-binding error in a principal-authority artifact.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrincipalAuthorityBindingError {
    /// The artifact is malformed, noncanonical, or internally inconsistent.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> PrincipalAuthorityBindingError {
    PrincipalAuthorityBindingError::Invalid(message.into())
}

fn hash_bytes(bytes: &[u8]) -> Result<[u8; 32], PrincipalAuthorityBindingError> {
    let digest = Sha256::digest(bytes).map_err(|error| invalid(error.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hash_from_binding_ref(value: &str) -> Result<[u8; 32], PrincipalAuthorityBindingError> {
    let digest = value
        .strip_prefix(PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX)
        .ok_or_else(|| invalid("binding_ref has a noncanonical prefix"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "binding_ref must end in exactly one lowercase 32-byte hex digest",
        ));
    }
    let mut out = [0u8; 32];
    for (index, pair) in digest.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!("validated lowercase hex"),
            }
        };
        out[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(out)
}

/// Validate the exact portable-principal grammar owned by this binding plane.
///
/// Local users, sessions, login identities, and system aliases are deliberately absent. Agentgres
/// references are accepted only for the path-qualified domain object class.
pub fn validate_principal_authority_ref(value: &str) -> Result<(), PrincipalAuthorityBindingError> {
    if value.is_empty()
        || value.len() > PRINCIPAL_REF_MAX_BYTES
        || value != value.trim()
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid(
            "principal_ref must be non-empty, ASCII, bounded, and free of surrounding whitespace",
        ));
    }

    let tail = ["worker://", "service://", "org://", "domain://"]
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
        .or_else(|| value.strip_prefix("agentgres://domain/"))
        .ok_or_else(|| {
            invalid(
                "principal_ref must use worker://, service://, org://, domain://, or agentgres://domain/",
            )
        })?;

    if tail.is_empty()
        || tail.starts_with('/')
        || tail.ends_with('/')
        || tail.contains("//")
        || tail.contains(['?', '#', '%', '*', '\\'])
    {
        return Err(invalid("principal_ref contains a noncanonical path tail"));
    }
    for segment in tail.split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !segment
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'-' | b'~' | b':' | b'@')
            })
        {
            return Err(invalid(
                "principal_ref contains an empty, aliased, or unsupported path segment",
            ));
        }
    }
    Ok(())
}

/// The authority family represented by a principal binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalAuthorityKind {
    /// A registered [`ApprovalAuthority`] that signs governed approval grants.
    Approval,
}

/// Lifecycle state carried by each immutable binding version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalAuthorityBindingStatus {
    /// This version may resolve when it is the current head and its authority remains valid.
    Active,
    /// This version is an immutable revocation successor and never resolves as active authority.
    Revoked,
}

/// Root-signed statement for one immutable binding version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PrincipalAuthorityBindingStatementV1 {
    /// Statement schema version.
    pub schema_version: u16,
    /// Exact canonical portable principal being bound.
    pub principal_ref: String,
    /// Authority family represented by this binding.
    pub authority_kind: PrincipalAuthorityKind,
    /// Monotonic version within this principal's append-only chain.
    pub binding_version: u64,
    /// Lifecycle state introduced by this version.
    pub status: PrincipalAuthorityBindingStatus,
    /// Account identifier derived from the bound authority key.
    pub authority_id: [u8; 32],
    /// Exact public key frozen from the ApprovalAuthority registry artifact.
    pub authority_public_key: Vec<u8>,
    /// Signature suite for the frozen authority key.
    pub authority_signature_suite: SignatureSuite,
    /// Canonical artifact hash of the complete ApprovalAuthority snapshot.
    pub approval_authority_snapshot_hash: [u8; 32],
    /// Content-addressed ref of the previous immutable version, when this is a successor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_binding_ref: Option<String>,
    /// Content hash of the previous immutable version, when this is a successor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_binding_hash: Option<[u8; 32]>,
    /// Wallet-root signing timestamp in milliseconds.
    pub signed_at_ms: u64,
    /// Optional binding expiry in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// Account identifier of the wallet control root that signed this statement.
    pub issuer_root_account_id: [u8; 32],
    /// Optional canonical issuance/rotation reason; mandatory on revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize)]
struct StatementSigningMaterial<'a> {
    domain: &'static str,
    statement: &'a PrincipalAuthorityBindingStatementV1,
}

impl PrincipalAuthorityBindingStatementV1 {
    /// Canonical, domain-separated bytes signed by the wallet control root.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PrincipalAuthorityBindingError> {
        serde_jcs::to_vec(&StatementSigningMaterial {
            domain: PRINCIPAL_AUTHORITY_BINDING_SIGNING_DOMAIN,
            statement: self,
        })
        .map_err(|error| invalid(format!("statement canonicalization failed: {error}")))
    }

    /// Hash of the exact domain-separated signing material.
    pub fn statement_hash(&self) -> Result<[u8; 32], PrincipalAuthorityBindingError> {
        hash_bytes(&self.signing_bytes()?)
    }

    /// Verify canonical grammar, version-chain coordinates, and exact signer identities.
    pub fn verify_intrinsic(&self) -> Result<(), PrincipalAuthorityBindingError> {
        if self.schema_version != PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION {
            return Err(invalid("unsupported principal-authority statement schema"));
        }
        validate_principal_authority_ref(&self.principal_ref)?;
        if self.binding_version == 0 {
            return Err(invalid("binding_version must be at least 1"));
        }
        match (
            self.binding_version,
            self.previous_binding_ref.as_ref(),
            self.previous_binding_hash,
        ) {
            (1, None, None) => {}
            (1, _, _) => {
                return Err(invalid(
                    "binding version 1 must not name previous coordinates",
                ))
            }
            (_, Some(previous_ref), Some(previous_hash)) => {
                if hash_from_binding_ref(previous_ref)? != previous_hash {
                    return Err(invalid(
                        "previous_binding_ref does not encode previous_binding_hash",
                    ));
                }
            }
            _ => return Err(invalid(
                "successor bindings require both previous_binding_ref and previous_binding_hash",
            )),
        }
        if self.authority_public_key.is_empty()
            || self.approval_authority_snapshot_hash == [0u8; 32]
        {
            return Err(invalid(
                "binding authority key and snapshot hash must be non-empty",
            ));
        }
        let derived_authority = account_id_from_key_material(
            self.authority_signature_suite,
            &self.authority_public_key,
        )
        .map_err(|error| invalid(format!("invalid authority key: {error}")))?;
        if derived_authority != self.authority_id {
            return Err(invalid(
                "authority_id does not match authority_public_key/signature_suite",
            ));
        }
        if self.signed_at_ms == 0 {
            return Err(invalid("signed_at_ms must be non-zero"));
        }
        if self
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= self.signed_at_ms)
        {
            return Err(invalid("binding expiry must be later than signed_at_ms"));
        }
        match self.status {
            PrincipalAuthorityBindingStatus::Active => {
                if self.reason.as_ref().is_some_and(|reason| {
                    reason.trim().is_empty() || reason.as_str() != reason.trim()
                }) {
                    return Err(invalid("binding reason must be canonical and nonblank"));
                }
            }
            PrincipalAuthorityBindingStatus::Revoked => {
                if !self
                    .reason
                    .as_ref()
                    .is_some_and(|reason| !reason.trim().is_empty() && reason == reason.trim())
                {
                    return Err(invalid(
                        "revoked bindings require a nonblank canonical reason",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProofHashMaterial<'a> {
    domain: &'static str,
    schema_version: u16,
    statement: &'a PrincipalAuthorityBindingStatementV1,
    statement_hash: [u8; 32],
    issuer_signature_proof: &'a SignatureProof,
}

/// Complete immutable proof for one principal-authority binding version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PrincipalAuthorityBindingProofV1 {
    /// Proof envelope schema version.
    pub schema_version: u16,
    /// Root-signed binding statement.
    pub statement: PrincipalAuthorityBindingStatementV1,
    /// Hash of the exact domain-separated statement signing bytes.
    pub statement_hash: [u8; 32],
    /// Wallet control-root signature and exact key/suite evidence.
    pub issuer_signature_proof: SignatureProof,
    /// Canonical content-addressed reference derived from `binding_hash`.
    pub binding_ref: String,
    /// Hash of the complete statement and root signature proof.
    pub binding_hash: [u8; 32],
}

impl PrincipalAuthorityBindingProofV1 {
    /// Construct the content-addressed proof around a signature over [`Self::signature_message`].
    pub fn new(
        statement: PrincipalAuthorityBindingStatementV1,
        issuer_signature_proof: SignatureProof,
    ) -> Result<Self, PrincipalAuthorityBindingError> {
        statement.verify_intrinsic()?;
        let statement_hash = statement.statement_hash()?;
        let binding_hash = hash_bytes(
            &serde_jcs::to_vec(&ProofHashMaterial {
                domain: PRINCIPAL_AUTHORITY_BINDING_PROOF_HASH_DOMAIN,
                schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
                statement: &statement,
                statement_hash,
                issuer_signature_proof: &issuer_signature_proof,
            })
            .map_err(|error| invalid(format!("proof canonicalization failed: {error}")))?,
        )?;
        let proof = Self {
            schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
            statement,
            statement_hash,
            issuer_signature_proof,
            binding_ref: format!(
                "{PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX}{}",
                lower_hex(&binding_hash)
            ),
            binding_hash,
        };
        proof.verify_intrinsic()?;
        Ok(proof)
    }

    /// Exact bytes that the issuer proof must sign.
    pub fn signature_message(&self) -> Result<Vec<u8>, PrincipalAuthorityBindingError> {
        self.statement.signing_bytes()
    }

    /// Recompute every content binding without treating structural proof as cryptographic proof.
    pub fn verify_intrinsic(&self) -> Result<(), PrincipalAuthorityBindingError> {
        if self.schema_version != PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION {
            return Err(invalid("unsupported principal-authority proof schema"));
        }
        self.statement.verify_intrinsic()?;
        let expected_statement_hash = self.statement.statement_hash()?;
        if self.statement_hash != expected_statement_hash {
            return Err(invalid(
                "statement_hash does not match the signed statement",
            ));
        }
        if self.issuer_signature_proof.public_key.is_empty()
            || self.issuer_signature_proof.signature.is_empty()
        {
            return Err(invalid("issuer signature proof is incomplete"));
        }
        let issuer_id = account_id_from_key_material(
            self.issuer_signature_proof.suite,
            &self.issuer_signature_proof.public_key,
        )
        .map_err(|error| invalid(format!("invalid issuer key: {error}")))?;
        if issuer_id != self.statement.issuer_root_account_id {
            return Err(invalid(
                "issuer_root_account_id does not match issuer signature proof",
            ));
        }
        let expected_binding_hash = hash_bytes(
            &serde_jcs::to_vec(&ProofHashMaterial {
                domain: PRINCIPAL_AUTHORITY_BINDING_PROOF_HASH_DOMAIN,
                schema_version: self.schema_version,
                statement: &self.statement,
                statement_hash: self.statement_hash,
                issuer_signature_proof: &self.issuer_signature_proof,
            })
            .map_err(|error| invalid(format!("proof canonicalization failed: {error}")))?,
        )?;
        if self.binding_hash != expected_binding_hash
            || hash_from_binding_ref(&self.binding_ref)? != expected_binding_hash
        {
            return Err(invalid(
                "binding hash/ref does not match the exact signed proof artifact",
            ));
        }
        Ok(())
    }

    /// Alias used by callers that emphasize content integrity.
    pub fn verify_integrity(&self) -> Result<(), PrincipalAuthorityBindingError> {
        self.verify_intrinsic()
    }

    /// Verify proof integrity, configured-root equality, and the cryptographic root signature.
    pub fn verify_root_signature_with<F>(
        &self,
        root: &WalletControlPlaneRootRecord,
        verifier: F,
    ) -> Result<(), PrincipalAuthorityBindingError>
    where
        F: FnOnce(SignatureSuite, &[u8], &[u8], &[u8]) -> Result<(), String>,
    {
        self.verify_intrinsic()?;
        if self.statement.issuer_root_account_id != root.account_id
            || self.issuer_signature_proof.suite != root.signature_suite
            || self.issuer_signature_proof.public_key != root.public_key
        {
            return Err(invalid(
                "issuer signature proof does not exactly match the configured wallet root",
            ));
        }
        verifier(
            self.issuer_signature_proof.suite,
            &self.issuer_signature_proof.public_key,
            &self.signature_message()?,
            &self.issuer_signature_proof.signature,
        )
        .map_err(|error| invalid(format!("root signature verification failed: {error}")))
    }

    /// Verify the exact mutable ApprovalAuthority artifact frozen by this proof.
    pub fn verify_authority_snapshot(
        &self,
        authority: &ApprovalAuthority,
    ) -> Result<(), PrincipalAuthorityBindingError> {
        authority
            .verify()
            .map_err(|error| invalid(error.to_string()))?;
        let snapshot_hash = authority
            .artifact_hash()
            .map_err(|error| invalid(error.to_string()))?;
        if authority.authority_id != self.statement.authority_id
            || authority.public_key != self.statement.authority_public_key
            || authority.signature_suite != self.statement.authority_signature_suite
            || snapshot_hash != self.statement.approval_authority_snapshot_hash
        {
            return Err(invalid(
                "ApprovalAuthority no longer matches the root-signed snapshot",
            ));
        }
        Ok(())
    }

    /// Require an active, unexpired binding at the supplied wallet timestamp.
    pub fn verify_active_at(&self, now_ms: u64) -> Result<(), PrincipalAuthorityBindingError> {
        self.verify_intrinsic()?;
        if self.statement.signed_at_ms > now_ms {
            return Err(invalid(
                "principal-authority binding is not active before signed_at_ms",
            ));
        }
        if self.statement.status != PrincipalAuthorityBindingStatus::Active {
            return Err(invalid("principal-authority binding is revoked"));
        }
        if self
            .statement
            .expires_at_ms
            .is_some_and(|expires_at| now_ms > expires_at)
        {
            return Err(invalid("principal-authority binding is expired"));
        }
        Ok(())
    }

    /// Stable coordinates retained in governed intents and replay receipts.
    pub fn coordinates(&self) -> PrincipalAuthorityBindingCoordinates {
        PrincipalAuthorityBindingCoordinates {
            binding_ref: self.binding_ref.clone(),
            binding_version: self.statement.binding_version,
            binding_hash: self.binding_hash,
        }
    }

    /// Verify exact sequential chain linkage to the prior immutable proof.
    pub fn verify_successor_of(
        &self,
        previous: &Self,
    ) -> Result<(), PrincipalAuthorityBindingError> {
        self.verify_intrinsic()?;
        previous.verify_intrinsic()?;
        if self.statement.principal_ref != previous.statement.principal_ref
            || self.statement.authority_kind != previous.statement.authority_kind
            || self.statement.binding_version != previous.statement.binding_version + 1
            || self.statement.previous_binding_ref.as_deref() != Some(previous.binding_ref.as_str())
            || self.statement.previous_binding_hash != Some(previous.binding_hash)
        {
            return Err(invalid(
                "binding successor does not name the exact prior ref/version/hash",
            ));
        }
        if self.statement.status == PrincipalAuthorityBindingStatus::Revoked
            && (self.statement.authority_id != previous.statement.authority_id
                || self.statement.authority_public_key != previous.statement.authority_public_key
                || self.statement.authority_signature_suite
                    != previous.statement.authority_signature_suite
                || self.statement.approval_authority_snapshot_hash
                    != previous.statement.approval_authority_snapshot_hash)
        {
            return Err(invalid(
                "revocation successor must retain the exact prior authority snapshot",
            ));
        }
        Ok(())
    }
}

/// Exact immutable coordinates consumed by downstream governed-intent replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PrincipalAuthorityBindingCoordinates {
    /// Content-addressed immutable proof reference.
    pub binding_ref: String,
    /// Monotonic version in the exact principal's chain.
    pub binding_version: u64,
    /// Immutable proof content hash.
    pub binding_hash: [u8; 32],
}

/// Mutable current-head pointer over an append-only proof chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PrincipalAuthorityBindingHeadV1 {
    /// Head-record schema version.
    pub schema_version: u16,
    /// Exact principal whose current head this record names.
    pub principal_ref: String,
    /// Authority family represented by the chain.
    pub authority_kind: PrincipalAuthorityKind,
    /// Exact current immutable proof coordinates.
    pub coordinates: PrincipalAuthorityBindingCoordinates,
    /// Current lifecycle state.
    pub status: PrincipalAuthorityBindingStatus,
    /// Wallet mutation timestamp in milliseconds.
    pub updated_at_ms: u64,
    /// Exact audit sequence whose state key commits the mutation event.
    pub mutation_audit_seq: u64,
    /// Audit event identifier for the mutation that installed this head.
    pub mutation_audit_event_id: [u8; 32],
    /// Audit event hash for the mutation that installed this head.
    pub mutation_audit_event_hash: [u8; 32],
}

/// Verified current resolution returned by wallet.network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PrincipalAuthorityResolutionV1 {
    /// Resolution artifact schema version.
    pub schema_version: u16,
    /// Exact canonical principal that was resolved.
    pub principal_ref: String,
    /// Resolved authority family.
    pub authority_kind: PrincipalAuthorityKind,
    /// Exact immutable coordinates verified as current.
    pub coordinates: PrincipalAuthorityBindingCoordinates,
    /// Exact operation scope the caller required.
    pub required_scope: String,
    /// Exact ApprovalAuthority allowlist entry matched by the canonical matcher.
    pub matched_scope: String,
    /// Complete registered authority snapshot whose hash is frozen in the binding proof.
    pub approval_authority: ApprovalAuthority,
    /// Resolved approval-authority identifier.
    pub authority_id: [u8; 32],
    /// Resolved approval-authority public key.
    pub authority_public_key: Vec<u8>,
    /// Resolved approval-authority signature suite.
    pub authority_signature_suite: SignatureSuite,
    /// Frozen ApprovalAuthority registry artifact hash.
    pub approval_authority_snapshot_hash: [u8; 32],
    /// Wallet resolution timestamp in milliseconds.
    pub resolved_at_ms: u64,
    /// Audit event identifier for the mutation that installed the current head.
    pub mutation_audit_event_id: [u8; 32],
    /// Audit event hash for the mutation that installed the current head.
    pub mutation_audit_event_hash: [u8; 32],
}

/// Request to append an initial or rotated active binding proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct IssuePrincipalAuthorityBindingParams {
    /// Complete root-signed immutable proof to append.
    pub proof: PrincipalAuthorityBindingProofV1,
}

/// Request to append a revoked successor to a binding chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct RevokePrincipalAuthorityBindingParams {
    /// Exact current binding ref that the revocation proof must name as its predecessor.
    pub predecessor_binding_ref: String,
    /// Complete root-signed immutable revocation proof.
    pub proof: PrincipalAuthorityBindingProofV1,
}

/// Request to resolve the current active authority for an exact principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ResolvePrincipalAuthorityParams {
    /// Nonzero id used to commit a single lookup receipt.
    pub request_id: [u8; 32],
    /// Exact canonical principal to resolve.
    pub principal_ref: String,
    /// Requested authority family.
    pub authority_kind: PrincipalAuthorityKind,
    /// Exact operation scope that the resolved ApprovalAuthority must allow.
    pub required_scope: String,
    /// Optional coordinates that must still be the exact current head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_coordinates: Option<PrincipalAuthorityBindingCoordinates>,
}

/// Durable receipt containing one verified principal-authority resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PrincipalAuthorityResolutionReceipt {
    /// Lookup request identifier.
    pub request_id: [u8; 32],
    /// Wallet resolution timestamp in milliseconds.
    pub resolved_at_ms: u64,
    /// Verified resolution result.
    pub resolution: PrincipalAuthorityResolutionV1,
}

/// Request to retrieve one immutable proof by content-addressed ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LookupPrincipalAuthorityBindingParams {
    /// Nonzero id used to commit a single lookup receipt.
    pub request_id: [u8; 32],
    /// Canonical immutable binding reference.
    pub binding_ref: String,
    /// Optional expected content hash for exact replay pinning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_binding_hash: Option<[u8; 32]>,
}

/// Durable receipt containing one immutable binding proof lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LookupPrincipalAuthorityBindingReceipt {
    /// Lookup request identifier.
    pub request_id: [u8; 32],
    /// Wallet lookup timestamp in milliseconds.
    pub fetched_at_ms: u64,
    /// Retrieved and integrity-checked immutable proof.
    pub proof: PrincipalAuthorityBindingProofV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
    use ioi_crypto::sign::eddsa::{
        Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
    };
    use std::collections::BTreeMap;

    fn keypair(seed: u8) -> Ed25519KeyPair {
        let private_key = Ed25519PrivateKey::from_bytes(&[seed; 32]).expect("private key");
        Ed25519KeyPair::from_private_key(&private_key).expect("keypair")
    }

    fn make_root(seed: u8) -> (WalletControlPlaneRootRecord, Ed25519KeyPair) {
        let keypair = keypair(seed);
        let public_key = keypair.public_key().to_bytes();
        let account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &public_key).expect("root id");
        (
            WalletControlPlaneRootRecord {
                account_id,
                signature_suite: SignatureSuite::ED25519,
                public_key,
                registered_at_ms: 1_700_000_000_000,
                updated_at_ms: 1_700_000_000_000,
                metadata: BTreeMap::new(),
            },
            keypair,
        )
    }

    fn make_authority(seed: u8) -> ApprovalAuthority {
        let keypair = keypair(seed);
        let public_key = keypair.public_key().to_bytes();
        let authority_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .expect("authority id");
        ApprovalAuthority {
            schema_version: 1,
            authority_id,
            public_key,
            signature_suite: SignatureSuite::ED25519,
            expires_at: 1_900_000_000_000,
            revoked: false,
            scope_allowlist: vec!["room_participation.admit".to_string()],
        }
    }

    fn statement(
        root: &WalletControlPlaneRootRecord,
        authority: &ApprovalAuthority,
        principal_ref: &str,
        version: u64,
        status: PrincipalAuthorityBindingStatus,
        previous: Option<&PrincipalAuthorityBindingProofV1>,
    ) -> PrincipalAuthorityBindingStatementV1 {
        PrincipalAuthorityBindingStatementV1 {
            schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
            principal_ref: principal_ref.to_string(),
            authority_kind: PrincipalAuthorityKind::Approval,
            binding_version: version,
            status,
            authority_id: authority.authority_id,
            authority_public_key: authority.public_key.clone(),
            authority_signature_suite: authority.signature_suite,
            approval_authority_snapshot_hash: authority.artifact_hash().expect("snapshot hash"),
            previous_binding_ref: previous.map(|proof| proof.binding_ref.clone()),
            previous_binding_hash: previous.map(|proof| proof.binding_hash),
            signed_at_ms: 1_700_000_000_000 + version,
            expires_at_ms: Some(1_800_000_000_000),
            issuer_root_account_id: root.account_id,
            reason: match status {
                PrincipalAuthorityBindingStatus::Active => None,
                PrincipalAuthorityBindingStatus::Revoked => Some("operator revocation".to_string()),
            },
        }
    }

    fn signed_proof(
        statement: PrincipalAuthorityBindingStatementV1,
        root_keypair: &Ed25519KeyPair,
    ) -> PrincipalAuthorityBindingProofV1 {
        let message = statement.signing_bytes().expect("signing bytes");
        let signature = root_keypair.sign(&message).expect("sign").to_bytes();
        PrincipalAuthorityBindingProofV1::new(
            statement,
            SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: root_keypair.public_key().to_bytes(),
                signature,
            },
        )
        .expect("proof")
    }

    fn protocol_fixture_material() -> (
        WalletControlPlaneRootRecord,
        ApprovalAuthority,
        PrincipalAuthorityBindingProofV1,
        PrincipalAuthorityBindingProofV1,
        ResolvePrincipalAuthorityParams,
        PrincipalAuthorityResolutionV1,
    ) {
        let (root, root_keypair) = make_root(7);
        let authority = make_authority(9);
        let active_statement = PrincipalAuthorityBindingStatementV1 {
            schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
            principal_ref: "agentgres://domain/acme.example".to_string(),
            authority_kind: PrincipalAuthorityKind::Approval,
            binding_version: 1,
            status: PrincipalAuthorityBindingStatus::Active,
            authority_id: authority.authority_id,
            authority_public_key: authority.public_key.clone(),
            authority_signature_suite: authority.signature_suite,
            approval_authority_snapshot_hash: authority.artifact_hash().expect("snapshot hash"),
            previous_binding_ref: None,
            previous_binding_hash: None,
            signed_at_ms: 1_781_286_400_000,
            expires_at_ms: Some(1_812_822_400_000),
            issuer_root_account_id: root.account_id,
            reason: None,
        };
        let active = signed_proof(active_statement, &root_keypair);
        let revoked_statement = PrincipalAuthorityBindingStatementV1 {
            schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
            principal_ref: active.statement.principal_ref.clone(),
            authority_kind: active.statement.authority_kind,
            binding_version: 2,
            status: PrincipalAuthorityBindingStatus::Revoked,
            authority_id: active.statement.authority_id,
            authority_public_key: active.statement.authority_public_key.clone(),
            authority_signature_suite: active.statement.authority_signature_suite,
            approval_authority_snapshot_hash: active.statement.approval_authority_snapshot_hash,
            previous_binding_ref: Some(active.binding_ref.clone()),
            previous_binding_hash: Some(active.binding_hash),
            signed_at_ms: 1_781_372_800_000,
            expires_at_ms: None,
            issuer_root_account_id: root.account_id,
            reason: Some("Approval authority rotated by the wallet control root.".to_string()),
        };
        let revoked = signed_proof(revoked_statement, &root_keypair);
        let request = ResolvePrincipalAuthorityParams {
            request_id: [22; 32],
            principal_ref: active.statement.principal_ref.clone(),
            authority_kind: active.statement.authority_kind,
            required_scope: "room_participation.admit".to_string(),
            expected_coordinates: Some(active.coordinates()),
        };
        let resolution = PrincipalAuthorityResolutionV1 {
            schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
            principal_ref: active.statement.principal_ref.clone(),
            authority_kind: active.statement.authority_kind,
            coordinates: active.coordinates(),
            required_scope: request.required_scope.clone(),
            matched_scope: "room_participation.admit".to_string(),
            approval_authority: authority.clone(),
            authority_id: active.statement.authority_id,
            authority_public_key: active.statement.authority_public_key.clone(),
            authority_signature_suite: active.statement.authority_signature_suite,
            approval_authority_snapshot_hash: active.statement.approval_authority_snapshot_hash,
            resolved_at_ms: 1_781_286_400_100,
            mutation_audit_event_id: [23; 32],
            mutation_audit_event_hash: [24; 32],
        };
        (root, authority, active, revoked, request, resolution)
    }

    fn verify_ed25519(
        suite: SignatureSuite,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        if suite != SignatureSuite::ED25519 {
            return Err("unsupported suite".to_string());
        }
        let public_key = Ed25519PublicKey::from_bytes(public_key).map_err(|e| e.to_string())?;
        let signature = Ed25519Signature::from_bytes(signature).map_err(|e| e.to_string())?;
        public_key
            .verify(message, &signature)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn principal_authority_ref_grammar_is_exact() {
        for accepted in [
            "worker://independent-alloy-lab",
            "service://solver_01",
            "service://sas/runtime-audit-weekly",
            "org://ioi.foundation",
            "domain://acme-host",
            "domain://marketplace/services",
            "agentgres://domain/acme.example",
            "agentgres://domain/hypervisor/local",
            "worker://alice@local",
            "worker://alice:local",
            "worker://alice~local",
        ] {
            validate_principal_authority_ref(accepted)
                .unwrap_or_else(|error| panic!("{accepted} should be canonical: {error}"));
        }

        for refused in [
            "",
            " worker://alice",
            "worker://alice ",
            "Worker://alice",
            "login://alice",
            "session://alice",
            "system://local",
            "agent://alice",
            "user://alice",
            "wallet://alice",
            "agentgres://alice",
            "agentgres://artifact/alice",
            "agentgres://domain/",
            "agentgres://domain//acme",
            "domain://acme/",
            "domain://./acme",
            "domain://acme/../admin",
            "worker://alice?admin=true",
            "worker://alice#root",
            "worker://ali*",
            "worker://ali%63e",
            "worker://alice\\admin",
            "worker://.alice",
            "worker://alice-",
        ] {
            assert!(
                validate_principal_authority_ref(refused).is_err(),
                "{refused} must be refused"
            );
        }
    }

    #[test]
    fn principal_authority_hashes_and_ref_are_stable() {
        let (root, root_keypair) = make_root(7);
        let authority = make_authority(9);
        let statement = statement(
            &root,
            &authority,
            "domain://acme-host",
            1,
            PrincipalAuthorityBindingStatus::Active,
            None,
        );
        let proof = signed_proof(statement.clone(), &root_keypair);
        let repeated = signed_proof(statement, &root_keypair);

        assert_eq!(proof, repeated, "Ed25519 + canonical JCS must be stable");
        assert_eq!(proof.statement_hash, repeated.statement_hash);
        assert_eq!(proof.binding_hash, repeated.binding_hash);
        assert_eq!(
            proof.binding_ref,
            format!(
                "{PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX}{}",
                lower_hex(&proof.binding_hash)
            )
        );
        assert_eq!(
            lower_hex(&proof.statement_hash),
            "fa5bf99fd2883d0ccb23c807d984c984930f5224691985bbcae2742779b173a5"
        );
        assert_eq!(
            lower_hex(&proof.binding_hash),
            "21302305661dd19c8aef596a7f3070385db58056a7372a3529863fa0460c2503"
        );
        assert_eq!(
            lower_hex(&authority.artifact_hash().expect("authority hash")),
            "d009e819160193b7280e7b41952538faa500cdf63f471848db57754c2f424b1f"
        );
    }

    #[test]
    fn wallet_protocol_fixture_is_a_rust_valid_cross_language_artifact() {
        let (root, authority, active, revoked, request, resolution) = protocol_fixture_material();
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packages/wallet-protocol/fixtures/wallet-protocol-fixtures.json"
        ));
        let fixture: serde_json::Value = serde_json::from_str(source).expect("protocol fixture");

        let fixture_active: PrincipalAuthorityBindingProofV1 =
            serde_json::from_value(fixture["principal_authority_binding_proof"].clone())
                .expect("active binding fixture");
        let fixture_revoked: PrincipalAuthorityBindingProofV1 =
            serde_json::from_value(fixture["principal_authority_revocation_proof"].clone())
                .expect("revocation fixture");
        let fixture_request: ResolvePrincipalAuthorityParams =
            serde_json::from_value(fixture["principal_authority_resolution_request"].clone())
                .expect("resolution request fixture");
        let fixture_resolution: PrincipalAuthorityResolutionV1 =
            serde_json::from_value(fixture["principal_authority_resolution"].clone())
                .expect("resolution fixture");

        assert_eq!(fixture_active, active);
        assert_eq!(fixture_revoked, revoked);
        assert_eq!(fixture_request, request);
        assert_eq!(fixture_resolution, resolution);
        fixture_active.verify_integrity().expect("active integrity");
        fixture_active
            .verify_root_signature_with(&root, verify_ed25519)
            .expect("active root signature");
        fixture_active
            .verify_authority_snapshot(&authority)
            .expect("active authority snapshot");
        fixture_revoked
            .verify_root_signature_with(&root, verify_ed25519)
            .expect("revocation root signature");
        fixture_revoked
            .verify_successor_of(&fixture_active)
            .expect("revocation coordinates and predecessor");
        assert_eq!(
            fixture_request.expected_coordinates,
            Some(fixture_active.coordinates())
        );
        assert_eq!(fixture_resolution.coordinates, fixture_active.coordinates());
    }

    #[test]
    fn principal_authority_proof_refuses_tampering_and_foreign_root() {
        let (root, root_keypair) = make_root(11);
        let authority = make_authority(12);
        let proof = signed_proof(
            statement(
                &root,
                &authority,
                "worker://alloy",
                1,
                PrincipalAuthorityBindingStatus::Active,
                None,
            ),
            &root_keypair,
        );
        proof.verify_integrity().expect("integrity");
        proof
            .verify_root_signature_with(&root, verify_ed25519)
            .expect("root signature");

        let mut tampered_statement = proof.clone();
        tampered_statement.statement.principal_ref = "worker://mallory".to_string();
        assert!(tampered_statement.verify_integrity().is_err());

        let mut tampered_hash = proof.clone();
        tampered_hash.binding_hash[0] ^= 0x80;
        assert!(tampered_hash.verify_integrity().is_err());

        let mut bad_signature = proof.issuer_signature_proof.clone();
        bad_signature.signature[0] ^= 0x01;
        let self_consistent_bad_signature =
            PrincipalAuthorityBindingProofV1::new(proof.statement.clone(), bad_signature)
                .expect("content-addressed proof");
        self_consistent_bad_signature
            .verify_integrity()
            .expect("content integrity is distinct from signature validity");
        assert!(self_consistent_bad_signature
            .verify_root_signature_with(&root, verify_ed25519)
            .is_err());

        let (foreign_root, foreign_keypair) = make_root(13);
        let foreign_proof = signed_proof(
            statement(
                &foreign_root,
                &authority,
                "worker://alloy",
                1,
                PrincipalAuthorityBindingStatus::Active,
                None,
            ),
            &foreign_keypair,
        );
        assert!(foreign_proof
            .verify_root_signature_with(&root, |_, _, _, _| {
                panic!("configured-root mismatch must refuse before crypto verification")
            })
            .is_err());
    }

    #[test]
    fn principal_authority_snapshot_binding_is_exact() {
        let (root, root_keypair) = make_root(21);
        let authority = make_authority(22);
        let proof = signed_proof(
            statement(
                &root,
                &authority,
                "service://verifier",
                1,
                PrincipalAuthorityBindingStatus::Active,
                None,
            ),
            &root_keypair,
        );
        proof
            .verify_authority_snapshot(&authority)
            .expect("exact snapshot");

        let mut drifted_scope = authority.clone();
        drifted_scope
            .scope_allowlist
            .push("extra.scope".to_string());
        assert!(proof.verify_authority_snapshot(&drifted_scope).is_err());

        let mut drifted_expiry = authority.clone();
        drifted_expiry.expires_at += 1;
        assert!(proof.verify_authority_snapshot(&drifted_expiry).is_err());

        let mut revoked = authority.clone();
        revoked.revoked = true;
        assert!(proof.verify_authority_snapshot(&revoked).is_err());

        let foreign_authority = make_authority(23);
        assert!(proof.verify_authority_snapshot(&foreign_authority).is_err());
    }

    #[test]
    fn principal_authority_active_verification_is_intrinsic_and_time_exact() {
        let (root, root_keypair) = make_root(24);
        let authority = make_authority(25);
        let proof = signed_proof(
            statement(
                &root,
                &authority,
                "service://time-verifier",
                1,
                PrincipalAuthorityBindingStatus::Active,
                None,
            ),
            &root_keypair,
        );
        let signed_at_ms = proof.statement.signed_at_ms;
        let expires_at_ms = proof.statement.expires_at_ms.expect("binding expiry");

        proof
            .verify_active_at(signed_at_ms)
            .expect("binding is active at its signed timestamp");
        proof
            .verify_active_at(expires_at_ms)
            .expect("expiry remains inclusive across the wallet ABI");
        assert!(proof.verify_active_at(signed_at_ms - 1).is_err());
        assert!(proof.verify_active_at(expires_at_ms + 1).is_err());

        let mut zero_signed_at = proof.clone();
        zero_signed_at.statement.signed_at_ms = 0;
        assert!(zero_signed_at.verify_active_at(signed_at_ms).is_err());

        let mut invalid_expiry = proof.clone();
        invalid_expiry.statement.expires_at_ms = Some(signed_at_ms);
        assert!(invalid_expiry.verify_active_at(signed_at_ms).is_err());

        let mut tampered = proof.clone();
        tampered.statement.principal_ref = "service://other-verifier".to_string();
        assert!(tampered.verify_active_at(signed_at_ms).is_err());
    }

    #[test]
    fn principal_authority_successor_and_revocation_semantics_are_exact() {
        let (root, root_keypair) = make_root(31);
        let authority = make_authority(32);
        let first = signed_proof(
            statement(
                &root,
                &authority,
                "org://alloy-lab",
                1,
                PrincipalAuthorityBindingStatus::Active,
                None,
            ),
            &root_keypair,
        );
        let revoked = signed_proof(
            statement(
                &root,
                &authority,
                "org://alloy-lab",
                2,
                PrincipalAuthorityBindingStatus::Revoked,
                Some(&first),
            ),
            &root_keypair,
        );
        revoked
            .verify_successor_of(&first)
            .expect("exact revocation successor");
        assert!(revoked.verify_active_at(1_700_000_000_100).is_err());

        let mut skipped_statement = statement(
            &root,
            &authority,
            "org://alloy-lab",
            3,
            PrincipalAuthorityBindingStatus::Active,
            Some(&first),
        );
        skipped_statement.reason = Some("rotation".to_string());
        let skipped = signed_proof(skipped_statement, &root_keypair);
        assert!(skipped.verify_successor_of(&first).is_err());

        let replacement = make_authority(33);
        let rotation = signed_proof(
            statement(
                &root,
                &replacement,
                "org://alloy-lab",
                2,
                PrincipalAuthorityBindingStatus::Active,
                Some(&first),
            ),
            &root_keypair,
        );
        rotation
            .verify_successor_of(&first)
            .expect("active rotation may change the exact authority snapshot");

        let bad_revocation = signed_proof(
            statement(
                &root,
                &replacement,
                "org://alloy-lab",
                2,
                PrincipalAuthorityBindingStatus::Revoked,
                Some(&first),
            ),
            &root_keypair,
        );
        assert!(bad_revocation.verify_successor_of(&first).is_err());

        let mut malformed_initial = first.statement.clone();
        malformed_initial.previous_binding_ref = Some(first.binding_ref.clone());
        malformed_initial.previous_binding_hash = Some(first.binding_hash);
        assert!(malformed_initial.verify_intrinsic().is_err());
    }

    #[test]
    fn principal_authority_coordinates_are_exact_even_for_the_same_key() {
        let (root, root_keypair) = make_root(41);
        let authority = make_authority(42);
        let first = signed_proof(
            statement(
                &root,
                &authority,
                "agentgres://domain/acme",
                1,
                PrincipalAuthorityBindingStatus::Active,
                None,
            ),
            &root_keypair,
        );
        let second = signed_proof(
            statement(
                &root,
                &authority,
                "agentgres://domain/acme",
                2,
                PrincipalAuthorityBindingStatus::Active,
                Some(&first),
            ),
            &root_keypair,
        );
        second
            .verify_successor_of(&first)
            .expect("same-key successor");

        let expected = first.coordinates();
        assert_eq!(
            hash_from_binding_ref(&expected.binding_ref).unwrap(),
            expected.binding_hash
        );
        assert_ne!(
            expected,
            second.coordinates(),
            "a newer head must refuse stale expected coordinates even with the same key"
        );
        let mut wrong_version = expected.clone();
        wrong_version.binding_version += 1;
        assert_ne!(wrong_version, expected);
        let mut wrong_hash = expected.clone();
        wrong_hash.binding_hash[0] ^= 1;
        assert_ne!(wrong_hash, expected);
        let mut wrong_ref = expected.clone();
        wrong_ref.binding_ref.replace_range(
            PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX.len()
                ..PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX.len() + 1,
            "f",
        );
        assert_ne!(wrong_ref, expected);
    }
}
