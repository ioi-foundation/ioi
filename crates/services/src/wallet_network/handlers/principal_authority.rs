use crate::agentic::runtime::kernel::approval::{ApprovalScopeContext, AuthorityScopeMatcher};
use crate::wallet_network::handlers::client_auth::{
    ensure_control_root_signer, ensure_initialized_wallet_client_role, load_control_root,
    WalletAuthRole,
};
use crate::wallet_network::keys::{
    audit_key, principal_authority_binding_head_key, principal_authority_binding_key,
    principal_authority_latest_mutation_key, principal_authority_lookup_receipt_key,
    principal_authority_resolution_receipt_key, principal_authority_version_index_key,
};
use crate::wallet_network::support::{
    append_audit_event_with_records, base_audit_metadata, block_timestamp_ms, hash_bytes,
    load_typed, verify_audit_event_at_seq,
};
use crate::wallet_network::validation::{
    load_registered_approval_authority, verify_wallet_signature_proof,
};
use crate::wallet_network::ExpectedPrincipalAuthorityBinding;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::action::ApprovalAuthority;
use ioi_types::app::wallet_network::{
    validate_principal_authority_ref, IssuePrincipalAuthorityBindingParams,
    LookupPrincipalAuthorityBindingParams, LookupPrincipalAuthorityBindingReceipt,
    PrincipalAuthorityBindingCoordinates, PrincipalAuthorityBindingHeadV1,
    PrincipalAuthorityBindingProofV1, PrincipalAuthorityBindingStatus, PrincipalAuthorityKind,
    PrincipalAuthorityResolutionReceipt, PrincipalAuthorityResolutionV1,
    ResolvePrincipalAuthorityParams, RevokePrincipalAuthorityBindingParams, VaultAuditEvent,
    VaultAuditEventKind, WalletControlPlaneRootRecord, PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX,
    PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
};
use ioi_types::app::SignatureProof;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use std::collections::{BTreeMap, BTreeSet};

const MAX_BINDING_CHAIN_DEPTH: u64 = 4_096;
const MAX_ACTIVE_BINDING_VERSION: u64 = MAX_BINDING_CHAIN_DEPTH - 1;

/// Wallet-owned O(1) proof of the latest mutation for one exact principal.
/// It is committed in the same state batch as the proof, head, and audit event.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct PrincipalAuthorityLatestMutationV1 {
    schema_version: u16,
    principal_ref_hash: [u8; 32],
    principal_ref: String,
    authority_kind: PrincipalAuthorityKind,
    coordinates: PrincipalAuthorityBindingCoordinates,
    status: PrincipalAuthorityBindingStatus,
    updated_at_ms: u64,
    mutation_audit_seq: u64,
    mutation_audit_event_id: [u8; 32],
    mutation_audit_event_hash: [u8; 32],
}

/// Immutable coordinates for one principal chain version. Unlike the mutable
/// head and latest-mutation marker, prior entries are never rewritten.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct PrincipalAuthorityVersionIndexV1 {
    schema_version: u16,
    principal_ref_hash: [u8; 32],
    principal_ref: String,
    authority_kind: PrincipalAuthorityKind,
    coordinates: PrincipalAuthorityBindingCoordinates,
    status: PrincipalAuthorityBindingStatus,
    mutation_audit_seq: u64,
    mutation_audit_event_id: [u8; 32],
    mutation_audit_event_hash: [u8; 32],
}

fn invalid(code: &str, detail: impl AsRef<str>) -> TransactionError {
    TransactionError::Invalid(format!("{code}: {}", detail.as_ref()))
}

fn validate_binding_chain_depth(binding_version: u64) -> Result<(), TransactionError> {
    if binding_version > MAX_BINDING_CHAIN_DEPTH {
        return Err(invalid(
            "principal_authority_binding_chain_too_deep",
            format!(
                "binding version {binding_version} exceeds the verification bound {MAX_BINDING_CHAIN_DEPTH}"
            ),
        ));
    }
    Ok(())
}

fn validate_binding_version_status(
    binding_version: u64,
    status: PrincipalAuthorityBindingStatus,
) -> Result<(), TransactionError> {
    validate_binding_chain_depth(binding_version)?;
    if status == PrincipalAuthorityBindingStatus::Active
        && binding_version > MAX_ACTIVE_BINDING_VERSION
    {
        return Err(invalid(
            "principal_authority_terminal_revocation_reserved",
            format!(
                "binding version {MAX_BINDING_CHAIN_DEPTH} is reserved for terminal revocation"
            ),
        ));
    }
    Ok(())
}

fn validate_required_scope(required_scope: &str) -> Result<(), TransactionError> {
    let bytes = required_scope.as_bytes();
    if required_scope.is_empty()
        || required_scope.len() > 256
        || required_scope != required_scope.trim()
        || required_scope != required_scope.to_ascii_lowercase()
        || !required_scope.is_ascii()
        || required_scope.bytes().any(|byte| byte.is_ascii_control())
        || !bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return Err(invalid(
            "principal_authority_required_scope_invalid",
            "required_scope must be an exact lowercase ASCII operation label",
        ));
    }
    Ok(())
}

fn ensure_nonzero_request_id(request_id: &[u8; 32]) -> Result<(), TransactionError> {
    if request_id == &[0u8; 32] {
        return Err(invalid(
            "principal_authority_request_id_invalid",
            "request_id must not be all zeroes",
        ));
    }
    Ok(())
}

fn principal_ref_hash(principal_ref: &str) -> Result<[u8; 32], TransactionError> {
    validate_principal_authority_ref(principal_ref).map_err(|error| {
        invalid(
            "principal_authority_principal_ref_invalid",
            error.to_string(),
        )
    })?;
    hash_bytes(principal_ref.as_bytes())
}

fn binding_hash_from_ref(binding_ref: &str) -> Result<[u8; 32], TransactionError> {
    let encoded = binding_ref
        .strip_prefix(PRINCIPAL_AUTHORITY_BINDING_REF_PREFIX)
        .ok_or_else(|| {
            invalid(
                "principal_authority_binding_ref_invalid",
                "binding_ref has the wrong canonical prefix",
            )
        })?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "principal_authority_binding_ref_invalid",
            "binding_ref must end in one lowercase 32-byte hex digest",
        ));
    }
    if encoded.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(invalid(
            "principal_authority_binding_ref_invalid",
            "binding_ref digest must use lowercase hex",
        ));
    }
    let decoded = hex::decode(encoded).map_err(|error| {
        invalid(
            "principal_authority_binding_ref_invalid",
            format!("binding_ref digest is invalid: {error}"),
        )
    })?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&decoded);
    Ok(hash)
}

fn validate_coordinates(
    coordinates: &PrincipalAuthorityBindingCoordinates,
) -> Result<(), TransactionError> {
    if coordinates.binding_version == 0 {
        return Err(invalid(
            "principal_authority_binding_coordinates_invalid",
            "binding_version must be at least 1",
        ));
    }
    if binding_hash_from_ref(&coordinates.binding_ref)? != coordinates.binding_hash {
        return Err(invalid(
            "principal_authority_binding_coordinates_invalid",
            "binding_ref does not encode binding_hash",
        ));
    }
    Ok(())
}

fn expected_latest_mutation(
    principal_ref_hash: [u8; 32],
    head: &PrincipalAuthorityBindingHeadV1,
) -> PrincipalAuthorityLatestMutationV1 {
    PrincipalAuthorityLatestMutationV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref_hash,
        principal_ref: head.principal_ref.clone(),
        authority_kind: head.authority_kind,
        coordinates: head.coordinates.clone(),
        status: head.status,
        updated_at_ms: head.updated_at_ms,
        mutation_audit_seq: head.mutation_audit_seq,
        mutation_audit_event_id: head.mutation_audit_event_id,
        mutation_audit_event_hash: head.mutation_audit_event_hash,
    }
}

fn expected_version_index(
    principal_ref_hash: [u8; 32],
    head: &PrincipalAuthorityBindingHeadV1,
) -> PrincipalAuthorityVersionIndexV1 {
    PrincipalAuthorityVersionIndexV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref_hash,
        principal_ref: head.principal_ref.clone(),
        authority_kind: head.authority_kind,
        coordinates: head.coordinates.clone(),
        status: head.status,
        mutation_audit_seq: head.mutation_audit_seq,
        mutation_audit_event_id: head.mutation_audit_event_id,
        mutation_audit_event_hash: head.mutation_audit_event_hash,
    }
}

fn load_version_index(
    state: &dyn StateAccess,
    principal_ref_hash: [u8; 32],
    binding_version: u64,
) -> Result<Option<PrincipalAuthorityVersionIndexV1>, TransactionError> {
    let key = principal_authority_version_index_key(&principal_ref_hash, binding_version);
    let Some(bytes) = state.get(&key)? else {
        return Ok(None);
    };
    let index = codec::from_bytes_canonical(&bytes).map_err(|error| {
        invalid(
            "principal_authority_version_index_malformed",
            error.to_string(),
        )
    })?;
    Ok(Some(index))
}

fn validate_version_index_head(
    state: &dyn StateAccess,
    principal_ref_hash: [u8; 32],
    head: &PrincipalAuthorityBindingHeadV1,
) -> Result<(), TransactionError> {
    let index = load_version_index(state, principal_ref_hash, head.coordinates.binding_version)?
        .ok_or_else(|| {
            invalid(
                "principal_authority_version_index_missing",
                "current head has no immutable version-index entry",
            )
        })?;
    if index.schema_version != PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION
        || index.principal_ref_hash != principal_ref_hash
        || index.principal_ref != head.principal_ref
    {
        return Err(invalid(
            "principal_authority_version_index_relocated",
            "version-index entry belongs to a different principal key or ref",
        ));
    }
    if index != expected_version_index(principal_ref_hash, head) {
        return Err(invalid(
            "principal_authority_version_index_mismatch",
            "current head does not exactly match its immutable version-index entry",
        ));
    }
    let next_version = head
        .coordinates
        .binding_version
        .checked_add(1)
        .ok_or_else(|| {
            invalid(
                "principal_authority_binding_version_overflow",
                "version overflow",
            )
        })?;
    if state
        .get(&principal_authority_version_index_key(
            &principal_ref_hash,
            next_version,
        ))?
        .is_some()
    {
        return Err(invalid(
            "principal_authority_binding_head_rolled_back",
            "a later immutable version-index entry exists for this principal",
        ));
    }
    Ok(())
}

fn validate_latest_mutation_commitment(
    state: &dyn StateAccess,
    principal_ref_hash: [u8; 32],
    head: &PrincipalAuthorityBindingHeadV1,
) -> Result<(), TransactionError> {
    let key = principal_authority_latest_mutation_key(&principal_ref_hash);
    let bytes = state.get(&key)?.ok_or_else(|| {
        invalid(
            "principal_authority_latest_mutation_missing",
            "current head has no wallet-owned latest-mutation commitment",
        )
    })?;
    let commitment: PrincipalAuthorityLatestMutationV1 = codec::from_bytes_canonical(&bytes)
        .map_err(|error| {
            invalid(
                "principal_authority_latest_mutation_malformed",
                error.to_string(),
            )
        })?;
    if commitment.schema_version != PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION {
        return Err(invalid(
            "principal_authority_latest_mutation_malformed",
            "latest-mutation commitment uses an unsupported schema",
        ));
    }
    if commitment.principal_ref_hash != principal_ref_hash
        || commitment.principal_ref != head.principal_ref
    {
        return Err(invalid(
            "principal_authority_latest_mutation_relocated",
            "latest-mutation commitment belongs to a different principal key or ref",
        ));
    }
    if commitment != expected_latest_mutation(principal_ref_hash, head) {
        return Err(invalid(
            "principal_authority_latest_mutation_mismatch",
            "current head does not exactly match the wallet-owned latest mutation",
        ));
    }
    Ok(())
}

fn validate_head_audit_commitment(
    state: &dyn StateAccess,
    head: &PrincipalAuthorityBindingHeadV1,
) -> Result<(), TransactionError> {
    let event: VaultAuditEvent = load_typed(state, &audit_key(head.mutation_audit_seq))?
        .ok_or_else(|| {
            invalid(
                "principal_authority_binding_head_audit_missing",
                "head mutation audit sequence points to no stored event",
            )
        })?;
    verify_audit_event_at_seq(&event, head.mutation_audit_seq).map_err(|error| {
        invalid(
            "principal_authority_binding_head_audit_invalid",
            error.to_string(),
        )
    })?;
    let expected_kind = match head.status {
        PrincipalAuthorityBindingStatus::Active => {
            VaultAuditEventKind::PrincipalAuthorityBindingIssued
        }
        PrincipalAuthorityBindingStatus::Revoked => {
            VaultAuditEventKind::PrincipalAuthorityBindingRevoked
        }
    };
    if event.event_id != head.mutation_audit_event_id
        || event.event_hash != head.mutation_audit_event_hash
        || event.timestamp_ms != head.updated_at_ms
        || event.kind != expected_kind
    {
        return Err(invalid(
            "principal_authority_binding_head_audit_invalid",
            "stored mutation event does not match the head sequence/id/hash/timestamp/kind commitment",
        ));
    }

    let proof = load_proof_by_hash(state, &head.coordinates.binding_hash)?.ok_or_else(|| {
        invalid(
            "principal_authority_binding_proof_missing",
            "current head points to no immutable proof",
        )
    })?;
    if proof.coordinates() != head.coordinates
        || proof.statement.principal_ref != head.principal_ref
        || proof.statement.authority_kind != head.authority_kind
        || proof.statement.status != head.status
    {
        return Err(invalid(
            "principal_authority_binding_head_invalid",
            "head and immutable proof disagree before audit validation",
        ));
    }
    let expected_metadata = BTreeMap::from([
        (
            "authority_id".to_string(),
            hex::encode(proof.statement.authority_id),
        ),
        (
            "binding_hash".to_string(),
            hex::encode(head.coordinates.binding_hash),
        ),
        (
            "binding_ref".to_string(),
            head.coordinates.binding_ref.clone(),
        ),
        (
            "binding_version".to_string(),
            head.coordinates.binding_version.to_string(),
        ),
        ("principal_ref".to_string(), head.principal_ref.clone()),
        (
            "signer_account_id".to_string(),
            hex::encode(proof.statement.issuer_root_account_id),
        ),
    ]);
    let mut committed_metadata = event.metadata.clone();
    committed_metadata.remove("seq");
    committed_metadata.remove("prev_hash");
    if committed_metadata != expected_metadata {
        return Err(invalid(
            "principal_authority_binding_head_audit_invalid",
            "stored mutation event metadata does not exactly describe the bound proof and issuer",
        ));
    }

    Ok(())
}

fn load_head(
    state: &dyn StateAccess,
    principal_ref: &str,
) -> Result<Option<PrincipalAuthorityBindingHeadV1>, TransactionError> {
    let principal_hash = principal_ref_hash(principal_ref)?;
    let head_key = principal_authority_binding_head_key(&principal_hash);
    let latest_mutation_key = principal_authority_latest_mutation_key(&principal_hash);
    let Some(head_bytes) = state.get(&head_key)? else {
        if state.get(&latest_mutation_key)?.is_some() {
            return Err(invalid(
                "principal_authority_latest_mutation_orphaned",
                "latest-mutation commitment survives without its current head",
            ));
        }
        if state
            .get(&principal_authority_version_index_key(&principal_hash, 1))?
            .is_some()
        {
            return Err(invalid(
                "principal_authority_version_index_orphaned",
                "immutable version-index history survives without its current head",
            ));
        }
        return Ok(None);
    };
    let head: PrincipalAuthorityBindingHeadV1 =
        codec::from_bytes_canonical(&head_bytes).map_err(|error| {
            invalid(
                "principal_authority_binding_head_malformed",
                error.to_string(),
            )
        })?;
    if head.schema_version != PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION
        || head.principal_ref != principal_ref
        || head.authority_kind != PrincipalAuthorityKind::Approval
    {
        return Err(invalid(
            "principal_authority_binding_head_invalid",
            "current head is relocated, unsupported, or names a different principal",
        ));
    }
    if head.updated_at_ms == 0
        || head.mutation_audit_event_id == [0u8; 32]
        || head.mutation_audit_event_hash == [0u8; 32]
    {
        return Err(invalid(
            "principal_authority_binding_head_audit_invalid",
            "current head lacks nonzero mutation timestamp/id/hash evidence",
        ));
    }
    validate_coordinates(&head.coordinates)?;
    validate_binding_version_status(head.coordinates.binding_version, head.status)?;
    validate_latest_mutation_commitment(state, principal_hash, &head)?;
    validate_version_index_head(state, principal_hash, &head)?;
    validate_head_audit_commitment(state, &head)?;
    Ok(Some(head))
}

fn load_proof_by_hash(
    state: &dyn StateAccess,
    binding_hash: &[u8; 32],
) -> Result<Option<PrincipalAuthorityBindingProofV1>, TransactionError> {
    load_typed(state, &principal_authority_binding_key(binding_hash))
}

fn load_head_proof(
    state: &dyn StateAccess,
    head: &PrincipalAuthorityBindingHeadV1,
) -> Result<PrincipalAuthorityBindingProofV1, TransactionError> {
    let proof = load_proof_by_hash(state, &head.coordinates.binding_hash)?.ok_or_else(|| {
        invalid(
            "principal_authority_binding_proof_missing",
            "current head points to no immutable proof",
        )
    })?;
    proof.verify_integrity().map_err(|error| {
        invalid(
            "principal_authority_binding_proof_invalid",
            error.to_string(),
        )
    })?;
    if proof.coordinates() != head.coordinates
        || proof.statement.principal_ref != head.principal_ref
        || proof.statement.authority_kind != head.authority_kind
        || proof.statement.status != head.status
    {
        return Err(invalid(
            "principal_authority_binding_head_invalid",
            "current head and immutable proof disagree",
        ));
    }
    Ok(proof)
}

fn validate_root_signature(
    proof: &PrincipalAuthorityBindingProofV1,
    root: &WalletControlPlaneRootRecord,
) -> Result<(), TransactionError> {
    proof
        .verify_root_signature_with(root, |suite, public_key, message, signature| {
            let signature_proof = SignatureProof {
                suite,
                public_key: public_key.to_vec(),
                signature: signature.to_vec(),
            };
            verify_wallet_signature_proof(&signature_proof, message, "principal-authority binding")
                .and_then(|signer_id| {
                    if signer_id == root.account_id {
                        Ok(())
                    } else {
                        Err(invalid(
                            "principal_authority_binding_root_mismatch",
                            "proof signer id does not match the configured wallet control root",
                        ))
                    }
                })
                .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            let message = error.to_string();
            let code = if message.contains("configured wallet root") {
                "principal_authority_binding_root_mismatch"
            } else if message.contains("unsupported") {
                "principal_authority_binding_signature_suite_unsupported"
            } else {
                "principal_authority_binding_proof_invalid"
            };
            invalid(code, message)
        })
}

fn load_current_authority(
    state: &dyn StateAccess,
    proof: &PrincipalAuthorityBindingProofV1,
    now_ms: u64,
    require_active: bool,
) -> Result<ApprovalAuthority, TransactionError> {
    let authority = load_registered_approval_authority(state, &proof.statement.authority_id)?
        .ok_or_else(|| {
            invalid(
                "principal_authority_approval_authority_unavailable",
                "bound approval authority is not registered",
            )
        })?;
    authority.verify().map_err(|error| {
        invalid(
            "principal_authority_approval_authority_invalid",
            error.to_string(),
        )
    })?;
    if authority.authority_id != proof.statement.authority_id
        || authority.public_key != proof.statement.authority_public_key
        || authority.signature_suite != proof.statement.authority_signature_suite
    {
        return Err(invalid(
            "principal_authority_approval_authority_drifted",
            "current approval-authority key tuple no longer matches the signed binding snapshot",
        ));
    }
    if require_active && authority.revoked {
        return Err(invalid(
            "principal_authority_approval_authority_revoked",
            "bound approval authority has been revoked",
        ));
    }
    if require_active && now_ms > authority.expires_at {
        return Err(invalid(
            "principal_authority_approval_authority_expired",
            "bound approval authority has expired",
        ));
    }
    proof
        .verify_authority_snapshot(&authority)
        .map_err(|error| {
            invalid(
                "principal_authority_approval_authority_drifted",
                error.to_string(),
            )
        })?;
    Ok(authority)
}

fn validate_binding_time(
    proof: &PrincipalAuthorityBindingProofV1,
    now_ms: u64,
    require_active: bool,
) -> Result<(), TransactionError> {
    if proof.statement.signed_at_ms == 0 || proof.statement.signed_at_ms > now_ms {
        return Err(invalid(
            "principal_authority_binding_time_invalid",
            "binding signed_at_ms must be non-zero and no later than wallet time",
        ));
    }
    if proof
        .statement
        .expires_at_ms
        .map(|expires_at| expires_at <= proof.statement.signed_at_ms)
        .unwrap_or(false)
    {
        return Err(invalid(
            "principal_authority_binding_time_invalid",
            "binding expiry must be later than signed_at_ms",
        ));
    }
    if require_active
        && proof
            .statement
            .expires_at_ms
            .map(|expires_at| now_ms > expires_at)
            .unwrap_or(false)
    {
        return Err(invalid(
            "principal_authority_binding_expired",
            "principal-authority binding has expired",
        ));
    }
    Ok(())
}

fn validate_proof(
    state: &dyn StateAccess,
    proof: &PrincipalAuthorityBindingProofV1,
    now_ms: u64,
    require_active_authority: bool,
) -> Result<ApprovalAuthority, TransactionError> {
    validate_binding_version_status(proof.statement.binding_version, proof.statement.status)?;
    validate_principal_authority_ref(&proof.statement.principal_ref).map_err(|error| {
        invalid(
            "principal_authority_principal_ref_invalid",
            error.to_string(),
        )
    })?;
    if proof.schema_version != PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION
        || proof.statement.schema_version != PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION
        || proof.statement.authority_kind != PrincipalAuthorityKind::Approval
    {
        return Err(invalid(
            "principal_authority_binding_schema_invalid",
            "binding proof uses an unsupported schema or authority kind",
        ));
    }
    let root = load_control_root(state)?.ok_or(TransactionError::UnauthorizedByCredentials)?;
    validate_root_signature(proof, &root)?;
    validate_binding_time(proof, now_ms, require_active_authority)?;
    load_current_authority(state, proof, now_ms, require_active_authority)
}

struct ValidatedCurrentPrincipalAuthority {
    head: PrincipalAuthorityBindingHeadV1,
    proof: PrincipalAuthorityBindingProofV1,
    authority: ApprovalAuthority,
    matched_scope: String,
    resolved_at_ms: u64,
}

fn validate_current_principal_authority(
    state: &dyn StateAccess,
    ctx: &TxContext<'_>,
    principal_ref: &str,
    required_scope: &str,
    expected_coordinates: Option<&PrincipalAuthorityBindingCoordinates>,
) -> Result<ValidatedCurrentPrincipalAuthority, TransactionError> {
    validate_principal_authority_ref(principal_ref).map_err(|error| {
        invalid(
            "principal_authority_principal_ref_invalid",
            error.to_string(),
        )
    })?;
    validate_required_scope(required_scope)?;
    let head = load_head(state, principal_ref)?.ok_or_else(|| {
        invalid(
            "principal_authority_binding_not_found",
            "no binding exists for the exact principal_ref",
        )
    })?;
    if expected_coordinates.is_some_and(|expected| expected != &head.coordinates) {
        return Err(invalid(
            "principal_authority_binding_coordinates_stale",
            "expected binding ref/version/hash do not match the current head",
        ));
    }
    if head.status != PrincipalAuthorityBindingStatus::Active {
        return Err(invalid(
            "principal_authority_binding_revoked",
            "current principal-authority binding is revoked",
        ));
    }
    let proof = load_head_proof(state, &head)?;
    let now_ms = block_timestamp_ms(ctx);
    let root = load_control_root(state)?.ok_or(TransactionError::UnauthorizedByCredentials)?;
    validate_binding_chain(state, &proof, &root)?;
    let authority = validate_proof(state, &proof, now_ms, true)?;
    let scope_context = ApprovalScopeContext::new(required_scope.to_string());
    let scope_decision = AuthorityScopeMatcher::evaluate(&authority, &scope_context);
    if !scope_decision.allowed {
        return Err(invalid(
            "principal_authority_scope_denied",
            scope_decision
                .reason
                .unwrap_or_else(|| "approval authority does not allow required_scope".to_string()),
        ));
    }
    let matched_scope = scope_decision.matched_scope.ok_or_else(|| {
        invalid(
            "principal_authority_scope_match_invalid",
            "canonical scope matcher allowed resolution without a matched allowlist entry",
        )
    })?;
    Ok(ValidatedCurrentPrincipalAuthority {
        head,
        proof,
        authority,
        matched_scope,
        resolved_at_ms: now_ms,
    })
}

pub(crate) fn validate_expected_principal_authority_binding(
    state: &dyn StateAccess,
    ctx: &TxContext<'_>,
    expected: &ExpectedPrincipalAuthorityBinding,
) -> Result<ApprovalAuthority, TransactionError> {
    let validated = validate_current_principal_authority(
        state,
        ctx,
        &expected.principal_ref,
        &expected.required_scope,
        Some(&expected.coordinates),
    )?;
    if validated.authority != expected.approval_authority
        || validated.proof.statement.approval_authority_snapshot_hash
            != expected.approval_authority_snapshot_hash
    {
        return Err(invalid(
            "principal_authority_snapshot_stale",
            "expected approval-authority snapshot does not match the current root-signed binding",
        ));
    }
    Ok(validated.authority)
}

fn validate_next_version(
    proof: &PrincipalAuthorityBindingProofV1,
    prior: Option<&PrincipalAuthorityBindingProofV1>,
) -> Result<(), TransactionError> {
    match prior {
        None => {
            if proof.statement.binding_version != 1
                || proof.statement.previous_binding_ref.is_some()
                || proof.statement.previous_binding_hash.is_some()
            {
                return Err(invalid(
                    "principal_authority_binding_cas_failed",
                    "first binding must be version 1 with no previous coordinates",
                ));
            }
        }
        Some(prior) => {
            proof.verify_successor_of(prior).map_err(|error| {
                invalid("principal_authority_binding_cas_failed", error.to_string())
            })?;
        }
    }
    Ok(())
}

/// Verify the complete append-only chain ending at `tip` without consulting
/// mutable approval-authority state. Every immutable predecessor must still be
/// present at its content-addressed key, signed by the exact configured root,
/// and linked by exact ref/hash/version coordinates.
fn validate_binding_chain(
    state: &dyn StateAccess,
    tip: &PrincipalAuthorityBindingProofV1,
    root: &WalletControlPlaneRootRecord,
) -> Result<(), TransactionError> {
    validate_binding_chain_depth(tip.statement.binding_version)?;

    let mut successor = tip.clone();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(successor.binding_hash) {
            return Err(invalid(
                "principal_authority_binding_chain_cycle",
                "binding chain repeats an immutable proof hash",
            ));
        }
        validate_root_signature(&successor, root)?;
        if successor.statement.binding_version == 1 {
            return Ok(());
        }

        let previous_hash = successor.statement.previous_binding_hash.ok_or_else(|| {
            invalid(
                "principal_authority_binding_chain_invalid",
                "successor omits previous_binding_hash",
            )
        })?;
        let previous_ref = successor
            .statement
            .previous_binding_ref
            .as_deref()
            .ok_or_else(|| {
                invalid(
                    "principal_authority_binding_chain_invalid",
                    "successor omits previous_binding_ref",
                )
            })?;
        if binding_hash_from_ref(previous_ref)? != previous_hash {
            return Err(invalid(
                "principal_authority_binding_chain_invalid",
                "previous_binding_ref does not encode previous_binding_hash",
            ));
        }
        let prior = load_proof_by_hash(state, &previous_hash)?.ok_or_else(|| {
            invalid(
                "principal_authority_binding_chain_missing",
                "an immutable predecessor proof is missing",
            )
        })?;
        validate_root_signature(&prior, root)?;
        successor.verify_successor_of(&prior).map_err(|error| {
            invalid(
                "principal_authority_binding_chain_invalid",
                error.to_string(),
            )
        })?;
        successor = prior;
    }
}

fn exact_replay(
    state: &dyn StateAccess,
    proof: &PrincipalAuthorityBindingProofV1,
    head: Option<&PrincipalAuthorityBindingHeadV1>,
) -> Result<bool, TransactionError> {
    let Some(existing) = load_proof_by_hash(state, &proof.binding_hash)? else {
        return Ok(false);
    };
    if existing != *proof {
        return Err(invalid(
            "principal_authority_binding_immutable_conflict",
            "content-addressed proof slot contains different bytes",
        ));
    }
    if let Some(head) = head {
        let current = load_head_proof(state, head)?;
        if current == *proof {
            return Ok(true);
        }
    }
    Err(invalid(
        "principal_authority_binding_stale_replay",
        "exact proof exists but is no longer the current head",
    ))
}

fn audit_metadata(proof: &PrincipalAuthorityBindingProofV1) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "principal_ref".to_string(),
        proof.statement.principal_ref.clone(),
    );
    metadata.insert("binding_ref".to_string(), proof.binding_ref.clone());
    metadata.insert("binding_hash".to_string(), hex::encode(proof.binding_hash));
    metadata.insert(
        "binding_version".to_string(),
        proof.statement.binding_version.to_string(),
    );
    metadata.insert(
        "authority_id".to_string(),
        hex::encode(proof.statement.authority_id),
    );
    metadata
}

fn commit_binding(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    proof: &PrincipalAuthorityBindingProofV1,
    audit_kind: VaultAuditEventKind,
) -> Result<(), TransactionError> {
    let principal_hash = principal_ref_hash(&proof.statement.principal_ref)?;
    let proof_key = principal_authority_binding_key(&proof.binding_hash);
    let head_key = principal_authority_binding_head_key(&principal_hash);
    let latest_mutation_key = principal_authority_latest_mutation_key(&principal_hash);
    let version_index_key =
        principal_authority_version_index_key(&principal_hash, proof.statement.binding_version);
    if state.get(&version_index_key)?.is_some() {
        return Err(invalid(
            "principal_authority_version_index_immutable_conflict",
            "binding version-index slot already exists and cannot be overwritten",
        ));
    }
    let mut metadata = base_audit_metadata(ctx);
    metadata.extend(audit_metadata(proof));
    let updated_at_ms = block_timestamp_ms(ctx);
    append_audit_event_with_records(state, ctx, audit_kind, metadata, |event| {
        let mutation_audit_seq = event
            .metadata
            .get("seq")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                invalid(
                    "principal_authority_binding_audit_invalid",
                    "new mutation audit event is missing its canonical sequence",
                )
            })?;
        let head = PrincipalAuthorityBindingHeadV1 {
            schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
            principal_ref: proof.statement.principal_ref.clone(),
            authority_kind: proof.statement.authority_kind,
            coordinates: proof.coordinates(),
            status: proof.statement.status,
            updated_at_ms,
            mutation_audit_seq,
            mutation_audit_event_id: event.event_id,
            mutation_audit_event_hash: event.event_hash,
        };
        let latest_mutation = expected_latest_mutation(principal_hash, &head);
        let version_index = expected_version_index(principal_hash, &head);
        Ok(vec![
            (proof_key, codec::to_bytes_canonical(proof)?),
            (head_key, codec::to_bytes_canonical(&head)?),
            (
                latest_mutation_key,
                codec::to_bytes_canonical(&latest_mutation)?,
            ),
            (
                version_index_key,
                codec::to_bytes_canonical(&version_index)?,
            ),
        ])
    })?;
    Ok(())
}

pub(crate) fn issue_principal_authority_binding(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: IssuePrincipalAuthorityBindingParams,
) -> Result<(), TransactionError> {
    ensure_control_root_signer(state, ctx)?;
    let proof = params.proof;
    if proof.statement.status != PrincipalAuthorityBindingStatus::Active {
        return Err(invalid(
            "principal_authority_binding_issue_status_invalid",
            "issue requires an active binding proof",
        ));
    }
    let now_ms = block_timestamp_ms(ctx);
    validate_proof(state, &proof, now_ms, true)?;
    let root = load_control_root(state)?.ok_or(TransactionError::UnauthorizedByCredentials)?;
    let head = load_head(state, &proof.statement.principal_ref)?;
    let prior = head
        .as_ref()
        .map(
            |head| -> Result<PrincipalAuthorityBindingProofV1, TransactionError> {
                let prior = load_head_proof(state, head)?;
                validate_binding_chain(state, &prior, &root)?;
                Ok(prior)
            },
        )
        .transpose()?;
    if exact_replay(state, &proof, head.as_ref())? {
        return Ok(());
    }
    validate_next_version(&proof, prior.as_ref())?;
    validate_binding_chain(state, &proof, &root)?;
    commit_binding(
        state,
        ctx,
        &proof,
        VaultAuditEventKind::PrincipalAuthorityBindingIssued,
    )
}

pub(crate) fn revoke_principal_authority_binding(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: RevokePrincipalAuthorityBindingParams,
) -> Result<(), TransactionError> {
    ensure_control_root_signer(state, ctx)?;
    let proof = params.proof;
    if proof.statement.previous_binding_ref.as_deref()
        != Some(params.predecessor_binding_ref.as_str())
    {
        return Err(invalid(
            "principal_authority_binding_predecessor_mismatch",
            "request predecessor_binding_ref does not exactly match the revocation proof",
        ));
    }
    if proof.statement.status != PrincipalAuthorityBindingStatus::Revoked {
        return Err(invalid(
            "principal_authority_binding_revoke_status_invalid",
            "revoke requires a revoked binding proof",
        ));
    }
    let now_ms = block_timestamp_ms(ctx);
    // Root/proof/time integrity is required, but an already revoked or expired
    // approval authority must never prevent the root from appending revocation.
    validate_principal_authority_ref(&proof.statement.principal_ref).map_err(|error| {
        invalid(
            "principal_authority_principal_ref_invalid",
            error.to_string(),
        )
    })?;
    let root = load_control_root(state)?.ok_or(TransactionError::UnauthorizedByCredentials)?;
    validate_root_signature(&proof, &root)?;
    validate_binding_time(&proof, now_ms, false)?;

    let head = load_head(state, &proof.statement.principal_ref)?.ok_or_else(|| {
        invalid(
            "principal_authority_binding_not_found",
            "there is no current binding to revoke",
        )
    })?;
    let prior = load_head_proof(state, &head)?;
    validate_binding_chain(state, &prior, &root)?;
    if exact_replay(state, &proof, Some(&head))? {
        return Ok(());
    }
    if head.coordinates.binding_ref != params.predecessor_binding_ref {
        return Err(invalid(
            "principal_authority_binding_cas_failed",
            "request predecessor_binding_ref is not the exact current head",
        ));
    }
    if head.status != PrincipalAuthorityBindingStatus::Active {
        return Err(invalid(
            "principal_authority_binding_already_revoked",
            "current binding head is not active",
        ));
    }
    validate_next_version(&proof, Some(&prior))?;
    validate_binding_chain(state, &proof, &root)?;
    commit_binding(
        state,
        ctx,
        &proof,
        VaultAuditEventKind::PrincipalAuthorityBindingRevoked,
    )
}

pub(crate) fn resolve_principal_authority(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ResolvePrincipalAuthorityParams,
) -> Result<(), TransactionError> {
    ensure_initialized_wallet_client_role(state, ctx, WalletAuthRole::Capability)?;
    ensure_nonzero_request_id(&params.request_id)?;
    if params.authority_kind != PrincipalAuthorityKind::Approval {
        return Err(invalid(
            "principal_authority_kind_unsupported",
            "only approval authority bindings are supported in v1",
        ));
    }
    let receipt_key = principal_authority_resolution_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(invalid(
            "principal_authority_request_id_replay",
            "resolution request_id has already been used",
        ));
    }
    let validated = validate_current_principal_authority(
        state,
        ctx,
        &params.principal_ref,
        &params.required_scope,
        params.expected_coordinates.as_ref(),
    )?;
    let head = validated.head;
    let proof = validated.proof;
    let authority = validated.authority;
    let resolution = PrincipalAuthorityResolutionV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: head.principal_ref.clone(),
        authority_kind: head.authority_kind,
        coordinates: head.coordinates.clone(),
        required_scope: params.required_scope.clone(),
        matched_scope: validated.matched_scope,
        approval_authority: authority.clone(),
        authority_id: authority.authority_id,
        authority_public_key: authority.public_key,
        authority_signature_suite: authority.signature_suite,
        approval_authority_snapshot_hash: proof.statement.approval_authority_snapshot_hash,
        resolved_at_ms: validated.resolved_at_ms,
        mutation_audit_event_id: head.mutation_audit_event_id,
        mutation_audit_event_hash: head.mutation_audit_event_hash,
    };
    let matched_scope = resolution.matched_scope.clone();
    let receipt = PrincipalAuthorityResolutionReceipt {
        request_id: params.request_id,
        resolved_at_ms: validated.resolved_at_ms,
        resolution,
    };
    let mut metadata = base_audit_metadata(ctx);
    metadata.insert("principal_ref".to_string(), params.principal_ref);
    metadata.insert("required_scope".to_string(), params.required_scope);
    metadata.insert("matched_scope".to_string(), matched_scope);
    metadata.insert(
        "binding_ref".to_string(),
        head.coordinates.binding_ref.clone(),
    );
    metadata.insert(
        "binding_version".to_string(),
        head.coordinates.binding_version.to_string(),
    );
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::PrincipalAuthorityBindingResolved,
        metadata,
        |_| Ok(vec![(receipt_key, codec::to_bytes_canonical(&receipt)?)]),
    )?;
    Ok(())
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn final_chain_slot_is_reserved_for_terminal_revocation() {
        validate_binding_version_status(
            MAX_ACTIVE_BINDING_VERSION,
            PrincipalAuthorityBindingStatus::Active,
        )
        .expect("the final active binding version remains admissible");
        validate_binding_version_status(
            MAX_BINDING_CHAIN_DEPTH,
            PrincipalAuthorityBindingStatus::Revoked,
        )
        .expect("the final chain slot admits terminal revocation");
        let active_error = validate_binding_version_status(
            MAX_BINDING_CHAIN_DEPTH,
            PrincipalAuthorityBindingStatus::Active,
        )
        .expect_err("the final slot must not become an active binding");
        assert!(active_error
            .to_string()
            .contains("terminal_revocation_reserved"));
        let error = validate_binding_version_status(
            MAX_BINDING_CHAIN_DEPTH + 1,
            PrincipalAuthorityBindingStatus::Revoked,
        )
        .expect_err("the first unresolvable binding version must fail before commit");
        assert!(error
            .to_string()
            .contains("principal_authority_binding_chain_too_deep"));
    }
}

pub(crate) fn lookup_principal_authority_binding(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: LookupPrincipalAuthorityBindingParams,
) -> Result<(), TransactionError> {
    ensure_initialized_wallet_client_role(state, ctx, WalletAuthRole::Capability)?;
    ensure_nonzero_request_id(&params.request_id)?;
    let receipt_key = principal_authority_lookup_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(invalid(
            "principal_authority_request_id_replay",
            "lookup request_id has already been used",
        ));
    }
    let binding_hash = binding_hash_from_ref(&params.binding_ref)?;
    if params
        .expected_binding_hash
        .map(|expected| expected != binding_hash)
        .unwrap_or(false)
    {
        return Err(invalid(
            "principal_authority_binding_hash_mismatch",
            "expected binding hash does not match binding_ref",
        ));
    }
    let proof = load_proof_by_hash(state, &binding_hash)?.ok_or_else(|| {
        invalid(
            "principal_authority_binding_not_found",
            "immutable binding proof does not exist",
        )
    })?;
    if proof.binding_ref != params.binding_ref || proof.binding_hash != binding_hash {
        return Err(invalid(
            "principal_authority_binding_proof_invalid",
            "stored proof does not match its content-addressed key",
        ));
    }
    let root = load_control_root(state)?.ok_or(TransactionError::UnauthorizedByCredentials)?;
    validate_root_signature(&proof, &root)?;
    let receipt = LookupPrincipalAuthorityBindingReceipt {
        request_id: params.request_id,
        fetched_at_ms: block_timestamp_ms(ctx),
        proof,
    };
    // Historical lookup is evidence retrieval, not active resolution. It does not
    // treat the proof as current authority and does not require the underlying
    // ApprovalAuthority to remain active.
    let mut metadata = base_audit_metadata(ctx);
    metadata.insert("binding_ref".to_string(), params.binding_ref);
    metadata.insert("binding_hash".to_string(), hex::encode(binding_hash));
    metadata.insert(
        "binding_version".to_string(),
        receipt.proof.statement.binding_version.to_string(),
    );
    metadata.insert(
        "principal_ref".to_string(),
        receipt.proof.statement.principal_ref.clone(),
    );
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::PrincipalAuthorityBindingFetched,
        metadata,
        |_| Ok(vec![(receipt_key, codec::to_bytes_canonical(&receipt)?)]),
    )?;
    Ok(())
}
