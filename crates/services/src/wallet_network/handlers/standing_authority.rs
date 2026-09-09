use crate::wallet_network::handlers::principal_authority::validate_expected_principal_authority_binding;
use crate::wallet_network::keys::{
    standing_approval_consumption_receipt_key, standing_approval_context_consumption_key,
    standing_approval_grant_journal_key, standing_approval_grant_state_key,
    standing_approval_settlement_receipt_key,
};
use crate::wallet_network::support::{
    append_audit_event_with_records, base_audit_metadata, block_timestamp_ms,
    load_revocation_epoch, load_typed,
};
use crate::wallet_network::validation::load_registered_approval_authority;
use crate::wallet_network::{
    ConsumeStandingApprovalGrantForEffectParams, RecordStandingApprovalGrantParams,
    RevokeStandingApprovalGrantParams, SettleStandingApprovalGrantConsumptionParams,
    StandingApprovalContextConsumption, StandingApprovalGrantConsumptionReceipt,
    StandingApprovalGrantJournal, StandingApprovalGrantSettlementReceipt,
    StandingApprovalGrantState, StandingApprovalGrantStatus, StandingApprovalLedgerTotals,
    StandingApprovalMode,
};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::sign::dilithium::{MldsaPublicKey, MldsaSignature};
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::action::StandingApprovalGrant;
use ioi_types::app::wallet_network::VaultAuditEventKind;
use ioi_types::app::SignatureSuite;
use ioi_types::error::TransactionError;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const STANDING_ENVELOPE_CONTRACT: &str = "schema://ioi/foundations/standing-authority-envelope/v1";
const APPROVAL_CONTEXT_CONTRACT: &str = "schema://ioi/foundations/approval-ceremony-context/v1";
const AUTH_FACTOR_RECEIPT_CONTRACT: &str =
    "schema://ioi/components/hypervisor/auth-factor-receipt/v1";
/// R-14 (ruled 2026-09-09, owner-reversible): the deployment-local operator key is a RECOGNIZED
/// CUSTODY TIER for recording a standing grant, under the same rules as the passkey step-up — one
/// ceremony, receipted before the effect, creating no effect authority, widening nothing. v1
/// pinned `factor_kind` to `passkey`, which is the right floor for a person at a device and the
/// wrong one for a deployment whose operator holds the approver key on the host itself; the
/// bounded alpha could therefore never mint a standing envelope at all. v2 admits the tier beside
/// the passkey and binds the verification mode to it, so neither tier borrows the other's evidence.
const AUTH_FACTOR_RECEIPT_CONTRACT_V2: &str =
    "schema://ioi/components/hypervisor/auth-factor-receipt/v2";
/// The posture ref a ceremony must require, per recognized tier. A ceremony naming neither is
/// refused: the recognized set is CLOSED, and a new tier is a new binding on record.
const RECOGNIZED_FACTOR_POSTURE_PREFIXES: &[(&str, &str)] = &[
    ("auth_factor://passkey/", "passkey"),
    (
        "auth_factor://deployment-local-operator/",
        "deployment_local_operator",
    ),
];
const APPROVAL_CONTEXT_DOMAIN: &[u8] = b"IOI-APPROVAL-CEREMONY-CONTEXT-V1\0";
const MAX_STANDING_EVIDENCE_BYTES: usize = 64 * 1024;

fn verify_signature(grant: &StandingApprovalGrant) -> Result<(), TransactionError> {
    let message = grant
        .signing_bytes()
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    match grant.approver_suite {
        SignatureSuite::ED25519 => {
            let key = Ed25519PublicKey::from_bytes(&grant.approver_public_key)
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
            let signature = Ed25519Signature::from_bytes(&grant.approver_sig)
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
            key.verify(&message, &signature).map_err(|error| {
                TransactionError::Invalid(format!(
                    "standing approval grant signature verification failed: {error}"
                ))
            })
        }
        SignatureSuite::ML_DSA_44 => {
            let key = MldsaPublicKey::from_bytes(&grant.approver_public_key)
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
            let signature = MldsaSignature::from_bytes(&grant.approver_sig)
                .map_err(|error| TransactionError::Invalid(error.to_string()))?;
            key.verify(&message, &signature).map_err(|error| {
                TransactionError::Invalid(format!(
                    "standing approval grant signature verification failed: {error}"
                ))
            })
        }
        other => Err(TransactionError::Invalid(format!(
            "unsupported standing approval grant signature suite: {}",
            other.0
        ))),
    }
}

fn validate_registered_grant(
    state: &dyn StateAccess,
    grant: &StandingApprovalGrant,
    now_ms: u64,
) -> Result<(), TransactionError> {
    grant
        .verify()
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    verify_signature(grant)?;
    let authority = load_registered_approval_authority(state, &grant.authority_id)?
        .ok_or_else(|| TransactionError::Invalid("approval authority is not registered".into()))?;
    authority
        .verify()
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    if authority.revoked {
        return Err(TransactionError::Invalid(
            "approval authority has been revoked".into(),
        ));
    }
    if authority.signature_suite != grant.approver_suite
        || authority.public_key != grant.approver_public_key
    {
        return Err(TransactionError::Invalid(
            "approval authority does not match standing grant signer".into(),
        ));
    }
    if now_ms < grant.issued_at_ms || now_ms > grant.expires_at_ms || now_ms > authority.expires_at
    {
        return Err(TransactionError::Invalid(
            "standing approval grant or authority is outside its validity window".into(),
        ));
    }
    Ok(())
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32], TransactionError> {
    let digest =
        Sha256::digest(bytes).map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

fn hash_value(value: &Value, pointer: &str, label: &str) -> Result<[u8; 32], TransactionError> {
    let encoded = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or_else(|| TransactionError::Invalid(format!("{label} is not a sha256 ref")))?;
    if encoded.len() != 64
        || encoded != encoded.to_ascii_lowercase()
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TransactionError::Invalid(format!(
            "{label} is not 32 lowercase bytes"
        )));
    }
    let decoded = hex::decode(encoded)
        .map_err(|_| TransactionError::Invalid(format!("{label} is not hexadecimal")))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded);
    if output == [0u8; 32] {
        return Err(TransactionError::Invalid(format!(
            "{label} must not be zero"
        )));
    }
    Ok(output)
}

/// The closed set of registered standing-envelope contracts, selected by the envelope's own
/// declared schema_version (then fully validated against that contract).
pub(crate) const SESSION_STANDING_ENVELOPE_CONTRACT: &str =
    "schema://ioi/components/hypervisor/session-standing-envelope/v1";

/// The closed set of registered auth-factor-receipt contracts, selected by the receipt's own
/// declared schema_version and then fully validated against that contract.
fn auth_factor_receipt_contract_for(bytes: &[u8]) -> Result<&'static str, TransactionError> {
    if bytes.is_empty() || bytes.len() > MAX_STANDING_EVIDENCE_BYTES {
        return Err(TransactionError::Invalid(
            "authentication factor receipt exceeds the standing evidence byte envelope".into(),
        ));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionError::Invalid(format!(
            "authentication factor receipt is invalid JSON: {error}"
        ))
    })?;
    match value.get("schema_version").and_then(Value::as_str) {
        Some("ioi.hypervisor.auth-factor-receipt.v1") => Ok(AUTH_FACTOR_RECEIPT_CONTRACT),
        Some("ioi.hypervisor.auth-factor-receipt.v2") => Ok(AUTH_FACTOR_RECEIPT_CONTRACT_V2),
        other => Err(TransactionError::Invalid(format!(
            "authentication factor receipt schema_version {other:?} is not a registered auth-factor-receipt contract"
        ))),
    }
}

fn standing_envelope_contract_for(bytes: &[u8]) -> Result<&'static str, TransactionError> {
    if bytes.is_empty() || bytes.len() > MAX_STANDING_EVIDENCE_BYTES {
        return Err(TransactionError::Invalid(
            "standing envelope exceeds the standing evidence byte envelope".into(),
        ));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionError::Invalid(format!("standing envelope is invalid JSON: {error}"))
    })?;
    match value.get("schema_version").and_then(Value::as_str) {
        Some("ioi.foundations.standing-authority-envelope.v1") => Ok(STANDING_ENVELOPE_CONTRACT),
        Some("ioi.hypervisor.session-standing-envelope.v1") => {
            Ok(SESSION_STANDING_ENVELOPE_CONTRACT)
        }
        other => Err(TransactionError::Invalid(format!(
            "standing envelope schema_version {other:?} is not a registered standing-envelope contract"
        ))),
    }
}

fn parse_registered_evidence(
    bytes: &[u8],
    contract: &str,
    label: &str,
) -> Result<(Value, Vec<u8>), TransactionError> {
    if bytes.is_empty() || bytes.len() > MAX_STANDING_EVIDENCE_BYTES {
        return Err(TransactionError::Invalid(format!(
            "{label} exceeds the standing evidence byte envelope"
        )));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| TransactionError::Invalid(format!("{label} is invalid JSON: {error}")))?;
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract, &value,
    )
    .map_err(|error| {
        TransactionError::Invalid(format!("{label} violates its registered contract: {error}"))
    })?;
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| TransactionError::Invalid(format!("{label} is not canonical: {error}")))?;
    Ok((value, canonical))
}

fn rfc3339_ms(value: &Value, pointer: &str, label: &str) -> Result<u64, TransactionError> {
    let parsed = OffsetDateTime::parse(
        value.pointer(pointer).and_then(Value::as_str).unwrap_or(""),
        &Rfc3339,
    )
    .map_err(|_| TransactionError::Invalid(format!("{label} is not RFC3339")))?;
    u64::try_from(parsed.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| TransactionError::Invalid(format!("{label} predates the Unix epoch")))
}

fn validate_standing_evidence(
    state: &dyn StateAccess,
    grant: &StandingApprovalGrant,
    params: &RecordStandingApprovalGrantParams,
    now_ms: u64,
) -> Result<(String, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32], bool), TransactionError> {
    // The envelope is one of the CLOSED set of registered standing-envelope contracts: the
    // provider-operation envelope, or the session envelope a Connections attach declares
    // (M13.3). The ceremony's validation_profile_ref must name the same contract below.
    let envelope_contract = standing_envelope_contract_for(&params.standing_envelope_json)?;
    let (envelope, envelope_json) = parse_registered_evidence(
        &params.standing_envelope_json,
        envelope_contract,
        "standing envelope",
    )?;
    let (context, context_json) = parse_registered_evidence(
        &params.approval_ceremony_context_json,
        APPROVAL_CONTEXT_CONTRACT,
        "approval ceremony context",
    )?;
    let factor_contract = auth_factor_receipt_contract_for(&params.auth_factor_receipt_json)?;
    let (factor, factor_json) = parse_registered_evidence(
        &params.auth_factor_receipt_json,
        factor_contract,
        "authentication factor receipt",
    )?;

    let envelope_hash = hash_value(&envelope, "/body_hash", "standing envelope body_hash")?;
    let policy_hash = hash_value(
        &envelope,
        "/trajectory_policy_hash",
        "standing envelope trajectory_policy_hash",
    )?;
    if envelope_hash != grant.standing_envelope_hash || policy_hash != grant.policy_hash {
        return Err(TransactionError::Invalid(
            "standing evidence does not bind the grant envelope and policy".into(),
        ));
    }
    let envelope_epoch = envelope
        .get("revocation_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| TransactionError::Invalid("standing envelope epoch is invalid".into()))?;
    let current_epoch = load_revocation_epoch(state)?;
    if envelope_epoch != current_epoch {
        return Err(TransactionError::Invalid(
            "standing envelope was invalidated by revocation epoch".into(),
        ));
    }
    let aggregate = envelope
        .get("aggregate_bounds")
        .ok_or_else(|| TransactionError::Invalid("standing envelope bounds are absent".into()))?;
    if grant.max_usages
        > aggregate
            .get("max_usages")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0)
        || grant.max_cumulative_deposit_microusd
            > aggregate
                .get("max_cumulative_deposit_microusd")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        || grant.max_cumulative_spend_microusd
            > aggregate
                .get("max_cumulative_spend_microusd")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        || grant.issued_at_ms
            < envelope
                .get("not_before_ms")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX)
        || grant.expires_at_ms
            > envelope
                .get("expires_at_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0)
    {
        return Err(TransactionError::Invalid(
            "standing grant widens its registered envelope".into(),
        ));
    }

    let mut context_material =
        Vec::with_capacity(APPROVAL_CONTEXT_DOMAIN.len() + context_json.len());
    context_material.extend_from_slice(APPROVAL_CONTEXT_DOMAIN);
    context_material.extend_from_slice(&context_json);
    let context_hash = digest32(&context_material)?;
    let context_refused = |detail: &str| {
        TransactionError::Invalid(format!(
            "approval ceremony context does not bind the standing grant: {detail}"
        ))
    };
    if context_hash != grant.approval_ceremony_context_hash {
        return Err(context_refused("context_hash"));
    }
    if hash_value(
        &context,
        "/authorization_subject/subject_hash",
        "approval subject hash",
    )? != envelope_hash
    {
        return Err(context_refused("authorization_subject.subject_hash"));
    }
    if hash_value(&context, "/policy_hash", "approval context policy hash")? != policy_hash {
        return Err(context_refused("policy_hash"));
    }
    if context.pointer("/authorization_subject/subject_ref")
        != envelope.get("standing_envelope_ref")
    {
        return Err(context_refused("authorization_subject.subject_ref"));
    }
    if context
        .pointer("/authorization_subject/validation_profile_ref")
        .and_then(Value::as_str)
        != Some(envelope_contract)
    {
        return Err(context_refused(
            "authorization_subject.validation_profile_ref",
        ));
    }
    if context.get("interaction_mode").and_then(Value::as_str) != Some("interactive") {
        return Err(context_refused("interaction_mode"));
    }
    if context
        .get("authentication_posture")
        .and_then(Value::as_str)
        != Some("step_up")
    {
        return Err(context_refused("authentication_posture"));
    }
    if context.get("receipt_timing").and_then(Value::as_str) != Some("before_effect") {
        return Err(context_refused("receipt_timing"));
    }
    // The ceremony must require a posture from the CLOSED set of recognized custody tiers, and the
    // factor receipt must be of exactly that tier: neither tier may borrow the other's evidence.
    let factor_kind = factor
        .get("factor_kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match context
        .get("required_auth_factor_posture_refs")
        .and_then(Value::as_array)
        .and_then(|refs| {
            refs.iter().find_map(|value| {
                let value = value.as_str()?;
                RECOGNIZED_FACTOR_POSTURE_PREFIXES
                    .iter()
                    .find(|(prefix, _)| value.starts_with(prefix))
                    .map(|(_, kind)| *kind)
            })
        }) {
        Some(tier) if tier == factor_kind => {}
        Some(_) => {
            return Err(context_refused(
                "required_auth_factor_posture_refs names a tier the factor receipt is not",
            ))
        }
        None => return Err(context_refused("required_auth_factor_posture_refs")),
    }
    if context.get("revocation_epoch").and_then(Value::as_u64) != Some(current_epoch) {
        return Err(context_refused("revocation_epoch"));
    }
    if hash_value(
        &context,
        "/policy_decision_receipt_hash",
        "policy decision receipt hash",
    )? != grant.review_receipt_hash
    {
        return Err(context_refused("policy_decision_receipt_hash"));
    }
    let context_issued_ms = rfc3339_ms(&context, "/issued_at", "context issued_at")?;
    let context_expires_ms = rfc3339_ms(&context, "/expires_at", "context expires_at")?;
    if context_issued_ms > now_ms.saturating_add(30_000)
        || context_expires_ms <= now_ms
        || context_expires_ms <= context_issued_ms
        || context_expires_ms.saturating_sub(context_issued_ms) > 5 * 60 * 1_000
        || grant.issued_at_ms < context_issued_ms
        || grant.issued_at_ms > context_expires_ms
    {
        return Err(TransactionError::Invalid(
            "approval ceremony context is outside its issuance window".into(),
        ));
    }

    let supplied_factor_hash = hash_value(&factor, "/receipt_hash", "factor receipt hash")?;
    let mut factor_without_hash = factor.clone();
    factor_without_hash
        .as_object_mut()
        .ok_or_else(|| TransactionError::Invalid("factor receipt is not an object".into()))?
        .remove("receipt_hash");
    let factor_hash = digest32(&serde_jcs::to_vec(&factor_without_hash).map_err(|error| {
        TransactionError::Invalid(format!("factor receipt cannot be hashed: {error}"))
    })?)?;
    if factor_hash != supplied_factor_hash
        || factor_hash != grant.auth_factor_receipt_hash
        || hash_value(
            &factor,
            "/approval_ceremony_context_hash",
            "factor approval context hash",
        )? != context_hash
        || factor.get("approval_ceremony_context_ref")
            != context.get("approval_ceremony_context_ref")
        || factor.get("authorization_subject") != context.get("authorization_subject")
        || factor.get("policy_hash") != context.get("policy_hash")
        || factor.get("principal_ref") != context.get("principal_ref")
        || factor.get("purpose").and_then(Value::as_str) != Some("standing_effect_authority")
        || factor
            .get("effect_authority_created")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(TransactionError::Invalid(
            "authentication factor receipt does not bind the standing grant".into(),
        ));
    }
    let factor_created_ms = rfc3339_ms(&factor, "/created_at", "factor receipt created_at")?;
    if factor_created_ms < context_issued_ms
        || factor_created_ms > context_expires_ms
        || factor_created_ms > now_ms.saturating_add(30_000)
    {
        return Err(TransactionError::Invalid(
            "authentication factor receipt is outside the consent window".into(),
        ));
    }
    let principal_ref = envelope
        .get("principal_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| TransactionError::Invalid("standing envelope principal is invalid".into()))?
        .to_string();
    // `single_use` is a posture the ceremony asserts about itself. Read it as a
    // strict boolean: a context that does not state it is not a single-use
    // ceremony and gets no single-use protection silently.
    let context_single_use = context
        .get("single_use")
        .and_then(Value::as_bool)
        .ok_or_else(|| context_refused("single_use"))?;
    Ok((
        principal_ref,
        envelope_json,
        context_json,
        factor_json,
        context_hash,
        context_single_use,
    ))
}

pub(crate) fn record_standing_approval_grant(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: RecordStandingApprovalGrantParams,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    validate_registered_grant(state, &params.grant, now_ms)?;
    let (
        principal_ref,
        standing_envelope_json,
        approval_ceremony_context_json,
        auth_factor_receipt_json,
        approval_ceremony_context_hash,
        context_single_use,
    ) = validate_standing_evidence(state, &params.grant, &params, now_ms)?;
    let grant_hash = params.grant.artifact_hash().map_err(|error| {
        TransactionError::Invalid(format!("standing approval grant hash failed: {error}"))
    })?;
    let key = standing_approval_grant_state_key(&grant_hash);
    if let Some(existing) = load_typed::<StandingApprovalGrantState>(state, &key)? {
        if existing.grant == params.grant
            && existing.grant_hash == grant_hash
            && existing.principal_ref == principal_ref
            && existing.standing_envelope_json == standing_envelope_json
            && existing.approval_ceremony_context_json == approval_ceremony_context_json
            && existing.auth_factor_receipt_json == auth_factor_receipt_json
        {
            return Ok(());
        }
        return Err(TransactionError::Invalid(
            "standing approval grant hash is bound to different state".into(),
        ));
    }
    // A single-use ceremony authorises ONE standing recording. This is checked
    // after the byte-identical idempotent replay above, so a retried record of the
    // same grant still succeeds while a second, different grant under the same
    // consent is refused — including after the first grant was revoked.
    let context_key = standing_approval_context_consumption_key(&approval_ceremony_context_hash);
    if context_single_use {
        if let Some(consumed) =
            load_typed::<StandingApprovalContextConsumption>(state, &context_key)?
        {
            if consumed.standing_grant_hash != grant_hash {
                return Err(TransactionError::Invalid(
                    "approval ceremony context is single use and already authorised a standing grant"
                        .into(),
                ));
            }
        }
    }
    let context_consumption = StandingApprovalContextConsumption {
        schema_version: 1,
        approval_ceremony_context_hash,
        standing_grant_hash: grant_hash,
        consumed_at_ms: now_ms,
    };
    let record = StandingApprovalGrantState {
        schema_version: 1,
        grant_hash,
        grant: params.grant,
        principal_ref,
        standing_envelope_json,
        approval_ceremony_context_json,
        auth_factor_receipt_json,
        issued_revocation_epoch: load_revocation_epoch(state)?,
        uses_consumed: 0,
        cumulative_deposit_reserved_microusd: 0,
        cumulative_spend_reserved_microusd: 0,
        cumulative_spend_settled_microusd: 0,
        last_consumed_at_ms: None,
        status: StandingApprovalGrantStatus::Active,
    };
    let mut metadata = base_audit_metadata(ctx);
    metadata.insert("standing_grant_hash".into(), hex::encode(grant_hash));
    metadata.insert(
        "standing_envelope_hash".into(),
        hex::encode(record.grant.standing_envelope_hash),
    );
    metadata.insert("approval_mode".into(), "standing_envelope".into());
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        metadata,
        |_| {
            Ok(vec![
                (key, ioi_types::codec::to_bytes_canonical(&record)?),
                (
                    context_key,
                    ioi_types::codec::to_bytes_canonical(&context_consumption)?,
                ),
            ])
        },
    )
    .map(|_| ())
}

pub(crate) fn revoke_standing_approval_grant(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: RevokeStandingApprovalGrantParams,
) -> Result<(), TransactionError> {
    let key = standing_approval_grant_state_key(&params.grant_hash);
    let mut record: StandingApprovalGrantState = load_typed(state, &key)?.ok_or_else(|| {
        TransactionError::Invalid("standing approval grant is not registered".into())
    })?;
    record.status = StandingApprovalGrantStatus::Revoked;
    let mut metadata = base_audit_metadata(ctx);
    metadata.insert("standing_grant_hash".into(), hex::encode(params.grant_hash));
    metadata.insert("standing_grant_status".into(), "revoked".into());
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        metadata,
        |_| Ok(vec![(key, ioi_types::codec::to_bytes_canonical(&record)?)]),
    )
    .map(|_| ())
}

fn receipt_hash(
    receipt: &StandingApprovalGrantConsumptionReceipt,
) -> Result<[u8; 32], TransactionError> {
    let mut material = serde_json::to_value(receipt)
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    material["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
    let canonical = serde_jcs::to_vec(&material)
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let digest =
        Sha256::digest(&canonical).map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

fn settlement_receipt_hash(
    receipt: &StandingApprovalGrantSettlementReceipt,
) -> Result<[u8; 32], TransactionError> {
    let mut material = serde_json::to_value(receipt)
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    material["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
    let canonical = serde_jcs::to_vec(&material)
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let digest =
        Sha256::digest(&canonical).map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

pub(crate) fn consume_standing_approval_grant_for_effect(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConsumeStandingApprovalGrantForEffectParams,
) -> Result<(), TransactionError> {
    for (label, value) in [
        ("grant_hash", params.grant_hash),
        ("standing_envelope_hash", params.standing_envelope_hash),
        ("policy_hash", params.policy_hash),
        ("request_hash", params.request_hash),
        ("consumption_id", params.consumption_id),
    ] {
        if value == [0u8; 32] {
            return Err(TransactionError::Invalid(format!(
                "standing approval draw {label} must not be zero"
            )));
        }
    }
    if params.expected_target_label.trim().is_empty()
        || params.expected_target_label.len() > 256
        || params.estimated_deposit_microusd == 0
        || params.estimated_spend_microusd == 0
        || params.estimated_spend_microusd > params.estimated_deposit_microusd
    {
        return Err(TransactionError::Invalid(
            "standing approval draw bounds are invalid".into(),
        ));
    }

    let receipt_key = standing_approval_consumption_receipt_key(&params.consumption_id);
    if let Some(existing) =
        load_typed::<StandingApprovalGrantConsumptionReceipt>(state, &receipt_key)?
    {
        if existing.grant_hash == params.grant_hash
            && existing.standing_envelope_hash == params.standing_envelope_hash
            && existing.policy_hash == params.policy_hash
            && existing.request_hash == params.request_hash
            && existing.consumption_id == params.consumption_id
            && existing.expected_principal_authority == params.expected_principal_authority
            && existing.target_label == params.expected_target_label
            && existing.estimated_deposit_microusd == params.estimated_deposit_microusd
            && existing.estimated_spend_microusd == params.estimated_spend_microusd
            && existing.receipt_hash == receipt_hash(&existing)?
        {
            return Ok(());
        }
        return Err(TransactionError::Invalid(
            "standing approval consumption id is bound to a different draw".into(),
        ));
    }

    let state_key = standing_approval_grant_state_key(&params.grant_hash);
    let mut grant_state: StandingApprovalGrantState =
        load_typed(state, &state_key)?.ok_or_else(|| {
            TransactionError::Invalid("standing approval grant is not registered".into())
        })?;
    if grant_state.grant_hash != params.grant_hash
        || grant_state.grant.standing_envelope_hash != params.standing_envelope_hash
        || grant_state.grant.policy_hash != params.policy_hash
    {
        return Err(TransactionError::Invalid(
            "standing approval grant does not bind the exact envelope and policy".into(),
        ));
    }
    // The lifecycle status is named exactly: an exhausted lease crossed its usage bound, a revoked
    // one was fenced, an expired one lapsed. "not active" is the shared refusal family.
    match grant_state.status {
        StandingApprovalGrantStatus::Active => {}
        StandingApprovalGrantStatus::Exhausted => {
            return Err(TransactionError::Invalid(format!(
                "standing approval grant is not active: exhausted, usages {} of {} consumed",
                grant_state.uses_consumed, grant_state.grant.max_usages
            )));
        }
        StandingApprovalGrantStatus::Revoked => {
            return Err(TransactionError::Invalid(
                "standing approval grant is not active: revoked".into(),
            ));
        }
        StandingApprovalGrantStatus::Expired => {
            return Err(TransactionError::Invalid(
                "standing approval grant is not active: expired".into(),
            ));
        }
    }
    let now_ms = block_timestamp_ms(ctx);
    validate_registered_grant(state, &grant_state.grant, now_ms)?;
    if grant_state.issued_revocation_epoch != load_revocation_epoch(state)? {
        return Err(TransactionError::Invalid(
            "standing approval grant was invalidated by revocation epoch".into(),
        ));
    }
    if ctx.signer_account_id.0 != grant_state.grant.audience {
        return Err(TransactionError::Invalid(
            "standing approval grant audience does not match transaction signer".into(),
        ));
    }
    let principal = validate_expected_principal_authority_binding(
        state,
        ctx,
        &params.expected_principal_authority,
    )?;
    // The envelope principal is the governing authority. The authenticated operator is bound
    // separately by the ceremony context and factor receipt, both of which name the exact signed
    // envelope as their authorization subject.
    if params.expected_principal_authority.principal_ref != grant_state.principal_ref
        || principal.authority_id != grant_state.grant.authority_id
        || principal.public_key != grant_state.grant.approver_public_key
        || principal.signature_suite != grant_state.grant.approver_suite
    {
        return Err(TransactionError::Invalid(
            "standing approval grant principal or signer does not match current principal authority"
                .into(),
        ));
    }
    // M03.11: the cached counters are re-derived from the consumption journal on EVERY draw.
    // A counter that no longer equals the sum of its journaled receipts is not authority; the
    // draw refuses by name rather than trusting a number that could have rotted or been reset.
    let journal_key = standing_approval_grant_journal_key(&params.grant_hash);
    let mut journal = load_typed::<StandingApprovalGrantJournal>(state, &journal_key)?.unwrap_or(
        StandingApprovalGrantJournal {
            schema_version: 1,
            grant_hash: params.grant_hash,
            consumption_ids: Vec::new(),
        },
    );
    if journal.grant_hash != params.grant_hash {
        return Err(TransactionError::Invalid(
            "standing approval journal names a different grant".into(),
        ));
    }
    let derived = derive_standing_ledger_totals(state, &journal)?;
    if derived
        != (StandingApprovalLedgerTotals {
            uses_consumed: grant_state.uses_consumed,
            cumulative_deposit_reserved_microusd: grant_state.cumulative_deposit_reserved_microusd,
            cumulative_spend_reserved_microusd: grant_state.cumulative_spend_reserved_microusd,
        })
    {
        return Err(TransactionError::Invalid(format!(
            "standing approval ledger divergence: journal derives usages={} deposit={} spend={} but the grant state carries usages={} deposit={} spend={}",
            derived.uses_consumed,
            derived.cumulative_deposit_reserved_microusd,
            derived.cumulative_spend_reserved_microusd,
            grant_state.uses_consumed,
            grant_state.cumulative_deposit_reserved_microusd,
            grant_state.cumulative_spend_reserved_microusd
        )));
    }
    let next_usage = grant_state.uses_consumed.checked_add(1).ok_or_else(|| {
        TransactionError::Invalid("standing approval usage counter overflow".into())
    })?;
    let next_deposit = grant_state
        .cumulative_deposit_reserved_microusd
        .checked_add(params.estimated_deposit_microusd)
        .ok_or_else(|| TransactionError::Invalid("standing deposit counter overflow".into()))?;
    let next_spend = grant_state
        .cumulative_spend_reserved_microusd
        .checked_add(params.estimated_spend_microusd)
        .ok_or_else(|| TransactionError::Invalid("standing spend counter overflow".into()))?;
    if next_usage > grant_state.grant.max_usages {
        return Err(TransactionError::Invalid(format!(
            "standing approval usage envelope exceeded: remaining usages 0 of {}",
            grant_state.grant.max_usages
        )));
    }
    if next_deposit > grant_state.grant.max_cumulative_deposit_microusd {
        return Err(TransactionError::Invalid(format!(
            "standing approval cumulative deposit envelope exceeded: remaining deposit {} microusd, requested {}",
            grant_state
                .grant
                .max_cumulative_deposit_microusd
                .saturating_sub(grant_state.cumulative_deposit_reserved_microusd),
            params.estimated_deposit_microusd
        )));
    }
    if next_spend > grant_state.grant.max_cumulative_spend_microusd {
        return Err(TransactionError::Invalid(format!(
            "standing approval cumulative spend envelope exceeded: remaining spend {} microusd, requested {}",
            grant_state
                .grant
                .max_cumulative_spend_microusd
                .saturating_sub(grant_state.cumulative_spend_reserved_microusd),
            params.estimated_spend_microusd
        )));
    }

    grant_state.uses_consumed = next_usage;
    grant_state.cumulative_deposit_reserved_microusd = next_deposit;
    grant_state.cumulative_spend_reserved_microusd = next_spend;
    grant_state.last_consumed_at_ms = Some(now_ms);
    if next_usage == grant_state.grant.max_usages {
        grant_state.status = StandingApprovalGrantStatus::Exhausted;
    }
    let mut receipt = StandingApprovalGrantConsumptionReceipt {
        schema_version: 1,
        receipt_hash: [0u8; 32],
        grant_hash: params.grant_hash,
        standing_envelope_hash: params.standing_envelope_hash,
        policy_hash: params.policy_hash,
        request_hash: params.request_hash,
        consumption_id: params.consumption_id,
        authority_id: grant_state.grant.authority_id,
        audience: grant_state.grant.audience,
        expected_principal_authority: params.expected_principal_authority,
        target_label: params.expected_target_label,
        estimated_deposit_microusd: params.estimated_deposit_microusd,
        estimated_spend_microusd: params.estimated_spend_microusd,
        usage_ordinal: next_usage,
        remaining_usages: grant_state.grant.max_usages - next_usage,
        cumulative_deposit_reserved_microusd: next_deposit,
        remaining_deposit_microusd: grant_state.grant.max_cumulative_deposit_microusd
            - next_deposit,
        cumulative_spend_reserved_microusd: next_spend,
        remaining_spend_microusd: grant_state.grant.max_cumulative_spend_microusd - next_spend,
        consumed_at_ms: now_ms,
        approval_mode: StandingApprovalMode::SilentWithinStandingEnvelope,
    };
    receipt.receipt_hash = receipt_hash(&receipt)?;
    journal.consumption_ids.push(params.consumption_id);
    let mut metadata = base_audit_metadata(ctx);
    metadata.insert("standing_grant_hash".into(), hex::encode(params.grant_hash));
    metadata.insert("request_hash".into(), hex::encode(params.request_hash));
    metadata.insert("usage_ordinal".into(), next_usage.to_string());
    metadata.insert(
        "approval_mode".into(),
        "silent_within_standing_envelope".into(),
    );
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        metadata,
        |_| {
            Ok(vec![
                (
                    state_key,
                    ioi_types::codec::to_bytes_canonical(&grant_state)?,
                ),
                (receipt_key, ioi_types::codec::to_bytes_canonical(&receipt)?),
                (journal_key, ioi_types::codec::to_bytes_canonical(&journal)?),
            ])
        },
    )
    .map(|_| ())
}

/// Re-derive the draw-down totals from the journaled consumption receipts. Every journaled id
/// must resolve to a receipt for this grant; a missing or foreign receipt is a divergence.
pub(crate) fn derive_standing_ledger_totals(
    state: &dyn StateAccess,
    journal: &StandingApprovalGrantJournal,
) -> Result<StandingApprovalLedgerTotals, TransactionError> {
    let mut totals = StandingApprovalLedgerTotals {
        uses_consumed: 0,
        cumulative_deposit_reserved_microusd: 0,
        cumulative_spend_reserved_microusd: 0,
    };
    for consumption_id in &journal.consumption_ids {
        let receipt = load_typed::<StandingApprovalGrantConsumptionReceipt>(
            state,
            &standing_approval_consumption_receipt_key(consumption_id),
        )?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "standing approval journal names a consumption with no receipt".into(),
            )
        })?;
        if receipt.grant_hash != journal.grant_hash
            || receipt.receipt_hash != receipt_hash(&receipt)?
        {
            return Err(TransactionError::Invalid(
                "standing approval journal names a receipt that does not bind this grant".into(),
            ));
        }
        totals.uses_consumed = totals.uses_consumed.checked_add(1).ok_or_else(|| {
            TransactionError::Invalid("standing approval journal usage overflow".into())
        })?;
        totals.cumulative_deposit_reserved_microusd = totals
            .cumulative_deposit_reserved_microusd
            .checked_add(receipt.estimated_deposit_microusd)
            .ok_or_else(|| TransactionError::Invalid("standing journal deposit overflow".into()))?;
        totals.cumulative_spend_reserved_microusd = totals
            .cumulative_spend_reserved_microusd
            .checked_add(receipt.estimated_spend_microusd)
            .ok_or_else(|| TransactionError::Invalid("standing journal spend overflow".into()))?;
    }
    Ok(totals)
}

pub(crate) fn settle_standing_approval_grant_consumption(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: SettleStandingApprovalGrantConsumptionParams,
) -> Result<(), TransactionError> {
    if params.consumption_id == [0u8; 32]
        || params.terminal_evidence_hash == [0u8; 32]
        || params.terminal_evidence_ref.trim().is_empty()
        || params.terminal_evidence_ref.len() > 512
    {
        return Err(TransactionError::Invalid(
            "standing approval settlement evidence is invalid".into(),
        ));
    }

    let settlement_key = standing_approval_settlement_receipt_key(&params.consumption_id);
    if let Some(existing) =
        load_typed::<StandingApprovalGrantSettlementReceipt>(state, &settlement_key)?
    {
        if existing.consumption_id == params.consumption_id
            && existing.terminal_evidence_hash == params.terminal_evidence_hash
            && existing.terminal_evidence_ref == params.terminal_evidence_ref
            && existing.actual_spend_microusd == params.actual_spend_microusd
            && existing.receipt_hash == settlement_receipt_hash(&existing)?
        {
            return Ok(());
        }
        return Err(TransactionError::Invalid(
            "standing approval consumption already has different terminal settlement".into(),
        ));
    }

    let consumption: StandingApprovalGrantConsumptionReceipt = load_typed(
        state,
        &standing_approval_consumption_receipt_key(&params.consumption_id),
    )?
    .ok_or_else(|| {
        TransactionError::Invalid("standing approval consumption is not registered".into())
    })?;
    if consumption.receipt_hash != receipt_hash(&consumption)? {
        return Err(TransactionError::Invalid(
            "standing approval consumption receipt hash is invalid".into(),
        ));
    }
    if ctx.signer_account_id.0 != consumption.audience {
        return Err(TransactionError::UnauthorizedByCredentials);
    }
    if params.actual_spend_microusd > consumption.estimated_spend_microusd {
        return Err(TransactionError::Invalid(
            "terminal spend exceeds the authority reserved for this consumption".into(),
        ));
    }

    let grant_key = standing_approval_grant_state_key(&consumption.grant_hash);
    let mut grant_state: StandingApprovalGrantState = load_typed(state, &grant_key)?
        .ok_or_else(|| TransactionError::Invalid("standing approval grant is missing".into()))?;
    if grant_state.grant_hash != consumption.grant_hash
        || grant_state.cumulative_spend_reserved_microusd
            < consumption.cumulative_spend_reserved_microusd
    {
        return Err(TransactionError::Invalid(
            "standing approval settlement does not match current grant state".into(),
        ));
    }
    let next_settled = grant_state
        .cumulative_spend_settled_microusd
        .checked_add(params.actual_spend_microusd)
        .ok_or_else(|| TransactionError::Invalid("settled spend counter overflow".into()))?;
    if next_settled > grant_state.cumulative_spend_reserved_microusd {
        return Err(TransactionError::Invalid(
            "settled spend exceeds standing approval reservations".into(),
        ));
    }
    grant_state.cumulative_spend_settled_microusd = next_settled;

    let mut receipt = StandingApprovalGrantSettlementReceipt {
        schema_version: 1,
        receipt_hash: [0u8; 32],
        grant_hash: consumption.grant_hash,
        consumption_id: params.consumption_id,
        request_hash: consumption.request_hash,
        terminal_evidence_hash: params.terminal_evidence_hash,
        terminal_evidence_ref: params.terminal_evidence_ref,
        reserved_spend_microusd: consumption.estimated_spend_microusd,
        actual_spend_microusd: params.actual_spend_microusd,
        refunded_spend_microusd: consumption.estimated_spend_microusd
            - params.actual_spend_microusd,
        cumulative_spend_reserved_microusd: grant_state.cumulative_spend_reserved_microusd,
        cumulative_spend_settled_microusd: next_settled,
        settled_at_ms: block_timestamp_ms(ctx),
    };
    receipt.receipt_hash = settlement_receipt_hash(&receipt)?;

    let mut metadata = base_audit_metadata(ctx);
    metadata.insert(
        "standing_grant_hash".into(),
        hex::encode(consumption.grant_hash),
    );
    metadata.insert(
        "standing_consumption_id".into(),
        hex::encode(params.consumption_id),
    );
    metadata.insert(
        "actual_spend_microusd".into(),
        params.actual_spend_microusd.to_string(),
    );
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        metadata,
        |_| {
            Ok(vec![
                (
                    grant_key,
                    ioi_types::codec::to_bytes_canonical(&grant_state)?,
                ),
                (
                    settlement_key,
                    ioi_types::codec::to_bytes_canonical(&receipt)?,
                ),
            ])
        },
    )
    .map(|_| ())
}
