use crate::wallet_network::handlers::principal_authority::validate_expected_principal_authority_binding;
use crate::wallet_network::keys::{
    standing_approval_consumption_receipt_key, standing_approval_grant_state_key,
};
use crate::wallet_network::support::{
    append_audit_event_with_records, base_audit_metadata, block_timestamp_ms,
    load_revocation_epoch, load_typed,
};
use crate::wallet_network::validation::load_registered_approval_authority;
use crate::wallet_network::{
    ConsumeStandingApprovalGrantForEffectParams, RecordStandingApprovalGrantParams,
    RevokeStandingApprovalGrantParams, StandingApprovalGrantConsumptionReceipt,
    StandingApprovalGrantState, StandingApprovalGrantStatus, StandingApprovalMode,
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

pub(crate) fn record_standing_approval_grant(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: RecordStandingApprovalGrantParams,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    validate_registered_grant(state, &params.grant, now_ms)?;
    let grant_hash = params.grant.artifact_hash().map_err(|error| {
        TransactionError::Invalid(format!("standing approval grant hash failed: {error}"))
    })?;
    let key = standing_approval_grant_state_key(&grant_hash);
    if let Some(existing) = load_typed::<StandingApprovalGrantState>(state, &key)? {
        if existing.grant == params.grant && existing.grant_hash == grant_hash {
            return Ok(());
        }
        return Err(TransactionError::Invalid(
            "standing approval grant hash is bound to different state".into(),
        ));
    }
    let record = StandingApprovalGrantState {
        schema_version: 1,
        grant_hash,
        grant: params.grant,
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
        |_| Ok(vec![(key, ioi_types::codec::to_bytes_canonical(&record)?)]),
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
    if grant_state.status != StandingApprovalGrantStatus::Active {
        return Err(TransactionError::Invalid(
            "standing approval grant is not active".into(),
        ));
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
    if principal.authority_id != grant_state.grant.authority_id
        || principal.public_key != grant_state.grant.approver_public_key
        || principal.signature_suite != grant_state.grant.approver_suite
    {
        return Err(TransactionError::Invalid(
            "standing approval grant signer does not match current principal authority".into(),
        ));
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
        return Err(TransactionError::Invalid(
            "standing approval usage envelope exceeded".into(),
        ));
    }
    if next_deposit > grant_state.grant.max_cumulative_deposit_microusd {
        return Err(TransactionError::Invalid(
            "standing approval cumulative deposit envelope exceeded".into(),
        ));
    }
    if next_spend > grant_state.grant.max_cumulative_spend_microusd {
        return Err(TransactionError::Invalid(
            "standing approval cumulative spend envelope exceeded".into(),
        ));
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
            ])
        },
    )
    .map(|_| ())
}
