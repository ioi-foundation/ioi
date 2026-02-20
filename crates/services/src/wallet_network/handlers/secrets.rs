// Path: crates/services/src/wallet_network/handlers/secrets.rs

use crate::wallet_network::keys::{
    injection_attestation_key, injection_grant_key, injection_request_key, secret_alias_key,
    secret_key,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_typed, store_typed,
};
use crate::wallet_network::validation::{
    validate_guardian_attestation, validate_secret_injection_request,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    GuardianAttestation, SecretInjectionGrant, SecretInjectionRequest,
    SecretInjectionRequestRecord, VaultAuditEventKind,
};
use ioi_types::error::TransactionError;

pub(crate) fn record_secret_injection_request(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    record: SecretInjectionRequestRecord,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    validate_secret_injection_request(&record.request)?;
    validate_guardian_attestation(&record.attestation, now_ms)?;
    if record.request.attestation_nonce != record.attestation.nonce {
        return Err(TransactionError::Invalid(
            "secret injection request nonce does not match attestation nonce".to_string(),
        ));
    }
    if record.request.requested_at_ms < record.attestation.issued_at_ms
        || record.request.requested_at_ms > record.attestation.expires_at_ms
    {
        return Err(TransactionError::Invalid(
            "secret injection request timestamp must be within attestation validity window"
                .to_string(),
        ));
    }

    let request_key = injection_request_key(&record.request.request_id);
    if state.get(&request_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "secret injection request already exists".to_string(),
        ));
    }
    let attestation_key = injection_attestation_key(&record.request.request_id);
    if state.get(&attestation_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "secret injection attestation already exists for request".to_string(),
        ));
    }

    let alias_key = secret_alias_key(&record.request.secret_alias);
    let mapped_secret_id: String = load_typed(state, &alias_key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "secret alias '{}' is not registered",
            record.request.secret_alias.trim()
        ))
    })?;
    if state.get(&secret_key(&mapped_secret_id))?.is_none() {
        return Err(TransactionError::Invalid(
            "secret alias is mapped to missing secret record".to_string(),
        ));
    }

    store_typed(state, &request_key, &record.request)?;
    store_typed(state, &attestation_key, &record.attestation)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "request_id".to_string(),
        hex::encode(record.request.request_id),
    );
    meta.insert(
        "session_id".to_string(),
        hex::encode(record.request.session_id),
    );
    meta.insert(
        "secret_alias".to_string(),
        record.request.secret_alias.trim().to_string(),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::SecretInjectionRequested,
        meta,
    )?;
    Ok(())
}

pub(crate) fn grant_secret_injection(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    mut grant: SecretInjectionGrant,
) -> Result<(), TransactionError> {
    if grant.request_id == [0u8; 32] || grant.secret_id.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "secret injection grant requires request_id and secret_id".to_string(),
        ));
    }
    if grant.envelope.ciphertext.is_empty() {
        return Err(TransactionError::Invalid(
            "secret injection envelope ciphertext must not be empty".to_string(),
        ));
    }

    let now_ms = block_timestamp_ms(ctx);
    if grant.issued_at_ms == 0 {
        grant.issued_at_ms = now_ms;
    }
    if grant.expires_at_ms <= grant.issued_at_ms || grant.expires_at_ms <= now_ms {
        return Err(TransactionError::Invalid(
            "secret injection grant expiry must be in the future".to_string(),
        ));
    }

    let request_key = injection_request_key(&grant.request_id);
    let request: SecretInjectionRequest = load_typed(state, &request_key)?.ok_or_else(|| {
        TransactionError::Invalid(
            "secret injection grant requires prior attested request".to_string(),
        )
    })?;
    let attestation_key = injection_attestation_key(&grant.request_id);
    let attestation: GuardianAttestation =
        load_typed(state, &attestation_key)?.ok_or_else(|| {
            TransactionError::Invalid(
                "secret injection grant requires guardian attestation".to_string(),
            )
        })?;
    validate_guardian_attestation(&attestation, now_ms)?;
    if attestation.nonce != request.attestation_nonce {
        return Err(TransactionError::Invalid(
            "stored attestation nonce mismatch for secret injection request".to_string(),
        ));
    }
    if grant.expires_at_ms > attestation.expires_at_ms {
        return Err(TransactionError::Invalid(
            "secret injection grant expiry must be <= attestation expiry".to_string(),
        ));
    }

    let alias_key = secret_alias_key(&request.secret_alias);
    let expected_secret_id: String = load_typed(state, &alias_key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "secret alias '{}' is not registered",
            request.secret_alias.trim()
        ))
    })?;
    if expected_secret_id.trim() != grant.secret_id.trim() {
        return Err(TransactionError::Invalid(
            "secret injection grant secret_id does not match requested secret alias".to_string(),
        ));
    }
    if state.get(&secret_key(grant.secret_id.trim()))?.is_none() {
        return Err(TransactionError::Invalid(
            "secret injection grant references unknown secret_id".to_string(),
        ));
    }

    let key = injection_grant_key(&grant.request_id);
    if state.get(&key)?.is_some() {
        return Err(TransactionError::Invalid(
            "secret injection grant already exists".to_string(),
        ));
    }
    store_typed(state, &key, &grant)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("request_id".to_string(), hex::encode(grant.request_id));
    meta.insert("secret_id".to_string(), grant.secret_id.trim().to_string());
    meta.insert(
        "secret_alias".to_string(),
        request.secret_alias.trim().to_string(),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::SecretInjectionGranted,
        meta,
    )?;
    Ok(())
}
