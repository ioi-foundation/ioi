// Path: crates/services/src/wallet_network/handlers/approval.rs

use crate::wallet_network::keys::{
    approval_consumption_key, approval_key, interception_key, PANIC_FLAG_KEY, REVOCATION_EPOCH_KEY,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_revocation_epoch, load_typed,
    store_typed,
};
use crate::wallet_network::validation::{
    validate_approval, validate_approval_token_hybrid_signature,
};
use crate::wallet_network::{
    ApprovalConsumptionState, BumpRevocationEpochParams, ConsumeApprovalTokenParams,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    VaultAuditEventKind, WalletApprovalDecision, WalletApprovalDecisionKind,
    WalletInterceptionContext,
};
use ioi_types::error::TransactionError;

pub(crate) fn record_interception(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    interception: WalletInterceptionContext,
) -> Result<(), TransactionError> {
    let key = interception_key(&interception.request_hash);
    store_typed(state, &key, &interception)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "request_hash".to_string(),
        hex::encode(interception.request_hash),
    );
    meta.insert("target".to_string(), interception.target.canonical_label());
    append_audit_event(state, ctx, VaultAuditEventKind::InterceptionObserved, meta)?;
    Ok(())
}

pub(crate) fn record_approval(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    approval: WalletApprovalDecision,
) -> Result<(), TransactionError> {
    validate_approval(&approval)?;
    let approver_id = if matches!(
        approval.decision,
        WalletApprovalDecisionKind::AutoApproved | WalletApprovalDecisionKind::ApprovedByHuman
    ) {
        Some(validate_approval_token_hybrid_signature(&approval)?)
    } else {
        None
    };
    let request_hash = approval.interception.request_hash;
    let approval_state_key = approval_key(&request_hash);
    store_typed(state, &approval_state_key, &approval)?;

    let consumption_key = approval_consumption_key(&request_hash);
    let active_revocation_epoch = load_revocation_epoch(state)?;
    match approval.approval_token.as_ref() {
        Some(token) => {
            let max_usages = effective_max_usages(token.scope.max_usages)?;
            if token.scope.expires_at <= approval.decided_at_ms {
                return Err(TransactionError::Invalid(
                    "approval_token expiry must be later than decided_at_ms".to_string(),
                ));
            }
            if token.revocation_epoch < active_revocation_epoch {
                return Err(TransactionError::Invalid(
                    "approval_token revocation_epoch is below active revocation epoch".to_string(),
                ));
            }

            let consumption_state = ApprovalConsumptionState {
                request_hash,
                target: approval.interception.target.clone(),
                session_id: approval.interception.session_id,
                bound_audience: Some(token.audience),
                issued_revocation_epoch: token.revocation_epoch,
                token_nonce: token.nonce,
                token_counter: token.counter,
                expires_at_ms: token.scope.expires_at,
                max_usages,
                uses_consumed: 0,
                remaining_usages: max_usages,
                last_consumed_at_ms: None,
            };
            store_typed(state, &consumption_key, &consumption_state)?;
        }
        None => {
            if state.get(&consumption_key)?.is_some() {
                state.delete(&consumption_key)?;
            }
        }
    }

    let mut meta = base_audit_metadata(ctx);
    meta.insert("request_hash".to_string(), hex::encode(request_hash));
    meta.insert("decision".to_string(), format!("{:?}", approval.decision));
    meta.insert("surface".to_string(), format!("{:?}", approval.surface));
    if let Some(approver_id) = approver_id {
        meta.insert("approver_id".to_string(), hex::encode(approver_id));
    }
    append_audit_event(state, ctx, VaultAuditEventKind::ApprovalDecided, meta)?;
    Ok(())
}

pub(crate) fn consume_approval_token(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConsumeApprovalTokenParams,
) -> Result<(), TransactionError> {
    if params.request_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_hash must not be all zeroes".to_string(),
        ));
    }

    let approval: WalletApprovalDecision = load_typed(state, &approval_key(&params.request_hash))?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "approval decision does not exist for request_hash".to_string(),
            )
        })?;
    if !matches!(
        approval.decision,
        WalletApprovalDecisionKind::AutoApproved | WalletApprovalDecisionKind::ApprovedByHuman
    ) {
        return Err(TransactionError::Invalid(
            "approval decision is not approved".to_string(),
        ));
    }

    let Some(token) = approval.approval_token.as_ref() else {
        return Err(TransactionError::Invalid(
            "approved decision missing approval_token".to_string(),
        ));
    };
    if token.request_hash != params.request_hash {
        return Err(TransactionError::Invalid(
            "approval_token request hash mismatch".to_string(),
        ));
    }
    if token.audience == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "approval_token audience must not be all zeroes".to_string(),
        ));
    }
    if token.nonce == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "approval_token nonce must not be all zeroes".to_string(),
        ));
    }
    if token.counter == 0 {
        return Err(TransactionError::Invalid(
            "approval_token counter must be >= 1".to_string(),
        ));
    }

    let now_ms = if params.consumed_at_ms == 0 {
        block_timestamp_ms(ctx)
    } else {
        params.consumed_at_ms
    };

    let consumption_key = approval_consumption_key(&params.request_hash);
    let mut consumption_state: ApprovalConsumptionState = load_typed(state, &consumption_key)?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "approval consumption state missing; record_approval must run first".to_string(),
            )
        })?;

    let active_revocation_epoch = load_revocation_epoch(state)?;
    if token.revocation_epoch < active_revocation_epoch
        || consumption_state.issued_revocation_epoch < active_revocation_epoch
    {
        return Err(TransactionError::Invalid(
            "approval token invalidated by revocation epoch bump".to_string(),
        ));
    }
    if consumption_state.issued_revocation_epoch != token.revocation_epoch {
        return Err(TransactionError::Invalid(
            "approval token revocation epoch binding mismatch".to_string(),
        ));
    }
    if now_ms > consumption_state.expires_at_ms {
        return Err(TransactionError::Invalid(
            "approval token has expired".to_string(),
        ));
    }
    if consumption_state.target.canonical_label() != approval.interception.target.canonical_label()
    {
        return Err(TransactionError::Invalid(
            "approval consumption target mismatch".to_string(),
        ));
    }
    if consumption_state.session_id != approval.interception.session_id {
        return Err(TransactionError::Invalid(
            "approval consumption session mismatch".to_string(),
        ));
    }
    if consumption_state.token_nonce != token.nonce
        || consumption_state.token_counter != token.counter
    {
        return Err(TransactionError::Invalid(
            "approval token replay binding mismatch".to_string(),
        ));
    }
    if consumption_state.bound_audience != Some(token.audience) {
        return Err(TransactionError::Invalid(
            "approval token audience binding mismatch".to_string(),
        ));
    }
    if ctx.signer_account_id.0 != token.audience {
        return Err(TransactionError::Invalid(
            "approval token audience does not match transaction signer".to_string(),
        ));
    }

    if consumption_state.remaining_usages == 0 {
        return Err(TransactionError::Invalid(
            "approval token has no remaining usages".to_string(),
        ));
    }

    consumption_state.uses_consumed = consumption_state.uses_consumed.saturating_add(1);
    consumption_state.remaining_usages = consumption_state.remaining_usages.saturating_sub(1);
    consumption_state.last_consumed_at_ms = Some(now_ms);
    store_typed(state, &consumption_key, &consumption_state)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("request_hash".to_string(), hex::encode(params.request_hash));
    meta.insert(
        "target".to_string(),
        approval.interception.target.canonical_label(),
    );
    meta.insert("audience".to_string(), hex::encode(token.audience));
    meta.insert(
        "token_counter".to_string(),
        consumption_state.token_counter.to_string(),
    );
    meta.insert(
        "remaining_usages".to_string(),
        consumption_state.remaining_usages.to_string(),
    );
    meta.insert(
        "revocation_epoch".to_string(),
        consumption_state.issued_revocation_epoch.to_string(),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::ApprovalDecided, meta)?;
    Ok(())
}

pub(crate) fn panic_stop(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: BumpRevocationEpochParams,
) -> Result<(), TransactionError> {
    let epoch = load_revocation_epoch(state)?.saturating_add(1);
    store_typed(state, REVOCATION_EPOCH_KEY, &epoch)?;
    store_typed(state, PANIC_FLAG_KEY, &true)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("revocation_epoch".to_string(), epoch.to_string());
    if !params.reason.trim().is_empty() {
        meta.insert("reason".to_string(), params.reason.trim().to_string());
    }
    append_audit_event(state, ctx, VaultAuditEventKind::EmergencyStop, meta)?;
    Ok(())
}

fn effective_max_usages(max_usages: Option<u32>) -> Result<u32, TransactionError> {
    match max_usages {
        Some(0) => Err(TransactionError::Invalid(
            "approval_token max_usages must be >= 1".to_string(),
        )),
        Some(value) => Ok(value),
        None => Ok(1),
    }
}
