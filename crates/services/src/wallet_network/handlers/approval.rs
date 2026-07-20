use crate::agentic::runtime::kernel::approval::ApprovalScopeContext;
use crate::wallet_network::handlers::principal_authority::validate_expected_principal_authority_binding;
use crate::wallet_network::keys::{
    approval_authority_key, approval_consumption_key, approval_effect_consumption_receipt_key,
    approval_grant_state_key, approval_key, interception_key, PANIC_FLAG_KEY, REVOCATION_EPOCH_KEY,
};
use crate::wallet_network::support::{
    append_audit_event, append_audit_event_with_records, base_audit_metadata, block_timestamp_ms,
    load_revocation_epoch, load_typed, store_typed,
};
use crate::wallet_network::validation::{validate_approval, validate_registered_approval_grant};
use crate::wallet_network::{
    ApprovalConsumptionState, ApprovalGrantConsumptionReceipt, ApprovalGrantState,
    BumpRevocationEpochParams, ConsumeApprovalGrantForEffectParams,
    ConsumeApprovalGrantForEffectV2Params, ConsumeApprovalGrantParams,
    RegisterApprovalAuthorityParams, RevokeApprovalAuthorityParams,
};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant};
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
    meta.insert(
        "policy_hash".to_string(),
        hex::encode(interception.policy_hash),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::InterceptionObserved, meta)?;
    Ok(())
}

pub(crate) fn register_approval_authority(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: RegisterApprovalAuthorityParams,
) -> Result<(), TransactionError> {
    params
        .authority
        .verify()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval authority: {}", e)))?;
    store_typed(
        state,
        &approval_authority_key(&params.authority.authority_id),
        &params.authority,
    )?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "authority_id".to_string(),
        hex::encode(params.authority.authority_id),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::ApprovalDecided, meta)?;
    Ok(())
}

pub(crate) fn revoke_approval_authority(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: RevokeApprovalAuthorityParams,
) -> Result<(), TransactionError> {
    let key = approval_authority_key(&params.authority_id);
    let mut authority: ApprovalAuthority = load_typed(state, &key)?.ok_or_else(|| {
        TransactionError::Invalid("approval authority is not registered".to_string())
    })?;
    authority.revoked = true;
    store_typed(state, &key, &authority)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("authority_id".to_string(), hex::encode(params.authority_id));
    append_audit_event(state, ctx, VaultAuditEventKind::ApprovalDecided, meta)?;
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
        let grant = approval.approval_grant.as_ref().ok_or_else(|| {
            TransactionError::Invalid("approved decision missing approval_grant".to_string())
        })?;
        let scope_context = wallet_approval_scope_context(&approval.interception);
        validate_registered_approval_grant(
            state,
            grant,
            approval.decided_at_ms,
            approval.interception.policy_hash,
            Some(&scope_context),
        )?;
        Some(grant.authority_id)
    } else {
        None
    };

    let request_hash = approval.interception.request_hash;
    let approval_state_key = approval_key(&request_hash);
    let existing_approval: Option<WalletApprovalDecision> = load_typed(state, &approval_state_key)?;
    let exact_current_replay = existing_approval.as_ref() == Some(&approval);

    let consumption_key = approval_consumption_key(&request_hash);
    let active_revocation_epoch = load_revocation_epoch(state)?;
    let records;
    match approval.approval_grant.as_ref() {
        Some(grant) => {
            let max_usages = effective_max_usages(grant.max_usages)?;
            if grant.expires_at <= approval.decided_at_ms {
                return Err(TransactionError::Invalid(
                    "approval_grant expiry must be later than decided_at_ms".to_string(),
                ));
            }

            let fresh_consumption_state = ApprovalConsumptionState {
                request_hash,
                target: approval.interception.target.clone(),
                session_id: approval.interception.session_id,
                bound_audience: Some(grant.audience),
                issued_revocation_epoch: active_revocation_epoch,
                grant_nonce: grant.nonce,
                grant_counter: grant.counter,
                expires_at_ms: grant.expires_at,
                max_usages,
                uses_consumed: 0,
                remaining_usages: max_usages,
                last_consumed_at_ms: None,
            };
            let grant_hash = grant.artifact_hash().map_err(|error| {
                TransactionError::Invalid(format!("approval grant hash failed: {error}"))
            })?;
            let same_current_grant = match existing_approval
                .as_ref()
                .and_then(|decision| decision.approval_grant.as_ref())
            {
                Some(current_grant) => {
                    current_grant.artifact_hash().map_err(|error| {
                        TransactionError::Invalid(format!(
                            "recorded approval grant hash failed: {error}"
                        ))
                    })? == grant_hash
                }
                None => false,
            };
            if same_current_grant && !exact_current_replay {
                return Err(TransactionError::Invalid(
                    "signed approval grant is already bound to a different decision snapshot"
                        .to_string(),
                ));
            }
            let grant_state_key = approval_grant_state_key(&grant_hash);
            let existing_consumption: Option<ApprovalConsumptionState> =
                load_typed(state, &consumption_key)?;
            let existing_grant: Option<ApprovalGrantState> = load_typed(state, &grant_state_key)?;
            if existing_grant.is_none() && !exact_current_replay && existing_approval.is_some() {
                return Err(TransactionError::Invalid(
                    "request history lacks this grant-keyed usage evidence; use a new request hash"
                        .to_string(),
                ));
            }
            validate_decision_replacement_order(
                existing_approval.as_ref(),
                exact_current_replay,
                approval.decided_at_ms,
            )?;
            let mut preserved_history_records = Vec::new();
            let (consumption_state, grant_state) = match existing_grant {
                Some(existing) => {
                    validate_grant_state_for_approval(&existing, &approval, grant_hash)?;
                    validate_epoch_not_future(
                        "approval grant state",
                        existing.issued_revocation_epoch,
                        active_revocation_epoch,
                    )?;
                    let request_state = if exact_current_replay {
                        let request_state = existing_consumption.ok_or_else(|| {
                            TransactionError::Invalid(
                                "exact approval replay is missing its request usage state"
                                    .to_string(),
                            )
                        })?;
                        validate_consumption_state_for_approval(&request_state, &approval)?;
                        shared_usage_counters(&existing, Some(&request_state))?;
                        request_state
                    } else {
                        if let Some(current_approval) = existing_approval.as_ref() {
                            if current_approval.approval_grant.is_some() {
                                if let Some(record) = validate_current_approved_usage(
                                    state,
                                    current_approval,
                                    &consumption_key,
                                    active_revocation_epoch,
                                )? {
                                    preserved_history_records.push(record);
                                }
                            } else if let Some(current_request_state) =
                                existing_consumption.as_ref()
                            {
                                validate_consumption_state_for_approval(
                                    current_request_state,
                                    &approval,
                                )?;
                                shared_usage_counters(&existing, Some(current_request_state))?;
                            }
                        }
                        consumption_state_from_grant_state(&approval, grant, &existing)
                    };
                    (request_state, existing)
                }
                None => {
                    let request_state = if exact_current_replay {
                        let request_state = existing_consumption.ok_or_else(|| {
                            TransactionError::Invalid(
                                "exact approval replay is missing its legacy request usage state"
                                    .to_string(),
                            )
                        })?;
                        validate_consumption_state_for_approval(&request_state, &approval)?;
                        validate_epoch_not_future(
                            "approval request consumption state",
                            request_state.issued_revocation_epoch,
                            active_revocation_epoch,
                        )?;
                        request_state
                    } else {
                        fresh_consumption_state
                    };
                    let grant_state =
                        grant_state_from_consumption(&approval, grant_hash, &request_state);
                    (request_state, grant_state)
                }
            };
            validate_consumption_state_for_approval(&consumption_state, &approval)?;
            shared_usage_counters(&grant_state, Some(&consumption_state))?;
            preserved_history_records.extend([
                (
                    approval_state_key,
                    ioi_types::codec::to_bytes_canonical(&approval)?,
                ),
                (
                    consumption_key,
                    ioi_types::codec::to_bytes_canonical(&consumption_state)?,
                ),
                (
                    grant_state_key,
                    ioi_types::codec::to_bytes_canonical(&grant_state)?,
                ),
            ]);
            records = preserved_history_records;
        }
        None => {
            validate_decision_replacement_order(
                existing_approval.as_ref(),
                exact_current_replay,
                approval.decided_at_ms,
            )?;
            let mut next_records = vec![(
                approval_state_key,
                ioi_types::codec::to_bytes_canonical(&approval)?,
            )];
            if let Some(current_approval) = existing_approval.as_ref() {
                if current_approval.approval_grant.is_some() {
                    if let Some(record) = validate_current_approved_usage(
                        state,
                        current_approval,
                        &consumption_key,
                        active_revocation_epoch,
                    )? {
                        next_records.push(record);
                    }
                }
            }
            records = next_records;
        }
    }

    let mut meta = base_audit_metadata(ctx);
    meta.insert("request_hash".to_string(), hex::encode(request_hash));
    meta.insert("decision".to_string(), format!("{:?}", approval.decision));
    meta.insert("surface".to_string(), format!("{:?}", approval.surface));
    if let Some(approver_id) = approver_id {
        meta.insert("approver_id".to_string(), hex::encode(approver_id));
    }
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        meta,
        |_| Ok(records),
    )?;
    Ok(())
}

fn validate_decision_replacement_order(
    existing: Option<&WalletApprovalDecision>,
    exact_current_replay: bool,
    decided_at_ms: u64,
) -> Result<(), TransactionError> {
    if let Some(existing) = existing {
        if !exact_current_replay && decided_at_ms <= existing.decided_at_ms {
            return Err(TransactionError::Invalid(
                "approval decision replacement must have a later decided_at_ms".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_current_approved_usage(
    state: &dyn StateAccess,
    approval: &WalletApprovalDecision,
    consumption_key: &[u8],
    active_revocation_epoch: u64,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, TransactionError> {
    let grant = approval.approval_grant.as_ref().ok_or_else(|| {
        TransactionError::Invalid("approved decision missing approval_grant".to_string())
    })?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        TransactionError::Invalid(format!("recorded approval grant hash failed: {error}"))
    })?;
    let request_state: ApprovalConsumptionState =
        load_typed(state, consumption_key)?.ok_or_else(|| {
            TransactionError::Invalid(
                "cannot replace an approved decision without its request usage state".to_string(),
            )
        })?;
    validate_consumption_state_for_approval(&request_state, approval)?;
    validate_epoch_not_future(
        "approval request consumption state",
        request_state.issued_revocation_epoch,
        active_revocation_epoch,
    )?;
    let grant_state_key = approval_grant_state_key(&grant_hash);
    match load_typed::<ApprovalGrantState>(state, &grant_state_key)? {
        Some(grant_state) => {
            validate_grant_state_for_approval(&grant_state, approval, grant_hash)?;
            validate_epoch_not_future(
                "approval grant state",
                grant_state.issued_revocation_epoch,
                active_revocation_epoch,
            )?;
            shared_usage_counters(&grant_state, Some(&request_state))?;
            Ok(None)
        }
        None => {
            let grant_state = grant_state_from_consumption(approval, grant_hash, &request_state);
            Ok(Some((
                grant_state_key,
                ioi_types::codec::to_bytes_canonical(&grant_state)?,
            )))
        }
    }
}

pub(crate) fn consume_approval_grant(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConsumeApprovalGrantParams,
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

    let Some(grant) = approval.approval_grant.as_ref() else {
        return Err(TransactionError::Invalid(
            "approved decision missing approval_grant".to_string(),
        ));
    };
    if grant.request_hash != params.request_hash {
        return Err(TransactionError::Invalid(
            "approval_grant request hash mismatch".to_string(),
        ));
    }

    let now_ms = if params.consumed_at_ms == 0 {
        block_timestamp_ms(ctx)
    } else {
        params.consumed_at_ms
    };

    let scope_context = wallet_approval_scope_context(&approval.interception);
    validate_registered_approval_grant(
        state,
        grant,
        now_ms,
        approval.interception.policy_hash,
        Some(&scope_context),
    )?;

    let consumption_key = approval_consumption_key(&params.request_hash);
    let mut consumption_state: ApprovalConsumptionState = load_typed(state, &consumption_key)?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "approval consumption state missing; record_approval must run first".to_string(),
            )
        })?;

    let active_revocation_epoch = load_revocation_epoch(state)?;
    if consumption_state.issued_revocation_epoch < active_revocation_epoch {
        return Err(TransactionError::Invalid(
            "approval grant invalidated by revocation epoch bump".to_string(),
        ));
    }
    if now_ms > consumption_state.expires_at_ms {
        return Err(TransactionError::Invalid(
            "approval grant has expired".to_string(),
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
    if consumption_state.grant_nonce != grant.nonce
        || consumption_state.grant_counter != grant.counter
    {
        return Err(TransactionError::Invalid(
            "approval grant replay binding mismatch".to_string(),
        ));
    }
    if consumption_state.bound_audience != Some(grant.audience) {
        return Err(TransactionError::Invalid(
            "approval grant audience binding mismatch".to_string(),
        ));
    }
    if ctx.signer_account_id.0 != grant.audience {
        return Err(TransactionError::Invalid(
            "approval grant audience does not match transaction signer".to_string(),
        ));
    }

    let grant_hash = grant.artifact_hash().map_err(|error| {
        TransactionError::Invalid(format!("approval grant hash failed: {error}"))
    })?;
    let grant_state_key = approval_grant_state_key(&grant_hash);
    let mut grant_state: ApprovalGrantState = match load_typed(state, &grant_state_key)? {
        Some(existing) => existing,
        None => grant_state_from_consumption(&approval, grant_hash, &consumption_state),
    };
    validate_grant_state_for_approval(&grant_state, &approval, grant_hash)?;
    validate_consumption_state_for_approval(&consumption_state, &approval)?;
    let (uses_consumed, remaining_usages) =
        shared_usage_counters(&grant_state, Some(&consumption_state))?;
    if remaining_usages == 0 {
        return Err(TransactionError::Invalid(
            "approval grant has no remaining usages".to_string(),
        ));
    }

    let next_uses_consumed = uses_consumed.saturating_add(1);
    let next_remaining_usages = remaining_usages.saturating_sub(1);
    consumption_state.uses_consumed = next_uses_consumed;
    consumption_state.remaining_usages = next_remaining_usages;
    consumption_state.last_consumed_at_ms = Some(now_ms);
    grant_state.uses_consumed = next_uses_consumed;
    grant_state.remaining_usages = next_remaining_usages;
    grant_state.last_consumed_at_ms = Some(now_ms);

    let mut meta = base_audit_metadata(ctx);
    meta.insert("request_hash".to_string(), hex::encode(params.request_hash));
    meta.insert(
        "target".to_string(),
        approval.interception.target.canonical_label(),
    );
    meta.insert("audience".to_string(), hex::encode(grant.audience));
    meta.insert(
        "grant_counter".to_string(),
        consumption_state.grant_counter.to_string(),
    );
    meta.insert(
        "remaining_usages".to_string(),
        consumption_state.remaining_usages.to_string(),
    );
    meta.insert(
        "revocation_epoch".to_string(),
        consumption_state.issued_revocation_epoch.to_string(),
    );
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        meta,
        |_| {
            Ok(vec![
                (
                    consumption_key,
                    ioi_types::codec::to_bytes_canonical(&consumption_state)?,
                ),
                (
                    grant_state_key,
                    ioi_types::codec::to_bytes_canonical(&grant_state)?,
                ),
            ])
        },
    )?;
    Ok(())
}

pub(crate) fn consume_approval_grant_for_effect(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConsumeApprovalGrantForEffectParams,
) -> Result<(), TransactionError> {
    consume_approval_grant_for_effect_inner(state, ctx, params, None)
}

pub(crate) fn consume_approval_grant_for_effect_v2(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConsumeApprovalGrantForEffectV2Params,
) -> Result<(), TransactionError> {
    let ConsumeApprovalGrantForEffectV2Params {
        request_hash,
        grant_hash,
        consumption_id,
        expected_principal_authority,
        expected_target_label,
        expected_max_usages,
    } = params;
    consume_approval_grant_for_effect_inner(
        state,
        ctx,
        ConsumeApprovalGrantForEffectParams {
            request_hash,
            grant_hash,
            consumption_id,
            expected_principal_authority,
        },
        Some((expected_target_label, expected_max_usages)),
    )
}

fn consume_approval_grant_for_effect_inner(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConsumeApprovalGrantForEffectParams,
    exact_expectations: Option<(String, u32)>,
) -> Result<(), TransactionError> {
    if params.request_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_hash must not be all zeroes".to_string(),
        ));
    }
    if params.consumption_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "consumption_id must not be all zeroes".to_string(),
        ));
    }
    if params.grant_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "grant_hash must not be all zeroes".to_string(),
        ));
    }
    if let Some((expected_target_label, expected_max_usages)) = exact_expectations.as_ref() {
        if expected_target_label.is_empty() || expected_target_label.len() > 256 {
            return Err(TransactionError::Invalid(
                "expected_target_label must contain 1..=256 bytes".to_string(),
            ));
        }
        if *expected_max_usages == 0 {
            return Err(TransactionError::Invalid(
                "expected_max_usages must be positive".to_string(),
            ));
        }
    }

    let receipt_key = approval_effect_consumption_receipt_key(&params.consumption_id);
    if let Some(existing_bytes) = state.get(&receipt_key)? {
        let existing: ApprovalGrantConsumptionReceipt =
            ioi_types::codec::from_bytes_canonical(&existing_bytes).map_err(|error| {
                TransactionError::Invalid(format!(
                    "approval effect consumption receipt is unreadable: {error}"
                ))
            })?;
        if existing.request_hash != params.request_hash
            || existing.grant_hash != params.grant_hash
            || existing.consumption_id != params.consumption_id
            || existing.principal_authority != params.expected_principal_authority
        {
            return Err(TransactionError::Invalid(
                "approval effect consumption id is bound to a different request or grant, or a different principal authority".to_string(),
            ));
        }
        if exact_expectations
            .as_ref()
            .is_some_and(|(target, _)| existing.target.canonical_label() != target.as_str())
        {
            return Err(TransactionError::Invalid(
                "approval effect consumption id is bound to a different target".to_string(),
            ));
        }
        let grant_state: ApprovalGrantState =
            load_typed(state, &approval_grant_state_key(&params.grant_hash))?.ok_or_else(|| {
                TransactionError::Invalid(
                    "approval grant state is missing for an existing effect receipt".to_string(),
                )
            })?;
        if exact_expectations
            .as_ref()
            .is_some_and(|(_, expected)| grant_state.max_usages != *expected)
        {
            return Err(TransactionError::Invalid(
                "approval effect consumption id is bound to a different grant-use ceiling"
                    .to_string(),
            ));
        }
        validate_effect_receipt(&existing, &grant_state)?;
        return Ok(());
    }

    let grant_state_key = approval_grant_state_key(&params.grant_hash);
    let grant_state: ApprovalGrantState = match load_typed(state, &grant_state_key)? {
        Some(existing) => existing,
        None => derive_legacy_grant_state_for_effect(state, &params)?,
    };
    validate_grant_state_identity(&grant_state, &params)?;
    let current_approval: WalletApprovalDecision =
        load_typed(state, &approval_key(&params.request_hash))?.ok_or_else(|| {
            TransactionError::Invalid(
                "approval decision does not exist for request_hash".to_string(),
            )
        })?;
    if current_approval != grant_state.approval {
        return Err(TransactionError::Invalid(
            "approval grant is not the current request decision".to_string(),
        ));
    }
    if !matches!(
        grant_state.approval.decision,
        WalletApprovalDecisionKind::AutoApproved | WalletApprovalDecisionKind::ApprovedByHuman
    ) {
        return Err(TransactionError::Invalid(
            "approval decision is not approved".to_string(),
        ));
    }
    let actual_target = grant_state.approval.interception.target.canonical_label();
    if exact_expectations
        .as_ref()
        .is_some_and(|(expected, _)| actual_target != expected.as_str())
    {
        return Err(TransactionError::Invalid(
            "approval_effect_expected_target_mismatch: approval decision target does not match the effect's expected target".to_string(),
        ));
    }
    if exact_expectations
        .as_ref()
        .is_some_and(|(_, expected)| grant_state.max_usages != *expected)
    {
        return Err(TransactionError::Invalid(
            "approval_effect_expected_max_usages_mismatch: approval grant use ceiling does not match the effect's expected ceiling".to_string(),
        ));
    }
    let grant = grant_state
        .approval
        .approval_grant
        .as_ref()
        .ok_or_else(|| {
            TransactionError::Invalid("approved decision missing approval_grant".to_string())
        })?;
    let now_ms = block_timestamp_ms(ctx);
    let scope_context = wallet_approval_scope_context(&grant_state.approval.interception);
    validate_registered_approval_grant(
        state,
        grant,
        now_ms,
        grant_state.approval.interception.policy_hash,
        Some(&scope_context),
    )?;
    validate_live_grant_state(ctx, &grant_state, now_ms, load_revocation_epoch(state)?)?;
    let principal_authority = validate_expected_principal_authority_binding(
        state,
        ctx,
        &params.expected_principal_authority,
    )?;
    if principal_authority.authority_id != grant.authority_id
        || principal_authority.public_key != grant.approver_public_key
        || principal_authority.signature_suite != grant.approver_suite
    {
        return Err(TransactionError::Invalid(
            "approval grant signer does not match the exact current principal authority"
                .to_string(),
        ));
    }
    if grant_state.remaining_usages == 0 {
        return Err(TransactionError::Invalid(
            "approval grant has no remaining usages".to_string(),
        ));
    }

    let mut request_consumption_state =
        load_current_request_consumption_for_grant(state, &grant_state)?;
    let (uses_consumed, remaining_usages) = shared_usage_counters(
        &grant_state,
        request_consumption_state
            .as_ref()
            .map(|(_, consumption)| consumption),
    )?;
    if remaining_usages == 0 {
        return Err(TransactionError::Invalid(
            "approval grant has no remaining usages".to_string(),
        ));
    }

    let mut next_state = grant_state.clone();
    next_state.uses_consumed = uses_consumed.saturating_add(1);
    next_state.remaining_usages = remaining_usages.saturating_sub(1);
    next_state.last_consumed_at_ms = Some(now_ms);
    if let Some((_, consumption)) = request_consumption_state.as_mut() {
        consumption.uses_consumed = next_state.uses_consumed;
        consumption.remaining_usages = next_state.remaining_usages;
        consumption.last_consumed_at_ms = Some(now_ms);
    }
    let mut receipt = ApprovalGrantConsumptionReceipt {
        schema_version: 1,
        receipt_hash: [0u8; 32],
        request_hash: params.request_hash,
        grant_hash: params.grant_hash,
        consumption_id: params.consumption_id,
        principal_authority: params.expected_principal_authority.clone(),
        policy_hash: grant_state.approval.interception.policy_hash,
        authority_id: grant.authority_id,
        target: grant_state.approval.interception.target.clone(),
        session_id: grant_state.approval.interception.session_id,
        audience: grant.audience,
        issued_revocation_epoch: next_state.issued_revocation_epoch,
        grant_nonce: grant.nonce,
        grant_counter: grant.counter,
        consumed_at_ms: now_ms,
        usage_ordinal: next_state.uses_consumed,
        remaining_usages: next_state.remaining_usages,
    };
    receipt.receipt_hash = effect_receipt_hash(&receipt)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("request_hash".to_string(), hex::encode(params.request_hash));
    meta.insert(
        "consumption_id".to_string(),
        hex::encode(params.consumption_id),
    );
    meta.insert(
        "target".to_string(),
        grant_state.approval.interception.target.canonical_label(),
    );
    meta.insert("audience".to_string(), hex::encode(grant.audience));
    meta.insert("grant_counter".to_string(), grant.counter.to_string());
    meta.insert(
        "remaining_usages".to_string(),
        next_state.remaining_usages.to_string(),
    );
    meta.insert(
        "revocation_epoch".to_string(),
        next_state.issued_revocation_epoch.to_string(),
    );
    append_audit_event_with_records(
        state,
        ctx,
        VaultAuditEventKind::ApprovalDecided,
        meta,
        |_| {
            let mut records = vec![
                (
                    grant_state_key,
                    ioi_types::codec::to_bytes_canonical(&next_state)?,
                ),
                (receipt_key, ioi_types::codec::to_bytes_canonical(&receipt)?),
            ];
            if let Some((key, consumption)) = request_consumption_state {
                records.push((key, ioi_types::codec::to_bytes_canonical(&consumption)?));
            }
            Ok(records)
        },
    )?;
    Ok(())
}

fn validate_grant_state_for_approval(
    grant_state: &ApprovalGrantState,
    approval: &WalletApprovalDecision,
    expected_grant_hash: [u8; 32],
) -> Result<(), TransactionError> {
    let grant = approval.approval_grant.as_ref().ok_or_else(|| {
        TransactionError::Invalid("approved decision missing approval_grant".to_string())
    })?;
    let actual_grant_hash = grant.artifact_hash().map_err(|error| {
        TransactionError::Invalid(format!("approval grant hash failed: {error}"))
    })?;
    let max_usages = effective_max_usages(grant.max_usages)?;
    if grant_state.schema_version != 1
        || grant_state.grant_hash != expected_grant_hash
        || actual_grant_hash != expected_grant_hash
        || grant_state.approval != *approval
        || grant_state.max_usages != max_usages
    {
        return Err(TransactionError::Invalid(
            "approval grant state conflicts with the exact recorded approval".to_string(),
        ));
    }
    validate_usage_counters(
        "approval grant state",
        grant_state.max_usages,
        grant_state.uses_consumed,
        grant_state.remaining_usages,
    )
}

fn grant_state_from_consumption(
    approval: &WalletApprovalDecision,
    grant_hash: [u8; 32],
    consumption_state: &ApprovalConsumptionState,
) -> ApprovalGrantState {
    ApprovalGrantState {
        schema_version: 1,
        grant_hash,
        approval: approval.clone(),
        issued_revocation_epoch: consumption_state.issued_revocation_epoch,
        max_usages: consumption_state.max_usages,
        uses_consumed: consumption_state.uses_consumed,
        remaining_usages: consumption_state.remaining_usages,
        last_consumed_at_ms: consumption_state.last_consumed_at_ms,
    }
}

fn consumption_state_from_grant_state(
    approval: &WalletApprovalDecision,
    grant: &ApprovalGrant,
    grant_state: &ApprovalGrantState,
) -> ApprovalConsumptionState {
    ApprovalConsumptionState {
        request_hash: approval.interception.request_hash,
        target: approval.interception.target.clone(),
        session_id: approval.interception.session_id,
        bound_audience: Some(grant.audience),
        issued_revocation_epoch: grant_state.issued_revocation_epoch,
        grant_nonce: grant.nonce,
        grant_counter: grant.counter,
        expires_at_ms: grant.expires_at,
        max_usages: grant_state.max_usages,
        uses_consumed: grant_state.uses_consumed,
        remaining_usages: grant_state.remaining_usages,
        last_consumed_at_ms: grant_state.last_consumed_at_ms,
    }
}

fn validate_epoch_not_future(
    label: &str,
    issued_revocation_epoch: u64,
    active_revocation_epoch: u64,
) -> Result<(), TransactionError> {
    if issued_revocation_epoch > active_revocation_epoch {
        return Err(TransactionError::Invalid(format!(
            "{label} was issued under a future revocation epoch"
        )));
    }
    Ok(())
}

fn derive_legacy_grant_state_for_effect(
    state: &dyn StateAccess,
    params: &ConsumeApprovalGrantForEffectParams,
) -> Result<ApprovalGrantState, TransactionError> {
    let approval: WalletApprovalDecision = load_typed(state, &approval_key(&params.request_hash))?
        .ok_or_else(|| {
            TransactionError::Invalid(
                "approval grant state and legacy approval decision are both missing".to_string(),
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
    let grant = approval.approval_grant.as_ref().ok_or_else(|| {
        TransactionError::Invalid("approved decision missing approval_grant".to_string())
    })?;
    let grant_hash = grant.artifact_hash().map_err(|error| {
        TransactionError::Invalid(format!("approval grant hash failed: {error}"))
    })?;
    if grant.request_hash != params.request_hash || grant_hash != params.grant_hash {
        return Err(TransactionError::Invalid(
            "legacy approval does not bind the requested canonical grant".to_string(),
        ));
    }

    let consumption: ApprovalConsumptionState =
        load_typed(state, &approval_consumption_key(&params.request_hash))?.ok_or_else(|| {
            TransactionError::Invalid(
                "approval consumption state missing; record_approval must run first".to_string(),
            )
        })?;
    validate_consumption_state_for_approval(&consumption, &approval)?;
    Ok(grant_state_from_consumption(
        &approval,
        grant_hash,
        &consumption,
    ))
}

fn validate_consumption_state_for_approval(
    consumption_state: &ApprovalConsumptionState,
    approval: &WalletApprovalDecision,
) -> Result<(), TransactionError> {
    let grant = approval.approval_grant.as_ref().ok_or_else(|| {
        TransactionError::Invalid("approved decision missing approval_grant".to_string())
    })?;
    let max_usages = effective_max_usages(grant.max_usages)?;
    if consumption_state.request_hash != approval.interception.request_hash
        || consumption_state.target.canonical_label()
            != approval.interception.target.canonical_label()
        || consumption_state.session_id != approval.interception.session_id
        || consumption_state.bound_audience != Some(grant.audience)
        || consumption_state.grant_nonce != grant.nonce
        || consumption_state.grant_counter != grant.counter
        || consumption_state.expires_at_ms != grant.expires_at
        || consumption_state.max_usages != max_usages
    {
        return Err(TransactionError::Invalid(
            "approval request consumption state conflicts with the exact recorded grant"
                .to_string(),
        ));
    }
    validate_usage_counters(
        "approval request consumption state",
        consumption_state.max_usages,
        consumption_state.uses_consumed,
        consumption_state.remaining_usages,
    )
}

fn load_current_request_consumption_for_grant(
    state: &dyn StateAccess,
    grant_state: &ApprovalGrantState,
) -> Result<Option<(Vec<u8>, ApprovalConsumptionState)>, TransactionError> {
    let request_hash = grant_state.approval.interception.request_hash;
    let current_approval: Option<WalletApprovalDecision> =
        load_typed(state, &approval_key(&request_hash))?;
    if current_approval.as_ref() != Some(&grant_state.approval) {
        return Ok(None);
    }

    let key = approval_consumption_key(&request_hash);
    let consumption: ApprovalConsumptionState = load_typed(state, &key)?.ok_or_else(|| {
        TransactionError::Invalid(
            "approval consumption state missing; record_approval must run first".to_string(),
        )
    })?;
    validate_consumption_state_for_approval(&consumption, &grant_state.approval)?;
    if consumption.issued_revocation_epoch != grant_state.issued_revocation_epoch {
        return Err(TransactionError::Invalid(
            "approval grant usage records disagree on revocation epoch".to_string(),
        ));
    }
    Ok(Some((key, consumption)))
}

fn shared_usage_counters(
    grant_state: &ApprovalGrantState,
    request_state: Option<&ApprovalConsumptionState>,
) -> Result<(u32, u32), TransactionError> {
    validate_usage_counters(
        "approval grant state",
        grant_state.max_usages,
        grant_state.uses_consumed,
        grant_state.remaining_usages,
    )?;
    let Some(request_state) = request_state else {
        return Ok((grant_state.uses_consumed, grant_state.remaining_usages));
    };
    if request_state.max_usages != grant_state.max_usages {
        return Err(TransactionError::Invalid(
            "approval grant usage records disagree on max_usages".to_string(),
        ));
    }
    validate_usage_counters(
        "approval request consumption state",
        request_state.max_usages,
        request_state.uses_consumed,
        request_state.remaining_usages,
    )?;
    if request_state.issued_revocation_epoch != grant_state.issued_revocation_epoch
        || request_state.uses_consumed != grant_state.uses_consumed
        || request_state.remaining_usages != grant_state.remaining_usages
        || request_state.last_consumed_at_ms != grant_state.last_consumed_at_ms
    {
        return Err(TransactionError::Invalid(
            "approval grant usage records disagree; refusing an ambiguous shared budget"
                .to_string(),
        ));
    }
    Ok((grant_state.uses_consumed, grant_state.remaining_usages))
}

fn validate_usage_counters(
    label: &str,
    max_usages: u32,
    uses_consumed: u32,
    remaining_usages: u32,
) -> Result<(), TransactionError> {
    if max_usages == 0
        || uses_consumed > max_usages
        || remaining_usages > max_usages
        || uses_consumed.checked_add(remaining_usages) != Some(max_usages)
    {
        return Err(TransactionError::Invalid(format!(
            "{label} has invalid usage counters"
        )));
    }
    Ok(())
}

fn validate_grant_state_identity(
    grant_state: &ApprovalGrantState,
    params: &ConsumeApprovalGrantForEffectParams,
) -> Result<(), TransactionError> {
    let grant = grant_state
        .approval
        .approval_grant
        .as_ref()
        .ok_or_else(|| {
            TransactionError::Invalid("approved decision missing approval_grant".to_string())
        })?;
    let actual_hash = grant.artifact_hash().map_err(|error| {
        TransactionError::Invalid(format!("approval grant hash failed: {error}"))
    })?;
    if grant_state.schema_version != 1
        || grant_state.grant_hash != params.grant_hash
        || actual_hash != params.grant_hash
        || grant_state.approval.interception.request_hash != params.request_hash
        || grant.request_hash != params.request_hash
    {
        return Err(TransactionError::Invalid(
            "approval grant state differs from the exact request and canonical grant hash"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_live_grant_state(
    ctx: &TxContext<'_>,
    grant_state: &ApprovalGrantState,
    now_ms: u64,
    active_revocation_epoch: u64,
) -> Result<(), TransactionError> {
    let approval = &grant_state.approval;
    let grant = approval.approval_grant.as_ref().ok_or_else(|| {
        TransactionError::Invalid("approved decision missing approval_grant".to_string())
    })?;
    if grant_state.issued_revocation_epoch < active_revocation_epoch {
        return Err(TransactionError::Invalid(
            "approval grant invalidated by revocation epoch bump".to_string(),
        ));
    }
    if now_ms > grant.expires_at {
        return Err(TransactionError::Invalid(
            "approval grant has expired".to_string(),
        ));
    }
    if ctx.signer_account_id.0 != grant.audience {
        return Err(TransactionError::Invalid(
            "approval grant audience does not match transaction signer".to_string(),
        ));
    }
    Ok(())
}

fn validate_effect_receipt(
    receipt: &ApprovalGrantConsumptionReceipt,
    grant_state: &ApprovalGrantState,
) -> Result<(), TransactionError> {
    let approval = &grant_state.approval;
    let grant = approval.approval_grant.as_ref().ok_or_else(|| {
        TransactionError::Invalid("approved decision missing approval_grant".to_string())
    })?;
    let receipt_is_exact = receipt.schema_version == 1
        && receipt.receipt_hash == effect_receipt_hash(receipt)?
        && receipt.request_hash == approval.interception.request_hash
        && receipt.grant_hash == grant_state.grant_hash
        && receipt.policy_hash == approval.interception.policy_hash
        && receipt.authority_id == grant.authority_id
        && receipt.target.canonical_label() == approval.interception.target.canonical_label()
        && receipt.session_id == approval.interception.session_id
        && receipt.audience == grant.audience
        && receipt.issued_revocation_epoch == grant_state.issued_revocation_epoch
        && receipt.grant_nonce == grant.nonce
        && receipt.grant_counter == grant.counter
        && receipt.principal_authority.approval_authority.authority_id == grant.authority_id
        && receipt.principal_authority.approval_authority.public_key == grant.approver_public_key
        && receipt
            .principal_authority
            .approval_authority
            .signature_suite
            == grant.approver_suite
        && receipt.principal_authority.approval_authority_snapshot_hash
            == receipt
                .principal_authority
                .approval_authority
                .artifact_hash()
                .map_err(|error| {
                    TransactionError::Invalid(format!(
                        "approval effect consumption authority snapshot cannot be hashed: {error}"
                    ))
                })?
        && receipt.usage_ordinal > 0
        && receipt.usage_ordinal <= grant_state.uses_consumed
        && receipt
            .remaining_usages
            .saturating_add(receipt.usage_ordinal)
            == grant_state.max_usages
        && receipt.remaining_usages >= grant_state.remaining_usages;
    if !receipt_is_exact {
        return Err(TransactionError::Invalid(
            "approval effect consumption receipt conflicts with the durable intent".to_string(),
        ));
    }
    Ok(())
}

fn effect_receipt_hash(
    receipt: &ApprovalGrantConsumptionReceipt,
) -> Result<[u8; 32], TransactionError> {
    let mut material = serde_json::to_value(receipt).map_err(|error| {
        TransactionError::Invalid(format!(
            "approval effect consumption receipt cannot be serialized: {error}"
        ))
    })?;
    material["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
    let canonical = serde_jcs::to_vec(&material).map_err(|error| {
        TransactionError::Invalid(format!(
            "approval effect consumption receipt cannot be canonicalized: {error}"
        ))
    })?;
    let digest = DcryptSha256::digest(&canonical)
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    Ok(output)
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
            "approval_grant max_usages must be >= 1".to_string(),
        )),
        Some(value) => Ok(value),
        None => Ok(1),
    }
}

fn wallet_approval_scope_context(interception: &WalletInterceptionContext) -> ApprovalScopeContext {
    let mut context = ApprovalScopeContext::new(interception.target.canonical_label())
        .with_operation_label("wallet_network.approval");
    context.push_label(format!("target:{}", interception.target.canonical_label()));
    if let Some(session_id) = interception.session_id {
        context.push_label(format!("session:{}", hex::encode(session_id)));
    }
    context
}
