// Path: crates/services/src/wallet_network/handlers/connectors/delete.rs

use super::shared::{
    contains_mail_delete_capability, enforce_connector_action_replay_window,
    enforce_delete_cleanup_mailbox_target, enforce_mailbox_constraint, load_mail_connector_record,
    normalize_delete_limit, normalize_mailbox, resolve_mail_provider_credentials,
    LEASE_OPERATION_TRACK_LIMIT,
};
use crate::wallet_network::keys::{
    channel_key, lease_action_window_key, lease_consumption_key, lease_key,
    mail_delete_receipt_key,
};
use crate::wallet_network::mail_transport::mail_provider_for_config;
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_revocation_epoch, load_typed,
    store_typed,
};
use crate::wallet_network::{LeaseActionReplayWindowState, LeaseConsumptionState};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    MailDeleteSpamParams, MailDeleteSpamReceipt, SessionChannelRecord, SessionChannelState,
    SessionLease, SessionLeaseMode, VaultAuditEventKind,
};
use ioi_types::error::TransactionError;
use std::collections::BTreeMap;

pub(crate) fn mail_delete_spam(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MailDeleteSpamParams,
) -> Result<(), TransactionError> {
    if params.operation_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "operation_id must not be all zeroes".to_string(),
        ));
    }
    if params.channel_id == [0u8; 32] || params.lease_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "channel_id and lease_id must not be all zeroes".to_string(),
        ));
    }
    if params.op_seq == 0 {
        return Err(TransactionError::Invalid("op_seq must be >= 1".to_string()));
    }
    if params.op_nonce.is_some_and(|nonce| nonce == [0u8; 32]) {
        return Err(TransactionError::Invalid(
            "op_nonce must not be all zeroes when provided".to_string(),
        ));
    }

    let now_ms = block_timestamp_ms(ctx);
    let mailbox = normalize_mailbox(&params.mailbox);
    let delete_limit = normalize_delete_limit(params.max_delete);
    enforce_delete_cleanup_mailbox_target(&mailbox)?;

    let channel: SessionChannelRecord = load_typed(state, &channel_key(&params.channel_id))?
        .ok_or_else(|| TransactionError::Invalid("channel does not exist".to_string()))?;
    if channel.state != SessionChannelState::Open {
        return Err(TransactionError::Invalid(
            "channel must be open for connector mail operations".to_string(),
        ));
    }
    if now_ms > channel.envelope.expires_at_ms {
        return Err(TransactionError::Invalid("channel has expired".to_string()));
    }

    let lease: SessionLease = load_typed(state, &lease_key(&params.channel_id, &params.lease_id))?
        .ok_or_else(|| TransactionError::Invalid("lease does not exist".to_string()))?;
    if lease.channel_id != params.channel_id {
        return Err(TransactionError::Invalid(
            "lease channel binding mismatch".to_string(),
        ));
    }
    if now_ms > lease.expires_at_ms {
        return Err(TransactionError::Invalid("lease has expired".to_string()));
    }

    let active_revocation_epoch = load_revocation_epoch(state)?;
    if lease.revocation_epoch < active_revocation_epoch
        || channel.envelope.revocation_epoch < active_revocation_epoch
    {
        return Err(TransactionError::Invalid(
            "lease/channel invalidated by revocation epoch bump".to_string(),
        ));
    }

    if lease.audience != ctx.signer_account_id.0 {
        return Err(TransactionError::Invalid(
            "lease audience does not match transaction signer".to_string(),
        ));
    }
    if !contains_mail_delete_capability(&lease.capability_subset) {
        return Err(TransactionError::Invalid(
            "lease does not authorize mail delete capability".to_string(),
        ));
    }
    if !contains_mail_delete_capability(&channel.envelope.capability_set) {
        return Err(TransactionError::Invalid(
            "channel does not authorize mail delete capability".to_string(),
        ));
    }
    enforce_mailbox_constraint(lease.constraints_subset.get("mailbox"), &mailbox)?;
    enforce_mailbox_constraint(channel.envelope.constraints.get("mailbox"), &mailbox)?;

    let receipt_key = mail_delete_receipt_key(&params.operation_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "mail operation_id replay detected".to_string(),
        ));
    }

    let action_window_key = lease_action_window_key(&params.channel_id, &params.lease_id);
    let mut action_window = load_typed::<LeaseActionReplayWindowState>(state, &action_window_key)?
        .unwrap_or(LeaseActionReplayWindowState {
            channel_id: params.channel_id,
            lease_id: params.lease_id,
            ordering: channel.envelope.ordering,
            highest_seq: 0,
            seen_seqs: Default::default(),
            seen_nonces: Vec::new(),
        });
    if action_window.channel_id != params.channel_id || action_window.lease_id != params.lease_id {
        return Err(TransactionError::Invalid(
            "lease action replay window binding mismatch".to_string(),
        ));
    }
    if action_window.ordering != channel.envelope.ordering {
        return Err(TransactionError::Invalid(
            "lease action replay ordering mismatch with channel envelope".to_string(),
        ));
    }
    enforce_connector_action_replay_window(&mut action_window, params.op_seq, params.op_nonce)?;

    let consumption_key = lease_consumption_key(&params.channel_id, &params.lease_id);
    let mut consumption = load_typed::<LeaseConsumptionState>(state, &consumption_key)?.unwrap_or(
        LeaseConsumptionState {
            channel_id: params.channel_id,
            lease_id: params.lease_id,
            mode: lease.mode,
            audience: lease.audience,
            revocation_epoch: lease.revocation_epoch,
            expires_at_ms: lease.expires_at_ms,
            consumed_count: 0,
            consumed_operation_ids: Vec::new(),
            last_consumed_at_ms: None,
        },
    );

    if consumption.channel_id != params.channel_id || consumption.lease_id != params.lease_id {
        return Err(TransactionError::Invalid(
            "lease consumption state binding mismatch".to_string(),
        ));
    }
    if consumption.mode != lease.mode {
        return Err(TransactionError::Invalid(
            "lease consumption mode mismatch".to_string(),
        ));
    }
    if consumption.audience != lease.audience {
        return Err(TransactionError::Invalid(
            "lease consumption audience mismatch".to_string(),
        ));
    }
    if consumption.revocation_epoch != lease.revocation_epoch {
        return Err(TransactionError::Invalid(
            "lease consumption revocation_epoch mismatch".to_string(),
        ));
    }
    if consumption.expires_at_ms != lease.expires_at_ms {
        return Err(TransactionError::Invalid(
            "lease consumption expiry mismatch".to_string(),
        ));
    }
    if consumption
        .consumed_operation_ids
        .iter()
        .any(|op_id| *op_id == params.operation_id)
    {
        return Err(TransactionError::Invalid(
            "mail operation_id already consumed for this lease".to_string(),
        ));
    }
    if matches!(lease.mode, SessionLeaseMode::OneShot) && consumption.consumed_count > 0 {
        return Err(TransactionError::Invalid(
            "one-shot lease already consumed".to_string(),
        ));
    }

    let connector = load_mail_connector_record(state, &mailbox)?;
    let credentials = resolve_mail_provider_credentials(state, &connector)?;
    let provider = mail_provider_for_config(&connector.config)?;
    let delete_outcome =
        provider.delete_spam(&connector.config, &credentials, &mailbox, delete_limit)?;
    if delete_outcome.deleted_count > delete_limit {
        return Err(TransactionError::Invalid(format!(
            "mail provider deleted_count {} exceeds requested max_delete {}",
            delete_outcome.deleted_count, delete_limit
        )));
    }
    let preserved_reason_counts = BTreeMap::from([
        (
            "transactional_or_personal".to_string(),
            delete_outcome.preserved_transactional_or_personal_count,
        ),
        (
            "trusted_system_sender".to_string(),
            delete_outcome.preserved_trusted_system_count,
        ),
        (
            "low_confidence_other".to_string(),
            delete_outcome.preserved_low_confidence_other_count,
        ),
        (
            "delete_cap_guardrail".to_string(),
            delete_outcome.preserved_due_to_delete_cap_count,
        ),
    ]);

    let receipt = MailDeleteSpamReceipt {
        operation_id: params.operation_id,
        channel_id: params.channel_id,
        lease_id: params.lease_id,
        mailbox: mailbox.clone(),
        audience: lease.audience,
        executed_at_ms: now_ms,
        deleted_count: delete_outcome.deleted_count,
        evaluated_count: delete_outcome.evaluated_count,
        high_confidence_deleted_count: delete_outcome.high_confidence_deleted_count,
        skipped_low_confidence_count: delete_outcome.skipped_low_confidence_count,
        mailbox_total_count_before: delete_outcome.mailbox_total_count_before,
        mailbox_total_count_after: delete_outcome.mailbox_total_count_after,
        mailbox_total_count_delta: delete_outcome.mailbox_total_count_delta,
        spam_confidence_threshold_bps: delete_outcome.spam_confidence_threshold_bps,
        ontology_version: delete_outcome.ontology_version.clone(),
        cleanup_scope: delete_outcome.cleanup_scope.clone(),
        preserved_transactional_or_personal_count: delete_outcome
            .preserved_transactional_or_personal_count,
        preserved_trusted_system_count: delete_outcome.preserved_trusted_system_count,
        preserved_low_confidence_other_count: delete_outcome.preserved_low_confidence_other_count,
        preserved_due_to_delete_cap_count: delete_outcome.preserved_due_to_delete_cap_count,
        preserved_reason_counts: preserved_reason_counts.clone(),
    };
    store_typed(state, &receipt_key, &receipt)?;

    consumption.consumed_count = consumption.consumed_count.saturating_add(1);
    consumption.consumed_operation_ids.push(params.operation_id);
    if consumption.consumed_operation_ids.len() > LEASE_OPERATION_TRACK_LIMIT {
        let excess = consumption.consumed_operation_ids.len() - LEASE_OPERATION_TRACK_LIMIT;
        consumption.consumed_operation_ids.drain(0..excess);
    }
    consumption.last_consumed_at_ms = Some(now_ms);
    store_typed(state, &consumption_key, &consumption)?;
    store_typed(state, &action_window_key, &action_window)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("operation".to_string(), "mail_delete_spam@v1".to_string());
    meta.insert("operation_id".to_string(), hex::encode(params.operation_id));
    meta.insert("op_seq".to_string(), params.op_seq.to_string());
    meta.insert("channel_id".to_string(), hex::encode(params.channel_id));
    meta.insert("lease_id".to_string(), hex::encode(params.lease_id));
    meta.insert("mailbox".to_string(), mailbox);
    meta.insert(
        "deleted_count".to_string(),
        delete_outcome.deleted_count.to_string(),
    );
    meta.insert(
        "evaluated_count".to_string(),
        delete_outcome.evaluated_count.to_string(),
    );
    meta.insert(
        "high_confidence_deleted_count".to_string(),
        delete_outcome.high_confidence_deleted_count.to_string(),
    );
    meta.insert(
        "skipped_low_confidence_count".to_string(),
        delete_outcome.skipped_low_confidence_count.to_string(),
    );
    meta.insert(
        "mailbox_total_count_before".to_string(),
        delete_outcome.mailbox_total_count_before.to_string(),
    );
    meta.insert(
        "mailbox_total_count_after".to_string(),
        delete_outcome.mailbox_total_count_after.to_string(),
    );
    meta.insert(
        "mailbox_total_count_delta".to_string(),
        delete_outcome.mailbox_total_count_delta.to_string(),
    );
    meta.insert(
        "spam_confidence_threshold_bps".to_string(),
        delete_outcome.spam_confidence_threshold_bps.to_string(),
    );
    meta.insert(
        "ontology_version".to_string(),
        delete_outcome.ontology_version,
    );
    meta.insert("cleanup_scope".to_string(), delete_outcome.cleanup_scope);
    meta.insert(
        "preserved_transactional_or_personal_count".to_string(),
        delete_outcome
            .preserved_transactional_or_personal_count
            .to_string(),
    );
    meta.insert(
        "preserved_trusted_system_count".to_string(),
        delete_outcome.preserved_trusted_system_count.to_string(),
    );
    meta.insert(
        "preserved_low_confidence_other_count".to_string(),
        delete_outcome
            .preserved_low_confidence_other_count
            .to_string(),
    );
    meta.insert(
        "preserved_due_to_delete_cap_count".to_string(),
        delete_outcome.preserved_due_to_delete_cap_count.to_string(),
    );
    meta.insert(
        "preserved_reason.transactional_or_personal".to_string(),
        delete_outcome
            .preserved_transactional_or_personal_count
            .to_string(),
    );
    meta.insert(
        "preserved_reason.trusted_system_sender".to_string(),
        delete_outcome.preserved_trusted_system_count.to_string(),
    );
    meta.insert(
        "preserved_reason.low_confidence_other".to_string(),
        delete_outcome
            .preserved_low_confidence_other_count
            .to_string(),
    );
    meta.insert(
        "preserved_reason.delete_cap_guardrail".to_string(),
        delete_outcome.preserved_due_to_delete_cap_count.to_string(),
    );
    let preserved_reason_counts_json =
        serde_json::to_string(&preserved_reason_counts).map_err(|e| {
            TransactionError::Invalid(format!("preserved_reason_counts encode failed: {}", e))
        })?;
    meta.insert(
        "preserved_reason_counts_json".to_string(),
        preserved_reason_counts_json,
    );
    meta.insert(
        "consumed_count".to_string(),
        consumption.consumed_count.to_string(),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}
