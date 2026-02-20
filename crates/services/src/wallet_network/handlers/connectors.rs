// Path: crates/services/src/wallet_network/handlers/connectors.rs

use crate::wallet_network::keys::{
    channel_key, lease_action_window_key, lease_consumption_key, lease_key,
    mail_connector_get_receipt_key, mail_connector_key, mail_delete_receipt_key,
    mail_list_receipt_key, mail_read_receipt_key, mail_reply_receipt_key, secret_alias_key,
    secret_key,
};
use crate::wallet_network::mail_ontology::{
    classify_mail_spam, MAIL_ONTOLOGY_SIGNAL_VERSION,
};
use crate::wallet_network::mail_transport::{
    mail_provider_for_config, MailProviderCredentials, MailProviderMessage,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_revocation_epoch, load_typed,
    store_typed,
};
use crate::wallet_network::{LeaseActionReplayWindowState, LeaseConsumptionState};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorGetParams,
    MailConnectorGetReceipt, MailConnectorRecord, MailConnectorSecretAliases,
    MailConnectorUpsertParams, MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams,
    MailListRecentReceipt, MailMessageSummary, MailReadLatestParams, MailReadLatestReceipt,
    MailReplyParams, MailReplyReceipt, SessionChannelRecord, SessionChannelState, SessionLease,
    SessionLeaseMode, VaultAuditEventKind, VaultSecretRecord,
};
use ioi_types::error::TransactionError;
use std::collections::BTreeMap;

const LEASE_OPERATION_TRACK_LIMIT: usize = 256;
const LEASE_ACTION_NONCE_TRACK_LIMIT: usize = 256;
const UNORDERED_CONNECTOR_ACTION_REPLAY_WINDOW: u64 = 512;
const MAIL_LIST_RECENT_DEFAULT_LIMIT: usize = 25;
const MAIL_LIST_RECENT_MAX_LIMIT: usize = 200;
const MAIL_DELETE_SPAM_DEFAULT_LIMIT: u32 = 25;
const MAIL_DELETE_SPAM_MAX_LIMIT: u32 = 500;
const MAIL_CONNECTOR_MAX_ALIAS_LEN: usize = 128;
const MAIL_CONNECTOR_SENSITIVE_METADATA_KEYWORDS: [&str; 6] = [
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
];
const MAIL_READ_CAPABILITY_ALIASES: [&str; 4] =
    ["mail.read.latest", "mail:read", "mail.read", "email:read"];
const MAIL_LIST_CAPABILITY_ALIASES: [&str; 8] = [
    "mail.list.recent",
    "mail:list",
    "mail.list",
    "email:list",
    "mail.read.latest",
    "mail:read",
    "mail.read",
    "email:read",
];
const MAIL_DELETE_CAPABILITY_ALIASES: [&str; 7] = [
    "mail.delete.spam",
    "mail.delete",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.modify",
    "email:modify",
];
const MAIL_DELETE_MAILBOX_ALIASES: [&str; 5] = ["spam", "junk", "junkemail", "bulk", "trash"];
const MAIL_REPLY_CAPABILITY_ALIASES: [&str; 9] = [
    "mail.reply",
    "mail.send",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.compose",
    "email:compose",
    "mail.modify",
    "email:modify",
];

pub(crate) fn mail_connector_upsert(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MailConnectorUpsertParams,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    let mailbox = normalize_mailbox(&params.mailbox);
    let config = normalize_mail_connector_config(params.config)?;
    ensure_connector_secret_aliases_registered(state, &config.secret_aliases)?;

    let key = mail_connector_key(&mailbox);
    let existing: Option<MailConnectorRecord> = load_typed(state, &key)?;
    if let Some(existing_record) = &existing {
        if existing_record.mailbox != mailbox {
            return Err(TransactionError::Invalid(
                "stored mail connector mailbox binding mismatch".to_string(),
            ));
        }
    }

    let record = MailConnectorRecord {
        mailbox: mailbox.clone(),
        config,
        created_at_ms: existing
            .as_ref()
            .map_or(now_ms, |record| record.created_at_ms),
        updated_at_ms: now_ms,
    };
    store_typed(state, &key, &record)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "operation".to_string(),
        "mail_connector_upsert@v1".to_string(),
    );
    meta.insert("mailbox".to_string(), mailbox);
    meta.insert(
        "provider".to_string(),
        format!("{:?}", record.config.provider),
    );
    meta.insert(
        "existed".to_string(),
        existing.as_ref().map(|_| true).unwrap_or(false).to_string(),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}

pub(crate) fn mail_connector_get(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MailConnectorGetParams,
) -> Result<(), TransactionError> {
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }

    let now_ms = block_timestamp_ms(ctx);
    let mailbox = normalize_mailbox(&params.mailbox);
    let receipt_key = mail_connector_get_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "mail connector get request_id replay detected".to_string(),
        ));
    }

    let connector_key = mail_connector_key(&mailbox);
    let connector: MailConnectorRecord = load_typed(state, &connector_key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "mail connector for mailbox '{}' is not configured",
            mailbox
        ))
    })?;
    if connector.mailbox != mailbox {
        return Err(TransactionError::Invalid(
            "mail connector mailbox binding mismatch".to_string(),
        ));
    }

    let provider = format!("{:?}", connector.config.provider);
    let receipt = MailConnectorGetReceipt {
        request_id: params.request_id,
        mailbox: mailbox.clone(),
        fetched_at_ms: now_ms,
        connector,
    };
    store_typed(state, &receipt_key, &receipt)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("operation".to_string(), "mail_connector_get@v1".to_string());
    meta.insert("request_id".to_string(), hex::encode(params.request_id));
    meta.insert("mailbox".to_string(), mailbox);
    meta.insert("provider".to_string(), provider);
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}

pub(crate) fn mail_read_latest(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MailReadLatestParams,
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
    if !contains_mail_read_capability(&lease.capability_subset) {
        return Err(TransactionError::Invalid(
            "lease does not authorize mail read capability".to_string(),
        ));
    }
    if !contains_mail_read_capability(&channel.envelope.capability_set) {
        return Err(TransactionError::Invalid(
            "channel does not authorize mail read capability".to_string(),
        ));
    }
    enforce_mailbox_constraint(lease.constraints_subset.get("mailbox"), &mailbox)?;
    enforce_mailbox_constraint(channel.envelope.constraints.get("mailbox"), &mailbox)?;

    let receipt_key = mail_read_receipt_key(&params.operation_id);
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
    let message = provider
        .read_latest(&connector.config, &credentials, &mailbox, now_ms)
        .map(|provider_message| mail_provider_message_to_summary(provider_message, &mailbox))?;
    let receipt = MailReadLatestReceipt {
        operation_id: params.operation_id,
        channel_id: params.channel_id,
        lease_id: params.lease_id,
        mailbox: mailbox.clone(),
        audience: lease.audience,
        executed_at_ms: now_ms,
        message,
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
    meta.insert("operation".to_string(), "mail_read_latest@v1".to_string());
    meta.insert("operation_id".to_string(), hex::encode(params.operation_id));
    meta.insert("op_seq".to_string(), params.op_seq.to_string());
    meta.insert("channel_id".to_string(), hex::encode(params.channel_id));
    meta.insert("lease_id".to_string(), hex::encode(params.lease_id));
    meta.insert("mailbox".to_string(), mailbox);
    meta.insert("lease_mode".to_string(), format!("{:?}", lease.mode));
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

pub(crate) fn mail_list_recent(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MailListRecentParams,
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
    let limit = normalize_mail_list_limit(params.limit);

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
    if !contains_mail_list_capability(&lease.capability_subset) {
        return Err(TransactionError::Invalid(
            "lease does not authorize mail list capability".to_string(),
        ));
    }
    if !contains_mail_list_capability(&channel.envelope.capability_set) {
        return Err(TransactionError::Invalid(
            "channel does not authorize mail list capability".to_string(),
        ));
    }
    enforce_mailbox_constraint(lease.constraints_subset.get("mailbox"), &mailbox)?;
    enforce_mailbox_constraint(channel.envelope.constraints.get("mailbox"), &mailbox)?;

    let receipt_key = mail_list_receipt_key(&params.operation_id);
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
    let list_outcome = provider.list_recent(&connector.config, &credentials, &mailbox, limit, now_ms)?;
    let requested_limit = u32::try_from(list_outcome.requested_limit).unwrap_or(u32::MAX);
    let evaluated_count = u32::try_from(list_outcome.evaluated_count).unwrap_or(u32::MAX);
    let parse_error_count = u32::try_from(list_outcome.parse_error_count).unwrap_or(u32::MAX);
    let parse_confidence_bps = list_outcome.parse_confidence_bps;
    let parse_volume_band = list_outcome.parse_volume_band.clone();
    let messages = list_outcome
        .messages
        .into_iter()
        .map(|provider_message| mail_provider_message_to_summary(provider_message, &mailbox))
        .collect::<Vec<_>>();
    let receipt = MailListRecentReceipt {
        operation_id: params.operation_id,
        channel_id: params.channel_id,
        lease_id: params.lease_id,
        mailbox: mailbox.clone(),
        audience: lease.audience,
        executed_at_ms: now_ms,
        messages,
        requested_limit,
        evaluated_count,
        parse_error_count,
        parse_confidence_bps,
        parse_volume_band: parse_volume_band.clone(),
        ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
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
    meta.insert("operation".to_string(), "mail_list_recent@v1".to_string());
    meta.insert("operation_id".to_string(), hex::encode(params.operation_id));
    meta.insert("op_seq".to_string(), params.op_seq.to_string());
    meta.insert("channel_id".to_string(), hex::encode(params.channel_id));
    meta.insert("lease_id".to_string(), hex::encode(params.lease_id));
    meta.insert("mailbox".to_string(), mailbox);
    meta.insert("limit".to_string(), limit.to_string());
    meta.insert("requested_limit".to_string(), requested_limit.to_string());
    meta.insert("evaluated_count".to_string(), evaluated_count.to_string());
    meta.insert("parse_error_count".to_string(), parse_error_count.to_string());
    meta.insert(
        "parse_confidence_bps".to_string(),
        parse_confidence_bps.to_string(),
    );
    meta.insert("parse_volume_band".to_string(), parse_volume_band);
    meta.insert(
        "ontology_version".to_string(),
        MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
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
    enforce_delete_spam_mailbox_target(&mailbox)?;

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
        spam_confidence_threshold_bps: delete_outcome.spam_confidence_threshold_bps,
        ontology_version: delete_outcome.ontology_version.clone(),
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
        "spam_confidence_threshold_bps".to_string(),
        delete_outcome.spam_confidence_threshold_bps.to_string(),
    );
    meta.insert(
        "ontology_version".to_string(),
        delete_outcome.ontology_version,
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

pub(crate) fn mail_reply(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MailReplyParams,
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

    let to = params.to.trim();
    let subject = params.subject.trim();
    let body = params.body.trim();
    if to.is_empty() || subject.is_empty() || body.is_empty() {
        return Err(TransactionError::Invalid(
            "mail_reply requires non-empty to, subject, and body".to_string(),
        ));
    }

    let now_ms = block_timestamp_ms(ctx);
    let mailbox = normalize_mailbox(&params.mailbox);

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
    if !contains_mail_reply_capability(&lease.capability_subset) {
        return Err(TransactionError::Invalid(
            "lease does not authorize mail reply capability".to_string(),
        ));
    }
    if !contains_mail_reply_capability(&channel.envelope.capability_set) {
        return Err(TransactionError::Invalid(
            "channel does not authorize mail reply capability".to_string(),
        ));
    }
    enforce_mailbox_constraint(lease.constraints_subset.get("mailbox"), &mailbox)?;
    enforce_mailbox_constraint(channel.envelope.constraints.get("mailbox"), &mailbox)?;

    let receipt_key = mail_reply_receipt_key(&params.operation_id);
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
    let sent_message_id =
        provider.send_reply(&connector.config, &credentials, to, subject, body)?;
    let receipt = MailReplyReceipt {
        operation_id: params.operation_id,
        channel_id: params.channel_id,
        lease_id: params.lease_id,
        mailbox: mailbox.clone(),
        audience: lease.audience,
        executed_at_ms: now_ms,
        to: to.to_string(),
        subject: subject.to_string(),
        sent_message_id: sent_message_id.clone(),
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
    meta.insert("operation".to_string(), "mail_reply@v1".to_string());
    meta.insert("operation_id".to_string(), hex::encode(params.operation_id));
    meta.insert("op_seq".to_string(), params.op_seq.to_string());
    meta.insert("channel_id".to_string(), hex::encode(params.channel_id));
    meta.insert("lease_id".to_string(), hex::encode(params.lease_id));
    meta.insert("mailbox".to_string(), mailbox);
    meta.insert("to".to_string(), to.to_string());
    meta.insert("subject".to_string(), subject.to_string());
    meta.insert("sent_message_id".to_string(), sent_message_id);
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

fn enforce_connector_action_replay_window(
    replay_window: &mut LeaseActionReplayWindowState,
    op_seq: u64,
    op_nonce: Option<[u8; 32]>,
) -> Result<(), TransactionError> {
    match replay_window.ordering {
        ioi_types::app::wallet_network::SessionChannelOrdering::Ordered => {
            let expected_seq =
                if replay_window.seen_seqs.is_empty() && replay_window.highest_seq == 0 {
                    1
                } else {
                    replay_window.highest_seq.saturating_add(1)
                };
            if op_seq != expected_seq {
                return Err(TransactionError::Invalid(format!(
                    "ordered action op_seq {} does not match expected {}",
                    op_seq, expected_seq
                )));
            }
            replay_window.highest_seq = op_seq;
            replay_window.seen_seqs.clear();
            replay_window.seen_seqs.insert(op_seq);
        }
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered => {
            if replay_window.seen_seqs.contains(&op_seq) {
                return Err(TransactionError::Invalid(
                    "unordered action replay detected for op_seq".to_string(),
                ));
            }
            if op_seq.saturating_add(UNORDERED_CONNECTOR_ACTION_REPLAY_WINDOW)
                < replay_window.highest_seq
            {
                return Err(TransactionError::Invalid(
                    "unordered action op_seq is outside replay window".to_string(),
                ));
            }
            replay_window.highest_seq = replay_window.highest_seq.max(op_seq);
            replay_window.seen_seqs.insert(op_seq);
            let min_allowed = replay_window
                .highest_seq
                .saturating_sub(UNORDERED_CONNECTOR_ACTION_REPLAY_WINDOW);
            replay_window.seen_seqs.retain(|seq| *seq >= min_allowed);
        }
    }

    if let Some(op_nonce) = op_nonce {
        if replay_window
            .seen_nonces
            .iter()
            .any(|seen| *seen == op_nonce)
        {
            return Err(TransactionError::Invalid(
                "action op_nonce replay detected".to_string(),
            ));
        }
        replay_window.seen_nonces.push(op_nonce);
        if replay_window.seen_nonces.len() > LEASE_ACTION_NONCE_TRACK_LIMIT {
            let excess = replay_window.seen_nonces.len() - LEASE_ACTION_NONCE_TRACK_LIMIT;
            replay_window.seen_nonces.drain(0..excess);
        }
    }
    Ok(())
}

fn normalize_mailbox(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "primary".to_string();
    }
    trimmed.to_ascii_lowercase()
}

fn mail_provider_message_to_summary(
    message: MailProviderMessage,
    mailbox: &str,
) -> MailMessageSummary {
    let spam_classification =
        classify_mail_spam(mailbox, &message.from, &message.subject, &message.preview);
    MailMessageSummary {
        message_id: message.message_id,
        from: message.from,
        subject: message.subject,
        received_at_ms: message.received_at_ms,
        preview: message.preview,
        spam_confidence_bps: spam_classification.confidence_bps,
        spam_confidence_band: spam_classification.confidence_band.to_string(),
        spam_signal_tags: spam_classification.signal_tags,
    }
}

fn load_mail_connector_record(
    state: &dyn StateAccess,
    mailbox: &str,
) -> Result<MailConnectorRecord, TransactionError> {
    let key = mail_connector_key(mailbox);
    let connector: MailConnectorRecord = load_typed(state, &key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "mail connector for mailbox '{}' is not configured",
            mailbox
        ))
    })?;
    if connector.mailbox != mailbox {
        return Err(TransactionError::Invalid(
            "mail connector mailbox binding mismatch".to_string(),
        ));
    }
    Ok(connector)
}

fn resolve_mail_provider_credentials(
    state: &dyn StateAccess,
    connector: &MailConnectorRecord,
) -> Result<MailProviderCredentials, TransactionError> {
    let imap_secret = resolve_secret_alias_utf8(
        state,
        &connector.config.secret_aliases.imap_password_alias,
        "imap_password_alias",
    )?;
    let smtp_secret = resolve_secret_alias_utf8(
        state,
        &connector.config.secret_aliases.smtp_password_alias,
        "smtp_password_alias",
    )?;
    Ok(MailProviderCredentials {
        auth_mode: connector.config.auth_mode,
        imap_username: resolve_secret_alias_utf8(
            state,
            &connector.config.secret_aliases.imap_username_alias,
            "imap_username_alias",
        )?,
        imap_secret,
        smtp_username: resolve_secret_alias_utf8(
            state,
            &connector.config.secret_aliases.smtp_username_alias,
            "smtp_username_alias",
        )?,
        smtp_secret,
    })
}

fn ensure_connector_secret_aliases_registered(
    state: &dyn StateAccess,
    aliases: &MailConnectorSecretAliases,
) -> Result<(), TransactionError> {
    for (alias, field_name) in [
        (&aliases.imap_username_alias, "imap_username_alias"),
        (&aliases.imap_password_alias, "imap_password_alias"),
        (&aliases.smtp_username_alias, "smtp_username_alias"),
        (&aliases.smtp_password_alias, "smtp_password_alias"),
    ] {
        ensure_secret_alias_registered(state, alias, field_name)?;
    }
    Ok(())
}

fn ensure_secret_alias_registered(
    state: &dyn StateAccess,
    alias: &str,
    field_name: &str,
) -> Result<(), TransactionError> {
    let secret_id: String = load_typed(state, &secret_alias_key(alias))?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "mail connector secret alias '{}' for '{}' is not registered",
            alias.trim(),
            field_name
        ))
    })?;
    let secret: VaultSecretRecord =
        load_typed(state, &secret_key(&secret_id))?.ok_or_else(|| {
            TransactionError::Invalid(format!(
                "mail connector secret alias '{}' maps to unknown secret_id '{}'",
                alias.trim(),
                secret_id
            ))
        })?;
    if secret.ciphertext.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret '{}' has empty ciphertext",
            secret_id
        )));
    }
    Ok(())
}

fn resolve_secret_alias_utf8(
    state: &dyn StateAccess,
    alias: &str,
    field_name: &str,
) -> Result<String, TransactionError> {
    let secret_id: String = load_typed(state, &secret_alias_key(alias))?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "mail connector secret alias '{}' for '{}' is not registered",
            alias.trim(),
            field_name
        ))
    })?;
    let secret: VaultSecretRecord =
        load_typed(state, &secret_key(&secret_id))?.ok_or_else(|| {
            TransactionError::Invalid(format!(
                "mail connector secret alias '{}' maps to unknown secret_id '{}'",
                alias.trim(),
                secret_id
            ))
        })?;
    if secret.ciphertext.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret '{}' has empty ciphertext",
            secret_id
        )));
    }
    let value = String::from_utf8(secret.ciphertext).map_err(|_| {
        TransactionError::Invalid(format!(
            "mail connector secret '{}' is not utf-8 decodable",
            secret_id
        ))
    })?;
    if value.trim().is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret '{}' resolves to empty text",
            secret_id
        )));
    }
    Ok(value)
}

fn normalize_mail_connector_config(
    config: MailConnectorConfig,
) -> Result<MailConnectorConfig, TransactionError> {
    let account_email = config.account_email.trim().to_ascii_lowercase();
    if account_email.is_empty() {
        return Err(TransactionError::Invalid(
            "mail connector account_email must not be empty".to_string(),
        ));
    }

    let imap = normalize_mail_connector_endpoint("imap", config.imap)?;
    let smtp = normalize_mail_connector_endpoint("smtp", config.smtp)?;
    let secret_aliases = normalize_mail_connector_secret_aliases(config.secret_aliases)?;
    let metadata = normalize_mail_connector_metadata(config.metadata)?;

    Ok(MailConnectorConfig {
        provider: config.provider,
        auth_mode: normalize_mail_connector_auth_mode(config.auth_mode),
        account_email,
        imap,
        smtp,
        secret_aliases,
        metadata,
    })
}

fn normalize_mail_connector_auth_mode(mode: MailConnectorAuthMode) -> MailConnectorAuthMode {
    mode
}

fn normalize_mail_connector_endpoint(
    label: &str,
    endpoint: MailConnectorEndpoint,
) -> Result<MailConnectorEndpoint, TransactionError> {
    let host = endpoint.host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector {} host must not be empty",
            label
        )));
    }
    if endpoint.port == 0 {
        return Err(TransactionError::Invalid(format!(
            "mail connector {} port must be > 0",
            label
        )));
    }
    Ok(MailConnectorEndpoint {
        host,
        port: endpoint.port,
        tls_mode: endpoint.tls_mode,
    })
}

fn normalize_mail_connector_secret_aliases(
    aliases: MailConnectorSecretAliases,
) -> Result<MailConnectorSecretAliases, TransactionError> {
    Ok(MailConnectorSecretAliases {
        imap_username_alias: normalize_required_secret_alias(
            &aliases.imap_username_alias,
            "imap_username_alias",
        )?,
        imap_password_alias: normalize_required_secret_alias(
            &aliases.imap_password_alias,
            "imap_password_alias",
        )?,
        smtp_username_alias: normalize_required_secret_alias(
            &aliases.smtp_username_alias,
            "smtp_username_alias",
        )?,
        smtp_password_alias: normalize_required_secret_alias(
            &aliases.smtp_password_alias,
            "smtp_password_alias",
        )?,
    })
}

fn normalize_required_secret_alias(
    alias: &str,
    field_name: &str,
) -> Result<String, TransactionError> {
    let normalized = alias.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret alias '{}' must not be empty",
            field_name
        )));
    }
    if normalized.len() > MAIL_CONNECTOR_MAX_ALIAS_LEN {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret alias '{}' exceeds {} characters",
            field_name, MAIL_CONNECTOR_MAX_ALIAS_LEN
        )));
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret alias '{}' contains invalid characters",
            field_name
        )));
    }
    Ok(normalized)
}

fn normalize_mail_connector_metadata(
    metadata: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, TransactionError> {
    let mut normalized = BTreeMap::new();
    for (key, value) in metadata {
        let normalized_key = key.trim().to_ascii_lowercase();
        if normalized_key.is_empty() {
            continue;
        }
        if contains_sensitive_connector_metadata_key(&normalized_key) {
            return Err(TransactionError::Invalid(format!(
                "mail connector metadata key '{}' is not allowed for secret safety; use secret aliases instead",
                normalized_key
            )));
        }
        normalized.insert(normalized_key, value.trim().to_string());
    }
    Ok(normalized)
}

fn contains_sensitive_connector_metadata_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    MAIL_CONNECTOR_SENSITIVE_METADATA_KEYWORDS
        .iter()
        .any(|keyword| normalized.contains(keyword))
}

fn normalize_mail_list_limit(limit: u32) -> usize {
    if limit == 0 {
        return MAIL_LIST_RECENT_DEFAULT_LIMIT;
    }
    (limit as usize).clamp(1, MAIL_LIST_RECENT_MAX_LIMIT)
}

fn contains_mail_read_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_READ_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

fn contains_mail_list_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_LIST_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

fn contains_mail_delete_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_DELETE_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

fn enforce_delete_spam_mailbox_target(mailbox: &str) -> Result<(), TransactionError> {
    if MAIL_DELETE_MAILBOX_ALIASES
        .iter()
        .any(|allowed| mailbox.eq_ignore_ascii_case(allowed))
    {
        return Ok(());
    }
    Err(TransactionError::Invalid(format!(
        "mail_delete_spam requires spam/junk mailbox target; got '{}'",
        mailbox
    )))
}

fn contains_mail_reply_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_REPLY_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

fn enforce_mailbox_constraint(
    expected_mailbox: Option<&String>,
    mailbox: &str,
) -> Result<(), TransactionError> {
    let Some(expected_mailbox) = expected_mailbox else {
        return Ok(());
    };
    let expected = normalize_mailbox(expected_mailbox);
    if expected == mailbox {
        return Ok(());
    }
    Err(TransactionError::Invalid(format!(
        "mailbox '{}' is outside lease/channel constraints",
        mailbox
    )))
}

fn normalize_delete_limit(limit: u32) -> u32 {
    if limit == 0 {
        return MAIL_DELETE_SPAM_DEFAULT_LIMIT;
    }
    limit.clamp(1, MAIL_DELETE_SPAM_MAX_LIMIT)
}
