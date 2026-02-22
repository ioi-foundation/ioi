// Path: crates/services/src/wallet_network/handlers/connectors/config.rs

use super::shared::{
    ensure_connector_secret_aliases_registered, normalize_mail_connector_config, normalize_mailbox,
};
use crate::wallet_network::keys::{
    mail_connector_get_receipt_key, mail_connector_key,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_typed, store_typed,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    MailConnectorGetParams, MailConnectorGetReceipt, MailConnectorRecord, MailConnectorUpsertParams,
    VaultAuditEventKind,
};
use ioi_types::error::TransactionError;

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
