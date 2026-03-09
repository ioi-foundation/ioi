use super::config::mail_connector_upsert;
use crate::wallet_network::handlers::identity::{store_secret_record, upsert_policy_rule};
use crate::wallet_network::keys::{
    connector_auth_export_receipt_key, connector_auth_get_receipt_key,
    connector_auth_import_receipt_key, connector_auth_key, connector_auth_list_receipt_key,
    secret_alias_key, secret_key, CONNECTOR_AUTH_PREFIX, MAIL_CONNECTOR_PREFIX, POLICY_PREFIX,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_typed, store_typed,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::key_store::{decrypt_key, encrypt_key};
use ioi_types::app::wallet_network::{
    ConnectorAuthExportBundle, ConnectorAuthExportParams, ConnectorAuthExportReceipt,
    ConnectorAuthGetParams, ConnectorAuthGetReceipt, ConnectorAuthImportParams,
    ConnectorAuthImportReceipt, ConnectorAuthListParams, ConnectorAuthListReceipt,
    ConnectorAuthRecord, ConnectorAuthUpsertParams, MailConnectorRecord, MailConnectorUpsertParams,
    VaultAuditEventKind, VaultPolicyRule, VaultSecretRecord,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::collections::{BTreeMap, BTreeSet};

fn normalize_connector_id(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_provider_family(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_auth_record(
    state: &dyn StateAccess,
    record: ConnectorAuthRecord,
) -> Result<ConnectorAuthRecord, TransactionError> {
    let connector_id = normalize_connector_id(&record.connector_id);
    if connector_id.is_empty() {
        return Err(TransactionError::Invalid(
            "connector auth record requires non-empty connector_id".to_string(),
        ));
    }
    let provider_family = normalize_provider_family(&record.provider_family);
    if provider_family.is_empty() {
        return Err(TransactionError::Invalid(
            "connector auth record requires non-empty provider_family".to_string(),
        ));
    }

    let mut credential_aliases = BTreeMap::new();
    for (slot, alias) in record.credential_aliases {
        let normalized_slot = slot.trim().to_ascii_lowercase();
        let normalized_alias = alias.trim().to_ascii_lowercase();
        if normalized_slot.is_empty() || normalized_alias.is_empty() {
            return Err(TransactionError::Invalid(
                "connector auth credential aliases must use non-empty keys and values".to_string(),
            ));
        }
        let secret_id: String = load_typed(state, &secret_alias_key(&normalized_alias))?
            .ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "connector auth alias '{}' is not registered",
                    normalized_alias
                ))
            })?;
        let _: VaultSecretRecord =
            load_typed(state, &secret_key(&secret_id))?.ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "connector auth alias '{}' maps to missing secret '{}'",
                    normalized_alias, secret_id
                ))
            })?;
        credential_aliases.insert(normalized_slot, normalized_alias);
    }

    let granted_scopes = record
        .granted_scopes
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let account_label = record
        .account_label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let mailbox = record
        .mailbox
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let metadata = record
        .metadata
        .into_iter()
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_string()))
        .filter(|(key, value)| !key.is_empty() && !value.is_empty())
        .collect::<BTreeMap<_, _>>();

    Ok(ConnectorAuthRecord {
        connector_id,
        provider_family,
        auth_protocol: record.auth_protocol,
        state: record.state,
        account_label,
        mailbox,
        granted_scopes,
        credential_aliases,
        metadata,
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
        expires_at_ms: record.expires_at_ms,
        last_validated_at_ms: record.last_validated_at_ms,
    })
}

pub(crate) fn connector_auth_upsert(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConnectorAuthUpsertParams,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    let mut record = normalize_auth_record(state, params.record)?;
    let key = connector_auth_key(&record.connector_id);
    let existing: Option<ConnectorAuthRecord> = load_typed(state, &key)?;
    record.created_at_ms = existing
        .as_ref()
        .map(|value| value.created_at_ms)
        .unwrap_or_else(|| {
            if record.created_at_ms == 0 {
                now_ms
            } else {
                record.created_at_ms
            }
        });
    record.updated_at_ms = now_ms;
    store_typed(state, &key, &record)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "operation".to_string(),
        "connector_auth_upsert@v1".to_string(),
    );
    meta.insert("connector_id".to_string(), record.connector_id.clone());
    meta.insert(
        "provider_family".to_string(),
        record.provider_family.clone(),
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

pub(crate) fn connector_auth_get(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConnectorAuthGetParams,
) -> Result<(), TransactionError> {
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }
    let connector_id = normalize_connector_id(&params.connector_id);
    if connector_id.is_empty() {
        return Err(TransactionError::Invalid(
            "connector_id must not be empty".to_string(),
        ));
    }

    let receipt_key = connector_auth_get_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "connector auth get request_id replay detected".to_string(),
        ));
    }

    let record: ConnectorAuthRecord = load_typed(state, &connector_auth_key(&connector_id))?
        .ok_or_else(|| {
            TransactionError::Invalid(format!(
                "connector auth record '{}' is not configured",
                connector_id
            ))
        })?;
    let now_ms = block_timestamp_ms(ctx);
    let receipt = ConnectorAuthGetReceipt {
        request_id: params.request_id,
        connector_id: connector_id.clone(),
        fetched_at_ms: now_ms,
        record,
    };
    store_typed(state, &receipt_key, &receipt)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("operation".to_string(), "connector_auth_get@v1".to_string());
    meta.insert("connector_id".to_string(), connector_id);
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}

pub(crate) fn connector_auth_list(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConnectorAuthListParams,
) -> Result<(), TransactionError> {
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }
    let filter = params
        .provider_family
        .map(|value| normalize_provider_family(&value))
        .filter(|value| !value.is_empty());

    let receipt_key = connector_auth_list_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "connector auth list request_id replay detected".to_string(),
        ));
    }

    let mut records = Vec::new();
    for row in state.prefix_scan(CONNECTOR_AUTH_PREFIX)? {
        let (_, value) = row?;
        let record = codec::from_bytes_canonical::<ConnectorAuthRecord>(&value)?;
        if filter
            .as_ref()
            .map(|provider| record.provider_family == *provider)
            .unwrap_or(true)
        {
            records.push(record);
        }
    }
    records.sort_by(|left, right| left.connector_id.cmp(&right.connector_id));

    let now_ms = block_timestamp_ms(ctx);
    let receipt = ConnectorAuthListReceipt {
        request_id: params.request_id,
        listed_at_ms: now_ms,
        records,
    };
    store_typed(state, &receipt_key, &receipt)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "operation".to_string(),
        "connector_auth_list@v1".to_string(),
    );
    meta.insert(
        "provider_family".to_string(),
        filter.unwrap_or_else(|| "*".to_string()),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}

pub(crate) fn connector_auth_export(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConnectorAuthExportParams,
) -> Result<(), TransactionError> {
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }
    let passphrase = params.passphrase.trim().to_string();
    if passphrase.is_empty() {
        return Err(TransactionError::Invalid(
            "export passphrase must not be empty".to_string(),
        ));
    }
    let receipt_key = connector_auth_export_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "connector auth export request_id replay detected".to_string(),
        ));
    }

    let filter_ids = params
        .connector_ids
        .into_iter()
        .map(|value| normalize_connector_id(&value))
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();

    let mut connector_auth_records = Vec::new();
    let mut selected_ids = Vec::new();
    let mut secret_ids = BTreeSet::new();
    let mut mailboxes = BTreeSet::new();

    for row in state.prefix_scan(CONNECTOR_AUTH_PREFIX)? {
        let (_, value) = row?;
        let record = codec::from_bytes_canonical::<ConnectorAuthRecord>(&value)?;
        let include = filter_ids.is_empty() || filter_ids.contains(&record.connector_id);
        if !include {
            continue;
        }
        for alias in record.credential_aliases.values() {
            if let Some(secret_id) = load_typed::<String>(state, &secret_alias_key(alias))? {
                secret_ids.insert(secret_id);
            }
        }
        if let Some(mailbox) = &record.mailbox {
            mailboxes.insert(mailbox.clone());
        }
        selected_ids.push(record.connector_id.clone());
        connector_auth_records.push(record);
    }

    let mut secret_records = Vec::new();
    for secret_id in &secret_ids {
        if let Some(secret) = load_typed::<VaultSecretRecord>(state, &secret_key(secret_id))? {
            secret_records.push(secret);
        }
    }

    let mut mail_connectors = Vec::new();
    for mailbox in &mailboxes {
        let key = [MAIL_CONNECTOR_PREFIX, mailbox.as_bytes()].concat();
        if let Some(record) = load_typed::<MailConnectorRecord>(state, &key)? {
            mail_connectors.push(record);
        }
    }

    let mut policy_rules = Vec::new();
    for row in state.prefix_scan(POLICY_PREFIX)? {
        let (_, value) = row?;
        policy_rules.push(codec::from_bytes_canonical::<VaultPolicyRule>(&value)?);
    }
    policy_rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));

    let now_ms = block_timestamp_ms(ctx);
    let bundle = ConnectorAuthExportBundle {
        version: 1,
        exported_at_ms: now_ms,
        connector_auth_records,
        mail_connectors,
        policy_rules,
        secret_records,
    };
    let raw_bundle = codec::to_bytes_canonical(&bundle)?;
    let encrypted_bundle = encrypt_key(&raw_bundle, &passphrase).map_err(|e| {
        TransactionError::Invalid(format!("connector auth export encryption failed: {}", e))
    })?;
    let receipt = ConnectorAuthExportReceipt {
        request_id: params.request_id,
        exported_at_ms: now_ms,
        connector_ids: selected_ids.clone(),
        encrypted_bundle,
    };
    store_typed(state, &receipt_key, &receipt)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "operation".to_string(),
        "connector_auth_export@v1".to_string(),
    );
    meta.insert(
        "connector_count".to_string(),
        selected_ids.len().to_string(),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}

pub(crate) fn connector_auth_import(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: ConnectorAuthImportParams,
) -> Result<(), TransactionError> {
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }
    let passphrase = params.passphrase.trim().to_string();
    if passphrase.is_empty() {
        return Err(TransactionError::Invalid(
            "import passphrase must not be empty".to_string(),
        ));
    }
    if params.encrypted_bundle.is_empty() {
        return Err(TransactionError::Invalid(
            "import bundle must not be empty".to_string(),
        ));
    }
    let receipt_key = connector_auth_import_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "connector auth import request_id replay detected".to_string(),
        ));
    }

    let raw_bundle = decrypt_key(&params.encrypted_bundle, &passphrase)
        .map_err(|e| TransactionError::Invalid(format!("connector auth import failed: {}", e)))?;
    let bundle = codec::from_bytes_canonical::<ConnectorAuthExportBundle>(&raw_bundle.0)?;
    if bundle.version != 1 {
        return Err(TransactionError::Invalid(format!(
            "unsupported connector auth bundle version '{}'",
            bundle.version
        )));
    }

    if !params.replace_existing {
        for record in &bundle.connector_auth_records {
            if state
                .get(&connector_auth_key(&record.connector_id))?
                .is_some()
            {
                return Err(TransactionError::Invalid(format!(
                    "connector auth '{}' already exists; rerun with replace_existing=true",
                    record.connector_id
                )));
            }
        }
    }

    let mut imported_connector_ids = Vec::new();
    let mut imported_secret_ids = Vec::new();
    let mut imported_policy_rule_ids = Vec::new();
    let mut imported_mailboxes = Vec::new();

    for secret in bundle.secret_records {
        imported_secret_ids.push(secret.secret_id.clone());
        store_secret_record(state, ctx, secret)?;
    }

    for record in bundle.connector_auth_records {
        imported_connector_ids.push(record.connector_id.clone());
        connector_auth_upsert(state, ctx, ConnectorAuthUpsertParams { record })?;
    }

    for rule in bundle.policy_rules {
        imported_policy_rule_ids.push(rule.rule_id.clone());
        upsert_policy_rule(state, ctx, rule)?;
    }

    for connector in bundle.mail_connectors {
        imported_mailboxes.push(connector.mailbox.clone());
        mail_connector_upsert(
            state,
            ctx,
            MailConnectorUpsertParams {
                mailbox: connector.mailbox,
                config: connector.config,
            },
        )?;
    }

    let now_ms = block_timestamp_ms(ctx);
    let receipt = ConnectorAuthImportReceipt {
        request_id: params.request_id,
        imported_at_ms: now_ms,
        connector_ids: imported_connector_ids.clone(),
        secret_ids: imported_secret_ids,
        policy_rule_ids: imported_policy_rule_ids,
        mailboxes: imported_mailboxes,
    };
    store_typed(state, &receipt_key, &receipt)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "operation".to_string(),
        "connector_auth_import@v1".to_string(),
    );
    meta.insert(
        "connector_count".to_string(),
        imported_connector_ids.len().to_string(),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}
