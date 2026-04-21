use crate::wallet_network::keys::{
    registered_client_get_receipt_key, registered_client_key, registered_client_list_receipt_key,
    CONTROL_ROOT_KEY, REGISTERED_CLIENT_PREFIX,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_typed, store_typed,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::account_id_from_key_material;
use ioi_types::app::wallet_network::{
    VaultAuditEventKind, WalletClientRole, WalletClientState, WalletConfigureControlRootParams,
    WalletControlPlaneRootRecord, WalletGetClientParams, WalletGetClientReceipt,
    WalletListClientsParams, WalletListClientsReceipt, WalletRegisterClientParams,
    WalletRegisteredClientRecord, WalletRevokeClientParams,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WalletAuthRole {
    ControlPlane,
    Capability,
}

fn role_rank(role: WalletClientRole) -> u8 {
    match role {
        WalletClientRole::Capability => 1,
        WalletClientRole::ControlPlaneAdmin => 2,
    }
}

fn required_role_rank(role: WalletAuthRole) -> u8 {
    match role {
        WalletAuthRole::Capability => 1,
        WalletAuthRole::ControlPlane => 2,
    }
}

fn validate_root_record(root: &WalletControlPlaneRootRecord) -> Result<[u8; 32], TransactionError> {
    if root.public_key.is_empty() {
        return Err(TransactionError::Invalid(
            "control root public_key must not be empty".to_string(),
        ));
    }
    let derived = account_id_from_key_material(root.signature_suite, &root.public_key)?;
    if derived != root.account_id {
        return Err(TransactionError::Invalid(
            "control root account_id does not match signature suite/public_key".to_string(),
        ));
    }
    Ok(derived)
}

fn validate_client_record(
    client: &WalletRegisteredClientRecord,
) -> Result<[u8; 32], TransactionError> {
    if client.label.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "wallet client label must not be empty".to_string(),
        ));
    }
    if client.public_key.is_empty() {
        return Err(TransactionError::Invalid(
            "wallet client public_key must not be empty".to_string(),
        ));
    }
    let derived = account_id_from_key_material(client.signature_suite, &client.public_key)?;
    if derived != client.client_id {
        return Err(TransactionError::Invalid(
            "wallet client client_id does not match signature suite/public_key".to_string(),
        ));
    }
    Ok(derived)
}

pub(super) fn load_control_root(
    state: &dyn StateAccess,
) -> Result<Option<WalletControlPlaneRootRecord>, TransactionError> {
    load_typed(state, CONTROL_ROOT_KEY)
}

pub(super) fn load_registered_client(
    state: &dyn StateAccess,
    client_id: &[u8; 32],
) -> Result<Option<WalletRegisteredClientRecord>, TransactionError> {
    load_typed(state, &registered_client_key(client_id))
}

pub(super) fn ensure_control_root_signer(
    state: &dyn StateAccess,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    let root = load_control_root(state)?.ok_or(TransactionError::UnauthorizedByCredentials)?;
    if root.account_id != ctx.signer_account_id.0 {
        return Err(TransactionError::UnauthorizedByCredentials);
    }
    Ok(())
}

pub(super) fn ensure_wallet_client_role(
    state: &dyn StateAccess,
    ctx: &TxContext<'_>,
    required_role: WalletAuthRole,
) -> Result<(), TransactionError> {
    let Some(root) = load_control_root(state)? else {
        // Compatibility mode for legacy/uninitialized local state.
        return Ok(());
    };
    if root.account_id == ctx.signer_account_id.0 {
        return Ok(());
    }

    let client = load_registered_client(state, &ctx.signer_account_id.0)?
        .ok_or(TransactionError::UnauthorizedByCredentials)?;
    if client.state != WalletClientState::Active {
        return Err(TransactionError::UnauthorizedByCredentials);
    }
    let now_ms = block_timestamp_ms(ctx);
    if client
        .expires_at_ms
        .map(|expiry| now_ms > expiry)
        .unwrap_or(false)
    {
        return Err(TransactionError::UnauthorizedByCredentials);
    }
    if role_rank(client.role) < required_role_rank(required_role) {
        return Err(TransactionError::UnauthorizedByCredentials);
    }
    Ok(())
}

pub(crate) fn authorize_wallet_method(
    state: &dyn StateAccess,
    ctx: &TxContext<'_>,
    method: &str,
) -> Result<(), TransactionError> {
    match method {
        "configure_control_root@v1" => Ok(()),
        "register_client@v1"
        | "revoke_client@v1"
        | "get_client@v1"
        | "list_clients@v1"
        | "create_identity@v1"
        | "link_owner@v1"
        | "store_secret_record@v1"
        | "connector_auth_upsert@v1"
        | "connector_auth_get@v1"
        | "connector_auth_list@v1"
        | "connector_auth_export@v1"
        | "connector_auth_import@v1"
        | "upsert_policy_rule@v1"
        | "issue_session_grant@v1"
        | "issue_session_lease@v1"
        | "mail_connector_upsert@v1"
        | "mail_connector_get@v1"
        | "open_channel_init@v1"
        | "open_channel_try@v1"
        | "open_channel_ack@v1"
        | "open_channel_confirm@v1"
        | "close_channel@v1"
        | "commit_receipt_root@v1"
        | "record_secret_injection_request@v1"
        | "grant_secret_injection@v1"
        | "register_approval_authority@v1"
        | "revoke_approval_authority@v1"
        | "panic_stop@v1" => ensure_wallet_client_role(state, ctx, WalletAuthRole::ControlPlane),
        "mail_connector_ensure_binding@v1"
        | "mail_read_latest@v1"
        | "mail_list_recent@v1"
        | "mailbox_total_count@v1"
        | "mail_delete_spam@v1"
        | "mail_reply@v1"
        | "record_interception@v1"
        | "record_approval@v1"
        | "consume_approval_grant@v1" => {
            ensure_wallet_client_role(state, ctx, WalletAuthRole::Capability)
        }
        _ => Ok(()),
    }
}

pub(crate) fn configure_control_root(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    mut params: WalletConfigureControlRootParams,
) -> Result<(), TransactionError> {
    let derived = validate_root_record(&params.root)?;
    if derived != ctx.signer_account_id.0 {
        return Err(TransactionError::UnauthorizedByCredentials);
    }

    let now_ms = block_timestamp_ms(ctx);
    let existing = load_control_root(state)?;
    if let Some(existing_root) = existing.as_ref() {
        if existing_root.account_id != ctx.signer_account_id.0 {
            return Err(TransactionError::UnauthorizedByCredentials);
        }
        params.root.registered_at_ms = existing_root.registered_at_ms;
    } else if params.root.registered_at_ms == 0 {
        params.root.registered_at_ms = now_ms;
    }
    params.root.updated_at_ms = now_ms;
    store_typed(state, CONTROL_ROOT_KEY, &params.root)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "root_account_id".to_string(),
        hex::encode(params.root.account_id),
    );
    meta.insert(
        "signature_suite".to_string(),
        params.root.signature_suite.0.to_string(),
    );
    meta.insert(
        "rotated".to_string(),
        existing.as_ref().map(|_| true).unwrap_or(false).to_string(),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::ControlRootConfigured, meta)?;
    Ok(())
}

pub(crate) fn register_client(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    mut params: WalletRegisterClientParams,
) -> Result<(), TransactionError> {
    ensure_control_root_signer(state, ctx)?;
    validate_client_record(&params.client)?;

    let now_ms = block_timestamp_ms(ctx);
    let key = registered_client_key(&params.client.client_id);
    let existing: Option<WalletRegisteredClientRecord> = load_typed(state, &key)?;
    params.client.allowed_provider_families = params
        .client
        .allowed_provider_families
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    params.client.registered_at_ms = existing
        .as_ref()
        .map(|value| value.registered_at_ms)
        .unwrap_or_else(|| {
            if params.client.registered_at_ms == 0 {
                now_ms
            } else {
                params.client.registered_at_ms
            }
        });
    params.client.updated_at_ms = now_ms;
    store_typed(state, &key, &params.client)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "client_id".to_string(),
        hex::encode(params.client.client_id),
    );
    meta.insert("label".to_string(), params.client.label.clone());
    meta.insert(
        "role".to_string(),
        match params.client.role {
            WalletClientRole::ControlPlaneAdmin => "control_plane_admin".to_string(),
            WalletClientRole::Capability => "capability".to_string(),
        },
    );
    meta.insert(
        "replaced".to_string(),
        existing.as_ref().map(|_| true).unwrap_or(false).to_string(),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::ClientRegistered, meta)?;
    Ok(())
}

pub(crate) fn revoke_client(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: WalletRevokeClientParams,
) -> Result<(), TransactionError> {
    ensure_control_root_signer(state, ctx)?;
    let key = registered_client_key(&params.client_id);
    let mut record: WalletRegisteredClientRecord = load_typed(state, &key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "wallet client '{}' is not registered",
            hex::encode(params.client_id)
        ))
    })?;
    record.state = params.state;
    record.updated_at_ms = block_timestamp_ms(ctx);
    if record.state == WalletClientState::Revoked {
        record.expires_at_ms = Some(record.updated_at_ms);
    }
    store_typed(state, &key, &record)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("client_id".to_string(), hex::encode(record.client_id));
    meta.insert("label".to_string(), record.label.clone());
    meta.insert("state".to_string(), format!("{:?}", record.state));
    if !params.reason.trim().is_empty() {
        meta.insert("reason".to_string(), params.reason.trim().to_string());
    }
    append_audit_event(state, ctx, VaultAuditEventKind::ClientRevoked, meta)?;
    Ok(())
}

pub(crate) fn get_client(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: WalletGetClientParams,
) -> Result<(), TransactionError> {
    ensure_wallet_client_role(state, ctx, WalletAuthRole::ControlPlane)?;
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }
    let receipt_key = registered_client_get_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "wallet client get request_id replay detected".to_string(),
        ));
    }
    let client = load_registered_client(state, &params.client_id)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "wallet client '{}' is not registered",
            hex::encode(params.client_id)
        ))
    })?;
    let receipt = WalletGetClientReceipt {
        request_id: params.request_id,
        fetched_at_ms: block_timestamp_ms(ctx),
        client,
    };
    store_typed(state, &receipt_key, &receipt)?;
    Ok(())
}

pub(crate) fn list_clients(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: WalletListClientsParams,
) -> Result<(), TransactionError> {
    ensure_wallet_client_role(state, ctx, WalletAuthRole::ControlPlane)?;
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }
    let receipt_key = registered_client_list_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "wallet client list request_id replay detected".to_string(),
        ));
    }
    let mut clients = Vec::new();
    for row in state.prefix_scan(REGISTERED_CLIENT_PREFIX)? {
        let (_, value) = row?;
        let record = codec::from_bytes_canonical::<WalletRegisteredClientRecord>(&value)?;
        if params.role.map(|role| record.role == role).unwrap_or(true) {
            clients.push(record);
        }
    }
    clients.sort_by(|left, right| left.label.cmp(&right.label));
    let receipt = WalletListClientsReceipt {
        request_id: params.request_id,
        listed_at_ms: block_timestamp_ms(ctx),
        clients,
    };
    store_typed(state, &receipt_key, &receipt)?;
    Ok(())
}
