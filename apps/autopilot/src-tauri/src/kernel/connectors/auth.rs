use super::rpc::{build_wallet_call_tx, query_wallet_state, submit_tx_and_wait};
use super::types::{
    WalletConnectorAuthExportResult, WalletConnectorAuthGetResult, WalletConnectorAuthImportResult,
    WalletConnectorAuthListResult, WalletConnectorAuthRecordView,
};
use super::utils::generate_operation_id;
use crate::kernel::state::get_rpc_client;
use crate::models::AppState;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_crypto::key_store::decrypt_key;
use ioi_services::agentic::desktop::connectors::google_auth::{
    self, GoogleAuthSnapshot, GoogleOauthClientSnapshot,
};
use ioi_types::app::{
    ConnectorAuthGetParams, ConnectorAuthGetReceipt, ConnectorAuthImportParams,
    ConnectorAuthImportReceipt, ConnectorAuthListParams, ConnectorAuthListReceipt,
    ConnectorAuthProtocol, ConnectorAuthRecord, ConnectorAuthState, ConnectorAuthUpsertParams,
    SecretKind, VaultSecretRecord,
};
use ioi_types::codec;
use std::collections::BTreeMap;
use std::sync::Mutex;
use tauri::State;

const CONNECTOR_AUTH_GET_RECEIPT_PREFIX: &[u8] = b"connector_auth_get_receipt::";
const CONNECTOR_AUTH_LIST_RECEIPT_PREFIX: &[u8] = b"connector_auth_list_receipt::";
const CONNECTOR_AUTH_EXPORT_RECEIPT_PREFIX: &[u8] = b"connector_auth_export_receipt::";
const CONNECTOR_AUTH_IMPORT_RECEIPT_PREFIX: &[u8] = b"connector_auth_import_receipt::";
const SECRET_PREFIX: &[u8] = b"secret::";
const SECRET_ALIAS_PREFIX: &[u8] = b"secret_alias::";
const GOOGLE_CONNECTOR_ID: &str = "google.workspace";
const GOOGLE_PROVIDER_FAMILY: &str = "google.workspace";
const GOOGLE_ALIAS_ACCESS_TOKEN: &str = "google.workspace.access_token";
const GOOGLE_ALIAS_REFRESH_TOKEN: &str = "google.workspace.refresh_token";
const GOOGLE_ALIAS_CLIENT_ID: &str = "google.workspace.client_id";
const GOOGLE_ALIAS_CLIENT_SECRET: &str = "google.workspace.client_secret";

fn connector_auth_record_view(record: ConnectorAuthRecord) -> WalletConnectorAuthRecordView {
    WalletConnectorAuthRecordView {
        connector_id: record.connector_id,
        provider_family: record.provider_family,
        auth_protocol: match record.auth_protocol {
            ConnectorAuthProtocol::StaticPassword => "static_password".to_string(),
            ConnectorAuthProtocol::OAuth2Bearer => "oauth2_bearer".to_string(),
            ConnectorAuthProtocol::OAuth2Refresh => "oauth2_refresh".to_string(),
            ConnectorAuthProtocol::ApiKey => "api_key".to_string(),
            ConnectorAuthProtocol::Custom(value) => value,
        },
        state: match record.state {
            ConnectorAuthState::Connected => "connected".to_string(),
            ConnectorAuthState::NeedsAuth => "needs_auth".to_string(),
            ConnectorAuthState::Expired => "expired".to_string(),
            ConnectorAuthState::Revoked => "revoked".to_string(),
            ConnectorAuthState::Degraded => "degraded".to_string(),
        },
        account_label: record.account_label,
        mailbox: record.mailbox,
        granted_scopes: record.granted_scopes,
        credential_aliases: record.credential_aliases,
        metadata: record.metadata,
        updated_at_ms: record.updated_at_ms,
        expires_at_ms: record.expires_at_ms,
        last_validated_at_ms: record.last_validated_at_ms,
    }
}

fn wallet_secret_passphrase() -> String {
    std::env::var("IOI_WALLET_SECRET_PASS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("IOI_GUARDIAN_KEY_PASS")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "local-mode".to_string())
}

fn decrypt_wallet_secret_value(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.starts_with(b"IOI-GKEY") {
        return decrypt_key(ciphertext, &wallet_secret_passphrase())
            .map(|value| value.0.clone())
            .map_err(|error| format!("Failed to decrypt wallet secret: {}", error));
    }
    Ok(ciphertext.to_vec())
}

async fn store_secret_record(
    state: &State<'_, Mutex<AppState>>,
    secret_id: String,
    alias: String,
    value: String,
    kind: SecretKind,
) -> Result<(), String> {
    let mut client = get_rpc_client(state).await?;
    let record = VaultSecretRecord {
        secret_id,
        alias,
        kind,
        ciphertext: value.into_bytes(),
        metadata: BTreeMap::new(),
        created_at_ms: crate::kernel::state::now(),
        rotated_at_ms: None,
    };
    let params = codec::to_bytes_canonical(&record).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("store_secret_record@v1", params)?;
    submit_tx_and_wait(&mut client, tx).await
}

async fn upsert_connector_auth_record(
    state: &State<'_, Mutex<AppState>>,
    record: ConnectorAuthRecord,
) -> Result<(), String> {
    let mut client = get_rpc_client(state).await?;
    let params = codec::to_bytes_canonical(&ConnectorAuthUpsertParams { record })
        .map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("connector_auth_upsert@v1", params)?;
    submit_tx_and_wait(&mut client, tx).await
}

async fn query_secret_record_by_alias(
    state: &State<'_, Mutex<AppState>>,
    alias: &str,
) -> Result<Option<VaultSecretRecord>, String> {
    let mut client = get_rpc_client(state).await?;
    let alias_key = [
        SECRET_ALIAS_PREFIX,
        alias.trim().to_ascii_lowercase().as_bytes(),
    ]
    .concat();
    let secret_id_bytes = match query_wallet_state(&mut client, alias_key).await {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let secret_id: String =
        codec::from_bytes_canonical(&secret_id_bytes).map_err(|e| e.to_string())?;
    let secret_key = [SECRET_PREFIX, secret_id.as_bytes()].concat();
    let secret_bytes = match query_wallet_state(&mut client, secret_key).await {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let secret: VaultSecretRecord =
        codec::from_bytes_canonical(&secret_bytes).map_err(|e| e.to_string())?;
    Ok(Some(secret))
}

pub(crate) async fn wallet_connector_auth_get(
    state: State<'_, Mutex<AppState>>,
    connector_id: String,
) -> Result<WalletConnectorAuthGetResult, String> {
    wallet_connector_auth_get_inner(&state, connector_id).await
}

async fn wallet_connector_auth_get_inner(
    state: &State<'_, Mutex<AppState>>,
    connector_id: String,
) -> Result<WalletConnectorAuthGetResult, String> {
    let request_id = generate_operation_id();
    let params = ConnectorAuthGetParams {
        request_id,
        connector_id,
    };
    let mut client = get_rpc_client(state).await?;
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("connector_auth_get@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;
    let receipt_key = [CONNECTOR_AUTH_GET_RECEIPT_PREFIX, request_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: ConnectorAuthGetReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;
    Ok(WalletConnectorAuthGetResult {
        fetched_at_ms: receipt.fetched_at_ms,
        record: connector_auth_record_view(receipt.record),
    })
}

pub(crate) async fn wallet_connector_auth_list(
    state: State<'_, Mutex<AppState>>,
    provider_family: Option<String>,
) -> Result<WalletConnectorAuthListResult, String> {
    wallet_connector_auth_list_inner(&state, provider_family).await
}

pub(crate) async fn wallet_connector_auth_list_inner(
    state: &State<'_, Mutex<AppState>>,
    provider_family: Option<String>,
) -> Result<WalletConnectorAuthListResult, String> {
    let request_id = generate_operation_id();
    let params = ConnectorAuthListParams {
        request_id,
        provider_family,
    };
    let mut client = get_rpc_client(state).await?;
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("connector_auth_list@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;
    let receipt_key = [CONNECTOR_AUTH_LIST_RECEIPT_PREFIX, request_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: ConnectorAuthListReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;
    Ok(WalletConnectorAuthListResult {
        listed_at_ms: receipt.listed_at_ms,
        records: receipt
            .records
            .into_iter()
            .map(connector_auth_record_view)
            .collect(),
    })
}

pub(crate) async fn wallet_connector_auth_export(
    state: State<'_, Mutex<AppState>>,
    connector_ids: Option<Vec<String>>,
    passphrase: String,
) -> Result<WalletConnectorAuthExportResult, String> {
    let request_id = generate_operation_id();
    let params = ioi_types::app::ConnectorAuthExportParams {
        request_id,
        connector_ids: connector_ids.unwrap_or_default(),
        passphrase,
    };
    let mut client = get_rpc_client(&state).await?;
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("connector_auth_export@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;
    let receipt_key = [CONNECTOR_AUTH_EXPORT_RECEIPT_PREFIX, request_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: ioi_types::app::ConnectorAuthExportReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;
    Ok(WalletConnectorAuthExportResult {
        request_id_hex: hex::encode(receipt.request_id),
        exported_at_ms: receipt.exported_at_ms,
        connector_ids: receipt.connector_ids,
        bundle_base64: STANDARD.encode(receipt.encrypted_bundle),
    })
}

pub(crate) async fn wallet_connector_auth_import(
    state: State<'_, Mutex<AppState>>,
    bundle_base64: String,
    passphrase: String,
    replace_existing: Option<bool>,
) -> Result<WalletConnectorAuthImportResult, String> {
    let request_id = generate_operation_id();
    let params = ConnectorAuthImportParams {
        request_id,
        encrypted_bundle: STANDARD
            .decode(bundle_base64.trim())
            .map_err(|error| format!("Invalid bundle base64: {}", error))?,
        passphrase,
        replace_existing: replace_existing.unwrap_or(false),
    };
    let mut client = get_rpc_client(&state).await?;
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("connector_auth_import@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;
    let receipt_key = [CONNECTOR_AUTH_IMPORT_RECEIPT_PREFIX, request_id.as_slice()].concat();
    let receipt_bytes = query_wallet_state(&mut client, receipt_key).await?;
    let receipt: ConnectorAuthImportReceipt =
        codec::from_bytes_canonical(&receipt_bytes).map_err(|e| e.to_string())?;
    let _ = sync_google_auth_from_wallet(&state).await;
    Ok(WalletConnectorAuthImportResult {
        request_id_hex: hex::encode(receipt.request_id),
        imported_at_ms: receipt.imported_at_ms,
        connector_ids: receipt.connector_ids,
        secret_ids: receipt.secret_ids,
        policy_rule_ids: receipt.policy_rule_ids,
        mailboxes: receipt.mailboxes,
    })
}

pub(crate) async fn sync_google_auth_to_wallet(
    state: &State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let auth_snapshot = google_auth::current_auth_snapshot()?;
    let client_snapshot = google_auth::current_oauth_client_snapshot()?;

    let mut aliases = BTreeMap::new();
    let mut metadata = BTreeMap::new();
    metadata.insert("managed_by".to_string(), "wallet_network".to_string());
    metadata.insert("storage_mode".to_string(), "compat_mirror".to_string());

    if let Some(snapshot) = &auth_snapshot {
        if !snapshot.access_token.trim().is_empty() {
            store_secret_record(
                state,
                "google-workspace-access-token".to_string(),
                GOOGLE_ALIAS_ACCESS_TOKEN.to_string(),
                snapshot.access_token.clone(),
                SecretKind::AccessToken,
            )
            .await?;
            aliases.insert(
                "access_token".to_string(),
                GOOGLE_ALIAS_ACCESS_TOKEN.to_string(),
            );
        }
        if let Some(refresh_token) = snapshot
            .refresh_token
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            store_secret_record(
                state,
                "google-workspace-refresh-token".to_string(),
                GOOGLE_ALIAS_REFRESH_TOKEN.to_string(),
                refresh_token,
                SecretKind::AccessToken,
            )
            .await?;
            aliases.insert(
                "refresh_token".to_string(),
                GOOGLE_ALIAS_REFRESH_TOKEN.to_string(),
            );
        }
        if let Some(expires_at_utc) = snapshot.expires_at_utc.clone() {
            metadata.insert("expires_at_utc".to_string(), expires_at_utc);
        }
    }

    if let Some(snapshot) = &client_snapshot {
        store_secret_record(
            state,
            "google-workspace-client-id".to_string(),
            GOOGLE_ALIAS_CLIENT_ID.to_string(),
            snapshot.client_id.clone(),
            SecretKind::Custom("oauth_client_id".to_string()),
        )
        .await?;
        aliases.insert("client_id".to_string(), GOOGLE_ALIAS_CLIENT_ID.to_string());
        if let Some(client_secret) = snapshot
            .client_secret
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            store_secret_record(
                state,
                "google-workspace-client-secret".to_string(),
                GOOGLE_ALIAS_CLIENT_SECRET.to_string(),
                client_secret,
                SecretKind::Custom("oauth_client_secret".to_string()),
            )
            .await?;
            aliases.insert(
                "client_secret".to_string(),
                GOOGLE_ALIAS_CLIENT_SECRET.to_string(),
            );
        }
    }

    let now_ms = crate::kernel::state::now();
    let record = ConnectorAuthRecord {
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        provider_family: GOOGLE_PROVIDER_FAMILY.to_string(),
        auth_protocol: if auth_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.refresh_token.as_ref())
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            ConnectorAuthProtocol::OAuth2Refresh
        } else {
            ConnectorAuthProtocol::OAuth2Bearer
        },
        state: if auth_snapshot.is_some() || client_snapshot.is_some() {
            ConnectorAuthState::Connected
        } else {
            ConnectorAuthState::NeedsAuth
        },
        account_label: auth_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.account_email.clone()),
        mailbox: None,
        granted_scopes: auth_snapshot
            .as_ref()
            .map(|snapshot| snapshot.granted_scopes.clone())
            .unwrap_or_default(),
        credential_aliases: aliases,
        metadata,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
        expires_at_ms: None,
        last_validated_at_ms: Some(now_ms),
    };
    upsert_connector_auth_record(state, record).await
}

pub(crate) async fn sync_google_auth_from_wallet(
    state: &State<'_, Mutex<AppState>>,
) -> Result<bool, String> {
    let result = match wallet_connector_auth_get_inner(state, GOOGLE_CONNECTOR_ID.to_string()).await
    {
        Ok(result) => result,
        Err(_) => return Ok(false),
    };
    let aliases = result.record.credential_aliases;
    if aliases.is_empty() {
        google_auth::replace_local_auth_snapshot(None)?;
        google_auth::replace_local_oauth_client_snapshot(None)?;
        return Ok(true);
    }

    let access_token = if let Some(alias) = aliases.get("access_token") {
        query_secret_record_by_alias(state, alias)
            .await?
            .map(|record| decrypt_wallet_secret_value(&record.ciphertext))
            .transpose()?
            .map(|value| String::from_utf8(value).map_err(|e| e.to_string()))
            .transpose()?
            .unwrap_or_default()
    } else {
        String::new()
    };
    let refresh_token = if let Some(alias) = aliases.get("refresh_token") {
        query_secret_record_by_alias(state, alias)
            .await?
            .map(|record| decrypt_wallet_secret_value(&record.ciphertext))
            .transpose()?
            .map(|value| String::from_utf8(value).map_err(|e| e.to_string()))
            .transpose()?
            .filter(|value| !value.trim().is_empty())
    } else {
        None
    };
    let client_id = if let Some(alias) = aliases.get("client_id") {
        query_secret_record_by_alias(state, alias)
            .await?
            .map(|record| decrypt_wallet_secret_value(&record.ciphertext))
            .transpose()?
            .map(|value| String::from_utf8(value).map_err(|e| e.to_string()))
            .transpose()?
    } else {
        None
    };
    let client_secret = if let Some(alias) = aliases.get("client_secret") {
        query_secret_record_by_alias(state, alias)
            .await?
            .map(|record| decrypt_wallet_secret_value(&record.ciphertext))
            .transpose()?
            .map(|value| String::from_utf8(value).map_err(|e| e.to_string()))
            .transpose()?
            .filter(|value| !value.trim().is_empty())
    } else {
        None
    };

    google_auth::replace_local_auth_snapshot(Some(GoogleAuthSnapshot {
        account_email: result.record.account_label.clone(),
        access_token,
        refresh_token,
        expires_at_utc: result.record.metadata.get("expires_at_utc").cloned(),
        granted_scopes: result.record.granted_scopes.clone(),
        token_type: "Bearer".to_string(),
    }))?;

    if let Some(client_id) = client_id.filter(|value| !value.trim().is_empty()) {
        google_auth::replace_local_oauth_client_snapshot(Some(GoogleOauthClientSnapshot {
            client_id,
            client_secret,
        }))?;
    }

    Ok(true)
}

pub(crate) async fn bootstrap_google_wallet_auth(
    state: &State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    if sync_google_auth_from_wallet(state).await? {
        return Ok(());
    }
    sync_google_auth_to_wallet(state).await
}
