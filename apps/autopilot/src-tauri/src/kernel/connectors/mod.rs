mod auth;
mod commands;
mod config;
mod constants;
mod google_workspace;
mod operations;
mod policy;
mod rpc;
mod subscriptions;
mod types;
mod utils;

use crate::models::AppState;
use chrono::{TimeZone, Utc};
use serde_json::Value;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};

pub(crate) use auth::bootstrap_google_wallet_auth;
pub(crate) use policy::bootstrap_wallet_policy_state;
pub use policy::{
    policy_state_path_for, AutomationPolicyMode, ConnectorPolicyOverride, DataHandlingMode,
    GlobalPolicyDefaults, PolicyDecisionMode, ShieldApprovalHookReceipt, ShieldPolicyManager,
    ShieldPolicyState, ShieldRememberApprovalInput, ShieldRememberedApprovalExpiryUpdateInput,
    ShieldRememberedApprovalScopeUpdateInput, ShieldRememberedApprovalSnapshot,
};
pub use subscriptions::{
    registry_path_for, GoogleAutomationManager, GoogleConnectorSubscriptionView,
};
pub use types::{
    ConnectorCatalogEntry, WalletConnectorAuthExportResult, WalletConnectorAuthGetResult,
    WalletConnectorAuthImportResult, WalletConnectorAuthListResult,
    WalletMailConfigureAccountResult, WalletMailConfiguredAccountView, WalletMailDeleteSpamResult,
    WalletMailListRecentResult, WalletMailReadLatestResult, WalletMailReplyResult,
};

const GOOGLE_CONNECTOR_ID: &str = "google.workspace";
const MAIL_CONNECTOR_ID: &str = "mail.primary";
const MAIL_PROVIDER_FAMILY: &str = "mail.wallet_network";
const SHIELD_APPROVAL_MEMORY_UPDATED_EVENT: &str = "shield-approval-memory-updated";

fn connector_status_from_wallet_state(state: &str) -> String {
    match state.trim().to_ascii_lowercase().as_str() {
        "connected" => "connected".to_string(),
        "expired" | "revoked" | "degraded" => "degraded".to_string(),
        _ => "needs_auth".to_string(),
    }
}

fn timestamp_ms_to_utc(value: u64) -> Option<String> {
    Utc.timestamp_millis_opt(value as i64)
        .single()
        .map(|timestamp| timestamp.to_rfc3339())
}

fn base_connector_catalog() -> Vec<ConnectorCatalogEntry> {
    vec![
        ConnectorCatalogEntry {
            id: MAIL_CONNECTOR_ID.to_string(),
            plugin_id: "wallet_mail".to_string(),
            name: "Mail".to_string(),
            provider: "wallet.network".to_string(),
            category: "communication".to_string(),
            description:
                "Wallet-backed mail connector for delegated inbox listing, latest-message reads, spam cleanup, and governed replies.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec![
                "mail.read.latest".to_string(),
                "mail.list.recent".to_string(),
                "mail.delete.spam".to_string(),
                "mail.reply".to_string(),
            ],
            last_sync_at_utc: None,
            notes: Some(
                "Configure a mailbox to bind durable mail operations through the wallet auth layer."
                    .to_string(),
            ),
        },
        ConnectorCatalogEntry {
            id: GOOGLE_CONNECTOR_ID.to_string(),
            plugin_id: "google_workspace".to_string(),
            name: "Google".to_string(),
            provider: "google".to_string(),
            category: "productivity".to_string(),
            description:
                "Single Google connector exposing Gmail, Calendar, Docs, Sheets, BigQuery, Drive, Tasks, Chat, events, workflows, and expert raw access.".to_string(),
            status: "needs_auth".to_string(),
            auth_mode: "wallet_capability".to_string(),
            scopes: vec![
                "gmail".to_string(),
                "calendar".to_string(),
                "docs".to_string(),
                "sheets".to_string(),
                "bigquery".to_string(),
                "drive".to_string(),
                "tasks".to_string(),
                "chat".to_string(),
                "events".to_string(),
                "workflow".to_string(),
                "expert".to_string(),
            ],
            last_sync_at_utc: None,
            notes: Some(
                "Uses native Google OAuth for consent, then binds durable auth and governed execution through the wallet layer.".to_string(),
            ),
        },
    ]
}

fn patch_connector_catalog_from_auth(
    entries: &mut [ConnectorCatalogEntry],
    auth: &WalletConnectorAuthListResult,
) {
    if let Some(google_entry) = entries
        .iter_mut()
        .find(|entry| entry.id == GOOGLE_CONNECTOR_ID)
    {
        if let Some(record) = auth
            .records
            .iter()
            .find(|record| record.connector_id == GOOGLE_CONNECTOR_ID)
        {
            google_entry.status = connector_status_from_wallet_state(&record.state);
            google_entry.last_sync_at_utc = timestamp_ms_to_utc(record.updated_at_ms);
            if !record.granted_scopes.is_empty() {
                google_entry.scopes = record.granted_scopes.clone();
            }
            google_entry.notes = Some(match record.account_label.as_deref() {
                Some(account) if !account.trim().is_empty() => {
                    format!("Connected Google Workspace account {}.", account.trim())
                }
                _ => "Google Workspace auth is registered in the wallet layer.".to_string(),
            });
        }
    }

    if let Some(mail_entry) = entries
        .iter_mut()
        .find(|entry| entry.id == MAIL_CONNECTOR_ID)
    {
        let mail_records: Vec<_> = auth
            .records
            .iter()
            .filter(|record| {
                record.provider_family == MAIL_PROVIDER_FAMILY
                    || record.connector_id.starts_with("mail.")
            })
            .collect();

        if let Some(latest_record) = mail_records
            .iter()
            .max_by_key(|record| record.updated_at_ms)
        {
            mail_entry.status = connector_status_from_wallet_state(&latest_record.state);
            mail_entry.last_sync_at_utc = timestamp_ms_to_utc(latest_record.updated_at_ms);
            if !latest_record.granted_scopes.is_empty() {
                mail_entry.scopes = latest_record.granted_scopes.clone();
            }

            let configured_mailboxes = mail_records
                .iter()
                .filter_map(|record| record.mailbox.as_deref())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();

            let account = latest_record
                .account_label
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            mail_entry.notes = Some(match (configured_mailboxes.len(), account) {
                (count, Some(account_label)) if count > 1 => format!(
                    "Connected {} wallet-backed mailboxes. Most recent account: {}.",
                    count, account_label
                ),
                (_, Some(account_label)) => {
                    format!("Connected wallet-backed mail account {}.", account_label)
                }
                (count, None) if count > 1 => {
                    format!("Connected {} wallet-backed mailboxes.", count)
                }
                _ => "Wallet-backed mail auth is registered.".to_string(),
            });
        }
    }
}

fn mail_account_views_from_auth(
    auth: &WalletConnectorAuthListResult,
) -> Vec<WalletMailConfiguredAccountView> {
    let mut accounts = auth
        .records
        .iter()
        .filter(|record| {
            record.provider_family == MAIL_PROVIDER_FAMILY
                || record.connector_id.starts_with("mail.")
        })
        .filter_map(|record| {
            let mailbox = record.mailbox.as_deref()?.trim().to_string();
            let account_email = record.account_label.as_deref()?.trim().to_string();
            if mailbox.is_empty() || account_email.is_empty() {
                return None;
            }
            Some(WalletMailConfiguredAccountView {
                mailbox,
                account_email,
                sender_display_name: None,
                default_channel_id_hex: None,
                default_lease_id_hex: None,
                updated_at_ms: record.updated_at_ms,
            })
        })
        .collect::<Vec<_>>();
    accounts.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.mailbox.cmp(&right.mailbox))
    });
    accounts.dedup_by(|left, right| left.mailbox == right.mailbox);
    accounts
}

pub(crate) fn wallet_backed_bootstrap_enabled() -> bool {
    if let Ok(explicit) = std::env::var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP") {
        let normalized = explicit.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "on") {
            return true;
        }
        if matches!(normalized.as_str(), "0" | "false" | "no" | "off") {
            return false;
        }
    }

    if crate::is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV") {
        return false;
    }

    !matches!(
        std::env::var("AUTOPILOT_DATA_PROFILE")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("desktop-localgpu")
    )
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[tauri::command]
pub async fn connector_list_catalog(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<ConnectorCatalogEntry>, String> {
    let mut entries = base_connector_catalog();
    if let Ok(auth) = auth::wallet_connector_auth_list_inner(&state, None).await {
        patch_connector_catalog_from_auth(&mut entries, &auth);
    }
    Ok(entries)
}

#[tauri::command]
pub async fn wallet_mail_list_accounts(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<WalletMailConfiguredAccountView>, String> {
    let auth =
        auth::wallet_connector_auth_list_inner(&state, Some(MAIL_PROVIDER_FAMILY.to_string()))
            .await?;
    Ok(mail_account_views_from_auth(&auth))
}

#[tauri::command]
pub async fn wallet_mail_configure_account(
    state: State<'_, Mutex<AppState>>,
    mailbox: Option<String>,
    account_email: String,
    auth_mode: Option<String>,
    imap_host: String,
    imap_port: u16,
    imap_tls_mode: Option<String>,
    smtp_host: String,
    smtp_port: u16,
    smtp_tls_mode: Option<String>,
    sender_display_name: Option<String>,
    imap_username: Option<String>,
    imap_secret: String,
    smtp_username: Option<String>,
    smtp_secret: String,
) -> Result<WalletMailConfigureAccountResult, String> {
    commands::wallet_mail_configure_account(
        state,
        mailbox,
        account_email,
        auth_mode,
        imap_host,
        imap_port,
        imap_tls_mode,
        smtp_host,
        smtp_port,
        smtp_tls_mode,
        sender_display_name,
        imap_username,
        imap_secret,
        smtp_username,
        smtp_secret,
    )
    .await
}

#[tauri::command]
pub async fn wallet_mail_read_latest(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    shield_approved: Option<bool>,
) -> Result<WalletMailReadLatestResult, String> {
    let result = commands::wallet_mail_read_latest(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_mail_list_recent(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    limit: Option<u32>,
    shield_approved: Option<bool>,
) -> Result<WalletMailListRecentResult, String> {
    let result = commands::wallet_mail_list_recent(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        limit,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_mail_delete_spam(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    max_delete: Option<u32>,
    shield_approved: Option<bool>,
) -> Result<WalletMailDeleteSpamResult, String> {
    let result = commands::wallet_mail_delete_spam(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        max_delete,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_mail_reply(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, ShieldPolicyManager>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    to: String,
    subject: String,
    body: String,
    reply_to_message_id: Option<String>,
    shield_approved: Option<bool>,
) -> Result<WalletMailReplyResult, String> {
    let result = commands::wallet_mail_reply(
        state,
        policy_manager.clone(),
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        to,
        subject,
        body,
        reply_to_message_id,
        shield_approved,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn wallet_connector_auth_get(
    state: State<'_, Mutex<AppState>>,
    connector_id: String,
) -> Result<WalletConnectorAuthGetResult, String> {
    auth::wallet_connector_auth_get(state, connector_id).await
}

#[tauri::command]
pub async fn wallet_connector_auth_list(
    state: State<'_, Mutex<AppState>>,
    provider_family: Option<String>,
) -> Result<WalletConnectorAuthListResult, String> {
    auth::wallet_connector_auth_list(state, provider_family).await
}

#[tauri::command]
pub async fn wallet_connector_auth_export(
    state: State<'_, Mutex<AppState>>,
    connector_ids: Option<Vec<String>>,
    passphrase: String,
) -> Result<WalletConnectorAuthExportResult, String> {
    auth::wallet_connector_auth_export(state, connector_ids, passphrase).await
}

#[tauri::command]
pub async fn wallet_connector_auth_import(
    state: State<'_, Mutex<AppState>>,
    bundle_base64: String,
    passphrase: String,
    replace_existing: Option<bool>,
) -> Result<WalletConnectorAuthImportResult, String> {
    auth::wallet_connector_auth_import(state, bundle_base64, passphrase, replace_existing).await
}

#[tauri::command]
pub async fn connector_list_actions(
    connector_id: String,
) -> Result<Vec<google_workspace::ConnectorActionDefinition>, String> {
    google_workspace::connector_list_actions(connector_id).await
}

#[tauri::command]
pub async fn connector_configure(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    input: Value,
) -> Result<google_workspace::ConnectorConfigureResult, String> {
    google_workspace::connector_configure(state, manager, connector_id, input).await
}

#[tauri::command]
pub async fn connector_run_action(
    app: AppHandle,
    manager: State<'_, GoogleAutomationManager>,
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    action_id: String,
    input: Value,
) -> Result<google_workspace::ConnectorActionResult, String> {
    let result = google_workspace::connector_run_action(
        manager,
        policy_manager.clone(),
        connector_id,
        action_id,
        input,
    )
    .await;
    let _ = app.emit(
        SHIELD_APPROVAL_MEMORY_UPDATED_EVENT,
        policy_manager.approval_snapshot(),
    );
    result
}

#[tauri::command]
pub async fn connector_list_subscriptions(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
) -> Result<Vec<GoogleConnectorSubscriptionView>, String> {
    google_workspace::connector_list_subscriptions(manager, connector_id).await
}

#[tauri::command]
pub async fn connector_stop_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_stop_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_resume_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_resume_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_renew_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_renew_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_get_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    google_workspace::connector_get_subscription(manager, connector_id, subscription_id).await
}

#[tauri::command]
pub async fn connector_fetch_gmail_thread(
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    thread_id: String,
) -> Result<google_workspace::ConnectorActionResult, String> {
    google_workspace::connector_fetch_gmail_thread(policy_manager, connector_id, thread_id).await
}

#[tauri::command]
pub async fn connector_fetch_calendar_event(
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    calendar_id: String,
    event_id: String,
) -> Result<google_workspace::ConnectorActionResult, String> {
    google_workspace::connector_fetch_calendar_event(
        policy_manager,
        connector_id,
        calendar_id,
        event_id,
    )
    .await
}

#[tauri::command]
pub async fn connector_policy_get(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, ShieldPolicyManager>,
) -> Result<ShieldPolicyState, String> {
    policy::current_policy_state(state, manager).await
}

#[tauri::command]
pub async fn connector_policy_set(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, ShieldPolicyManager>,
    policy: ShieldPolicyState,
) -> Result<ShieldPolicyState, String> {
    policy::replace_policy_state(state, manager, policy).await
}

#[tauri::command]
pub async fn connector_policy_memory_get(
    manager: State<'_, ShieldPolicyManager>,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    policy::current_remembered_approval_snapshot(manager).await
}

#[tauri::command]
pub async fn connector_policy_memory_remember(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberApprovalInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::remember_approval_in_runtime(manager, input).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn connector_policy_memory_forget(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    decision_id: String,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::forget_approval_in_runtime(manager, decision_id).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn connector_policy_memory_set_scope_mode(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberedApprovalScopeUpdateInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::update_approval_scope_mode_in_runtime(manager, input).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub async fn connector_policy_memory_set_expiry(
    app: AppHandle,
    manager: State<'_, ShieldPolicyManager>,
    input: ShieldRememberedApprovalExpiryUpdateInput,
) -> Result<ShieldRememberedApprovalSnapshot, String> {
    let snapshot = policy::update_approval_expiry_in_runtime(manager, input).await?;
    let _ = app.emit(SHIELD_APPROVAL_MEMORY_UPDATED_EVENT, &snapshot);
    Ok(snapshot)
}
