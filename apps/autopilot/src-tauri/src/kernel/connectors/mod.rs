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
use serde_json::Value;
use std::sync::Mutex;
use tauri::State;

pub(crate) use auth::bootstrap_google_wallet_auth;
pub(crate) use policy::bootstrap_wallet_policy_state;
pub use policy::{policy_state_path_for, ShieldPolicyManager, ShieldPolicyState};
pub use subscriptions::{
    registry_path_for, GoogleAutomationManager, GoogleConnectorSubscriptionView,
};
pub use types::{
    WalletConnectorAuthExportResult, WalletConnectorAuthGetResult, WalletConnectorAuthImportResult,
    WalletConnectorAuthListResult, WalletMailConfigureAccountResult, WalletMailDeleteSpamResult,
    WalletMailListRecentResult, WalletMailReadLatestResult, WalletMailReplyResult,
};

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
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
) -> Result<WalletMailReadLatestResult, String> {
    commands::wallet_mail_read_latest(state, channel_id, lease_id, op_seq, mailbox).await
}

#[tauri::command]
pub async fn wallet_mail_list_recent(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    limit: Option<u32>,
) -> Result<WalletMailListRecentResult, String> {
    commands::wallet_mail_list_recent(state, channel_id, lease_id, op_seq, mailbox, limit).await
}

#[tauri::command]
pub async fn wallet_mail_delete_spam(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    max_delete: Option<u32>,
) -> Result<WalletMailDeleteSpamResult, String> {
    commands::wallet_mail_delete_spam(state, channel_id, lease_id, op_seq, mailbox, max_delete)
        .await
}

#[tauri::command]
pub async fn wallet_mail_reply(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    to: String,
    subject: String,
    body: String,
    reply_to_message_id: Option<String>,
) -> Result<WalletMailReplyResult, String> {
    commands::wallet_mail_reply(
        state,
        channel_id,
        lease_id,
        op_seq,
        mailbox,
        to,
        subject,
        body,
        reply_to_message_id,
    )
    .await
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
    manager: State<'_, GoogleAutomationManager>,
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    action_id: String,
    input: Value,
) -> Result<google_workspace::ConnectorActionResult, String> {
    google_workspace::connector_run_action(manager, policy_manager, connector_id, action_id, input)
        .await
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
