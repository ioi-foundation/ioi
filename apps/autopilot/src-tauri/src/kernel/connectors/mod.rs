mod approval;
mod commands;
mod config;
mod constants;
mod intent;
mod operations;
mod rpc;
mod types;
mod utils;

use crate::models::AppState;
use std::sync::Mutex;
use tauri::State;

pub use types::{
    WalletMailApprovalArtifactResult, WalletMailConfigureAccountResult, WalletMailDeleteSpamResult,
    WalletMailIntentResult, WalletMailListRecentResult, WalletMailReadLatestResult,
    WalletMailReplyResult,
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
        imap_username,
        imap_secret,
        smtp_username,
        smtp_secret,
    )
    .await
}

#[tauri::command]
pub async fn wallet_mail_generate_approval_artifact(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    query: String,
    mailbox: Option<String>,
    ttl_seconds: Option<u64>,
) -> Result<WalletMailApprovalArtifactResult, String> {
    commands::wallet_mail_generate_approval_artifact(
        state,
        channel_id,
        lease_id,
        op_seq,
        query,
        mailbox,
        ttl_seconds,
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
pub async fn wallet_mail_handle_intent(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    query: String,
    mailbox: Option<String>,
    list_limit: Option<u32>,
    approval_artifact_json: Option<String>,
) -> Result<WalletMailIntentResult, String> {
    commands::wallet_mail_handle_intent(
        state,
        channel_id,
        lease_id,
        op_seq,
        query,
        mailbox,
        list_limit,
        approval_artifact_json,
    )
    .await
}
