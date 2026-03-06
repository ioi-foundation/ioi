use super::config::{
    alias_for_mailbox, mailbox_or_default, parse_mail_connector_auth_mode,
    parse_mail_connector_tls_mode, secret_id_for_mailbox, tls_mode_label,
};
use super::operations::{
    execute_wallet_mail_delete_spam, execute_wallet_mail_list_recent,
    execute_wallet_mail_read_latest, execute_wallet_mail_reply,
};
use super::rpc::{build_wallet_call_tx, submit_tx_and_wait};
use super::types::{
    WalletMailConfigureAccountResult, WalletMailDeleteSpamResult, WalletMailListRecentResult,
    WalletMailReadLatestResult, WalletMailReplyResult,
};
use crate::kernel::state::get_rpc_client;
use crate::models::AppState;
use ioi_types::app::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
    MailConnectorSecretAliases, MailConnectorTlsMode, MailConnectorUpsertParams, SecretKind,
    VaultSecretRecord,
};
use ioi_types::codec;
use std::collections::BTreeMap;
use std::sync::Mutex;
use tauri::State;

pub(super) async fn wallet_mail_configure_account(
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
    let mailbox = mailbox_or_default(mailbox);
    let account_email = account_email.trim().to_string();
    if account_email.is_empty() || !account_email.contains('@') {
        return Err("accountEmail must be a valid email-like value.".to_string());
    }

    let imap_host = imap_host.trim().to_string();
    let smtp_host = smtp_host.trim().to_string();
    if imap_host.is_empty() || smtp_host.is_empty() {
        return Err("IMAP and SMTP host values are required.".to_string());
    }
    if imap_port == 0 || smtp_port == 0 {
        return Err("IMAP and SMTP ports must be > 0.".to_string());
    }

    let auth_mode = parse_mail_connector_auth_mode(auth_mode.as_deref())?;
    let imap_tls_mode =
        parse_mail_connector_tls_mode(imap_tls_mode.as_deref(), MailConnectorTlsMode::Tls)?;
    let smtp_tls_mode =
        parse_mail_connector_tls_mode(smtp_tls_mode.as_deref(), MailConnectorTlsMode::StartTls)?;

    let imap_username = imap_username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(account_email.as_str())
        .to_string();
    let smtp_username = smtp_username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(account_email.as_str())
        .to_string();

    let imap_secret = imap_secret.trim().to_string();
    let smtp_secret = smtp_secret.trim().to_string();
    if imap_secret.is_empty() || smtp_secret.is_empty() {
        return Err("IMAP/SMTP secret values are required.".to_string());
    }
    let sender_display_name = sender_display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);

    let imap_username_alias = alias_for_mailbox(&mailbox, "imap.username");
    let smtp_username_alias = alias_for_mailbox(&mailbox, "smtp.username");
    let (imap_secret_alias, smtp_secret_alias, auth_secret_kind) = match auth_mode {
        MailConnectorAuthMode::Password => (
            alias_for_mailbox(&mailbox, "imap.password"),
            alias_for_mailbox(&mailbox, "smtp.password"),
            SecretKind::Password,
        ),
        MailConnectorAuthMode::Oauth2 => (
            alias_for_mailbox(&mailbox, "imap.bearer_token"),
            alias_for_mailbox(&mailbox, "smtp.bearer_token"),
            SecretKind::AccessToken,
        ),
    };

    let now_ms = crate::kernel::state::now();
    let secret_specs = vec![
        (
            secret_id_for_mailbox(&mailbox, "imap-username"),
            imap_username_alias.clone(),
            imap_username,
            SecretKind::AccessToken,
        ),
        (
            secret_id_for_mailbox(&mailbox, "imap-secret"),
            imap_secret_alias.clone(),
            imap_secret,
            auth_secret_kind.clone(),
        ),
        (
            secret_id_for_mailbox(&mailbox, "smtp-username"),
            smtp_username_alias.clone(),
            smtp_username,
            SecretKind::AccessToken,
        ),
        (
            secret_id_for_mailbox(&mailbox, "smtp-secret"),
            smtp_secret_alias.clone(),
            smtp_secret,
            auth_secret_kind,
        ),
    ];

    let mut client = get_rpc_client(&state).await?;
    for (secret_id, alias, value, kind) in secret_specs {
        let record = VaultSecretRecord {
            secret_id,
            alias,
            kind,
            ciphertext: value.into_bytes(),
            metadata: BTreeMap::new(),
            created_at_ms: now_ms,
            rotated_at_ms: None,
        };
        let params_bytes = codec::to_bytes_canonical(&record).map_err(|e| e.to_string())?;
        let tx = build_wallet_call_tx("store_secret_record@v1", params_bytes)?;
        submit_tx_and_wait(&mut client, tx).await?;
    }

    let connector = MailConnectorUpsertParams {
        mailbox: mailbox.clone(),
        config: MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode,
            account_email: account_email.clone(),
            sender_display_name: sender_display_name.clone(),
            imap: MailConnectorEndpoint {
                host: imap_host.clone(),
                port: imap_port,
                tls_mode: imap_tls_mode,
            },
            smtp: MailConnectorEndpoint {
                host: smtp_host.clone(),
                port: smtp_port,
                tls_mode: smtp_tls_mode,
            },
            secret_aliases: MailConnectorSecretAliases {
                imap_username_alias: imap_username_alias.clone(),
                imap_password_alias: imap_secret_alias.clone(),
                smtp_username_alias: smtp_username_alias.clone(),
                smtp_password_alias: smtp_secret_alias.clone(),
            },
            metadata: {
                let mut metadata = BTreeMap::new();
                metadata.insert(
                    "configured_by".to_string(),
                    "autopilot.integrations".to_string(),
                );
                metadata
            },
        },
    };
    let params_bytes = codec::to_bytes_canonical(&connector).map_err(|e| e.to_string())?;
    let tx = build_wallet_call_tx("mail_connector_upsert@v1", params_bytes)?;
    submit_tx_and_wait(&mut client, tx).await?;

    Ok(WalletMailConfigureAccountResult {
        mailbox,
        account_email,
        sender_display_name,
        auth_mode: match auth_mode {
            MailConnectorAuthMode::Password => "password".to_string(),
            MailConnectorAuthMode::Oauth2 => "oauth2".to_string(),
        },
        imap_host,
        imap_port,
        imap_tls_mode: tls_mode_label(imap_tls_mode).to_string(),
        smtp_host,
        smtp_port,
        smtp_tls_mode: tls_mode_label(smtp_tls_mode).to_string(),
        imap_username_alias,
        imap_secret_alias,
        smtp_username_alias,
        smtp_secret_alias,
        updated_at_ms: now_ms,
    })
}

pub(super) async fn wallet_mail_read_latest(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
) -> Result<WalletMailReadLatestResult, String> {
    execute_wallet_mail_read_latest(&state, &channel_id, &lease_id, op_seq, mailbox).await
}

pub(super) async fn wallet_mail_list_recent(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    limit: Option<u32>,
) -> Result<WalletMailListRecentResult, String> {
    execute_wallet_mail_list_recent(&state, &channel_id, &lease_id, op_seq, mailbox, limit).await
}

pub(super) async fn wallet_mail_delete_spam(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    mailbox: Option<String>,
    max_delete: Option<u32>,
) -> Result<WalletMailDeleteSpamResult, String> {
    execute_wallet_mail_delete_spam(&state, &channel_id, &lease_id, op_seq, mailbox, max_delete)
        .await
}

pub(super) async fn wallet_mail_reply(
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
    execute_wallet_mail_reply(
        &state,
        &channel_id,
        &lease_id,
        op_seq,
        mailbox,
        to,
        subject,
        body,
        reply_to_message_id,
    )
    .await
}
