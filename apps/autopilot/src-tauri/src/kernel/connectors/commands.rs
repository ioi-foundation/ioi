use super::approval::{
    build_mail_intent_request_hash, normalize_approval_ttl_seconds, normalize_token_expiry_ms,
    synthesize_write_approval_artifact, verify_write_approval_artifact,
};
use super::config::{
    alias_for_mailbox, mailbox_or_default, parse_mail_connector_auth_mode,
    parse_mail_connector_tls_mode, secret_id_for_mailbox, tls_mode_label,
};
use super::constants::MAIL_CONNECTOR_DEFAULT_MAILBOX;
use super::intent::{classify_mail_intent, extract_reply_target, MailIntentKind};
use super::operations::{
    execute_wallet_mail_delete_spam, execute_wallet_mail_list_recent,
    execute_wallet_mail_read_latest, execute_wallet_mail_reply,
};
use super::rpc::{build_wallet_call_tx, load_wallet_revocation_epoch, submit_tx_and_wait};
use super::types::{
    WalletMailApprovalArtifactResult, WalletMailConfigureAccountResult, WalletMailDeleteSpamResult,
    WalletMailIntentResult, WalletMailListRecentResult, WalletMailReadLatestResult,
    WalletMailReplyResult,
};
use super::utils::decode_hex_32;
use crate::kernel::state::get_rpc_client;
use crate::models::AppState;
use ioi_types::app::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
    MailConnectorSecretAliases, MailConnectorTlsMode, MailConnectorUpsertParams, SecretKind,
    VaultSecretRecord, WalletApprovalDecision,
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

pub(super) async fn wallet_mail_generate_approval_artifact(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    query: String,
    mailbox: Option<String>,
    ttl_seconds: Option<u64>,
) -> Result<WalletMailApprovalArtifactResult, String> {
    if channel_id.trim().is_empty() || lease_id.trim().is_empty() {
        return Err("Channel ID and Lease ID are required.".to_string());
    }
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }

    let trimmed_query = query.trim().to_string();
    if trimmed_query.is_empty() {
        return Err("Mail request is empty.".to_string());
    }

    let intent = classify_mail_intent(&trimmed_query);
    if intent == MailIntentKind::Unknown {
        return Err(
            "Unsupported mail request. Try 'delete spam' or 'reply to <recipient>'.".to_string(),
        );
    }
    if !intent.requires_step_up_approval() {
        return Err("This intent does not require step-up approval.".to_string());
    }

    let channel_id_arr = decode_hex_32("channelId", &channel_id)?;
    let lease_id_arr = decode_hex_32("leaseId", &lease_id)?;
    let mailbox_value = mailbox
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(MAIL_CONNECTOR_DEFAULT_MAILBOX)
        .to_string();
    let ttl = normalize_approval_ttl_seconds(ttl_seconds);
    let now_ms = crate::kernel::state::now();

    let active_revocation_epoch = {
        let mut client = get_rpc_client(&state).await?;
        load_wallet_revocation_epoch(&mut client).await?
    };

    let artifact = synthesize_write_approval_artifact(
        intent,
        channel_id_arr,
        lease_id_arr,
        &mailbox_value,
        &trimmed_query,
        op_seq,
        now_ms,
        ttl,
        active_revocation_epoch,
    )?;

    let token = artifact
        .approval_token
        .as_ref()
        .ok_or_else(|| "synthesized approval artifact is missing approval_token".to_string())?;
    let approval_artifact_json =
        serde_json::to_string_pretty(&artifact).map_err(|e| e.to_string())?;

    Ok(WalletMailApprovalArtifactResult {
        normalized_intent: intent.as_str().to_string(),
        request_hash_hex: hex::encode(artifact.interception.request_hash),
        audience_hex: hex::encode(token.audience),
        revocation_epoch: token.revocation_epoch,
        expires_at_ms: normalize_token_expiry_ms(token.scope.expires_at),
        approval_artifact_json,
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

pub(super) async fn wallet_mail_handle_intent(
    state: State<'_, Mutex<AppState>>,
    channel_id: String,
    lease_id: String,
    op_seq: u64,
    query: String,
    mailbox: Option<String>,
    list_limit: Option<u32>,
    approval_artifact_json: Option<String>,
) -> Result<WalletMailIntentResult, String> {
    if channel_id.trim().is_empty() || lease_id.trim().is_empty() {
        return Err("Channel ID and Lease ID are required.".to_string());
    }
    if op_seq == 0 {
        return Err("opSeq must be >= 1".to_string());
    }

    let trimmed_query = query.trim().to_string();
    if trimmed_query.is_empty() {
        return Err("Mail request is empty.".to_string());
    }

    let intent = classify_mail_intent(&trimmed_query);
    let mailbox_value = mailbox.unwrap_or_else(|| MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string());
    let channel_id_binding = decode_hex_32("channelId", &channel_id)?;
    let lease_id_binding = decode_hex_32("leaseId", &lease_id)?;
    let expected_request_hash = if intent.requires_step_up_approval() {
        Some(build_mail_intent_request_hash(
            intent,
            channel_id_binding,
            lease_id_binding,
            &mailbox_value,
            &trimmed_query,
            op_seq,
        )?)
    } else {
        None
    };
    let mut out = WalletMailIntentResult {
        query: trimmed_query.clone(),
        normalized_intent: intent.as_str().to_string(),
        policy_decision: "blocked".to_string(),
        reason: "No policy route matched this mail request.".to_string(),
        approved: false,
        executed: false,
        operation: None,
        next_op_seq: op_seq,
        read_latest: None,
        list_recent: None,
        delete_spam: None,
        reply: None,
    };

    if intent == MailIntentKind::Unknown {
        out.reason =
            "Unsupported mail request. Try 'check inbox' or 'read latest email'.".to_string();
        return Ok(out);
    }

    if intent.requires_step_up_approval() {
        let Some(raw_artifact) = approval_artifact_json.as_deref().map(str::trim) else {
            out.policy_decision = "approval_required".to_string();
            out.reason = "Write/destructive mail intents require an approval artifact.".to_string();
            return Ok(out);
        };
        if raw_artifact.is_empty() {
            out.policy_decision = "approval_required".to_string();
            out.reason = "Write/destructive mail intents require an approval artifact.".to_string();
            return Ok(out);
        }

        let approval: WalletApprovalDecision = match serde_json::from_str(raw_artifact) {
            Ok(value) => value,
            Err(error) => {
                out.policy_decision = "blocked".to_string();
                out.reason = format!("Invalid approval artifact JSON: {}", error);
                return Ok(out);
            }
        };
        let active_revocation_epoch = {
            let mut client = get_rpc_client(&state).await?;
            load_wallet_revocation_epoch(&mut client).await?
        };

        if let Some(expected_request_hash) = expected_request_hash {
            if let Err(error) = verify_write_approval_artifact(
                &approval,
                intent,
                expected_request_hash,
                crate::kernel::state::now(),
                active_revocation_epoch,
            ) {
                out.policy_decision = "blocked".to_string();
                out.reason = format!("Approval artifact verification failed: {}", error);
                return Ok(out);
            }
        }

        out.approved = true;
    }

    // Read-only policy path: route natural language intent to connector-first tx operations.
    match intent {
        MailIntentKind::ReadLatest => {
            let read = execute_wallet_mail_read_latest(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason = "Policy allows read-only mail access for this session lease.".to_string();
            out.executed = true;
            out.operation = Some("mail_read_latest@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.read_latest = Some(read);
        }
        MailIntentKind::ListRecent => {
            let list = execute_wallet_mail_list_recent(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
                list_limit,
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason = "Policy allows read-only mail access for this session lease.".to_string();
            out.executed = true;
            out.operation = Some("mail_list_recent@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.list_recent = Some(list);
        }
        MailIntentKind::DeleteSpam => {
            let delete = execute_wallet_mail_delete_spam(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
                None,
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason =
                "Approved write intent; executing bounded spam-deletion connector op.".to_string();
            out.executed = true;
            out.operation = Some("mail_delete_spam@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.delete_spam = Some(delete);
        }
        MailIntentKind::Reply => {
            let recipient = extract_reply_target(&trimmed_query);
            let to = if recipient.contains('@') {
                recipient
            } else {
                format!("{}@example.com", recipient.to_ascii_lowercase())
            };
            let subject = "Quick follow-up".to_string();
            let body =
                "Autopilot draft reply placeholder. Replace with final assistant-composed content."
                    .to_string();
            let reply = execute_wallet_mail_reply(
                &state,
                &channel_id,
                &lease_id,
                op_seq,
                Some(mailbox_value),
                to,
                subject,
                body,
                None,
            )
            .await?;
            out.policy_decision = "allowed".to_string();
            out.reason = "Approved write intent; executing bounded reply connector op.".to_string();
            out.executed = true;
            out.operation = Some("mail_reply@v1".to_string());
            out.next_op_seq = op_seq.saturating_add(1);
            out.reply = Some(reply);
        }
        MailIntentKind::Unknown => {
            out.reason = "Intent classification reached unsupported state.".to_string();
        }
    }

    Ok(out)
}
