use super::constants::{MAIL_PREVIEW_MAX_LEN, MAIL_SUBJECT_MAX_LEN};
use super::imap_ops::{
    authenticate_imap_session, build_tls_connector, delete_spam_from_imap_session,
    list_recent_from_imap_session, mailbox_total_count_from_mailbox, open_plain_imap_client,
    read_latest_from_imap_session, smtp_auth_secret,
};
use super::mailbox::{
    cleanup_scope_from_mailbox, cleanup_scope_label, is_primary_mailbox_name, is_spam_mailbox_name,
    normalize_remote_mailbox_name, CleanupMailboxScope,
};
use super::model::{
    MailProviderClient, MailProviderCredentials, MailProviderDeleteSpamOutcome,
    MailProviderListOutcome, MailProviderMailboxTotalCountOutcome, MailProviderMessage,
};
use super::util::{bound_text, deterministic_mock_id};
use crate::wallet_network::mail_ontology::{
    parse_volume_band, MAIL_ONTOLOGY_SIGNAL_VERSION, SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorProvider, MailConnectorTlsMode,
    MailboxTotalCountProvenance,
};
use ioi_types::error::TransactionError;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{Message, SmtpTransport, Transport};

pub(crate) struct ImapSmtpMailProviderClient;

pub(crate) fn mail_provider_for_config(
    config: &MailConnectorConfig,
) -> Result<Box<dyn MailProviderClient>, TransactionError> {
    match config.provider {
        MailConnectorProvider::ImapSmtp => {
            if is_mock_provider(config) {
                Ok(Box::new(MockMailProviderClient))
            } else {
                Ok(Box::new(ImapSmtpMailProviderClient))
            }
        }
    }
}

impl MailProviderClient for ImapSmtpMailProviderClient {
    fn read_latest(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        now_ms: u64,
    ) -> Result<MailProviderMessage, TransactionError> {
        let remote_mailbox = normalize_remote_mailbox_name(mailbox);
        match config.imap.tls_mode {
            MailConnectorTlsMode::Tls => {
                let tls = build_tls_connector()?;
                let client = imap::connect(
                    (config.imap.host.as_str(), config.imap.port),
                    &config.imap.host,
                    &tls,
                )
                .map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap tls connect failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = read_latest_from_imap_session(&mut session, &remote_mailbox, now_ms);
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::StartTls => {
                let client = open_plain_imap_client(&config.imap)?;
                let tls = build_tls_connector()?;
                let client = client.secure(&config.imap.host, &tls).map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap starttls secure failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = read_latest_from_imap_session(&mut session, &remote_mailbox, now_ms);
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::Plaintext => {
                let client = open_plain_imap_client(&config.imap)?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = read_latest_from_imap_session(&mut session, &remote_mailbox, now_ms);
                let _ = session.logout();
                out
            }
        }
    }

    fn list_recent(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        limit: usize,
        now_ms: u64,
    ) -> Result<MailProviderListOutcome, TransactionError> {
        let remote_mailbox = normalize_remote_mailbox_name(mailbox);
        match config.imap.tls_mode {
            MailConnectorTlsMode::Tls => {
                let tls = build_tls_connector()?;
                let client = imap::connect(
                    (config.imap.host.as_str(), config.imap.port),
                    &config.imap.host,
                    &tls,
                )
                .map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap tls connect failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out =
                    list_recent_from_imap_session(&mut session, &remote_mailbox, limit, now_ms);
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::StartTls => {
                let client = open_plain_imap_client(&config.imap)?;
                let tls = build_tls_connector()?;
                let client = client.secure(&config.imap.host, &tls).map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap starttls secure failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out =
                    list_recent_from_imap_session(&mut session, &remote_mailbox, limit, now_ms);
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::Plaintext => {
                let client = open_plain_imap_client(&config.imap)?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out =
                    list_recent_from_imap_session(&mut session, &remote_mailbox, limit, now_ms);
                let _ = session.logout();
                out
            }
        }
    }

    fn mailbox_total_count(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
    ) -> Result<MailProviderMailboxTotalCountOutcome, TransactionError> {
        let remote_mailbox = normalize_remote_mailbox_name(mailbox);
        match config.imap.tls_mode {
            MailConnectorTlsMode::Tls => {
                let tls = build_tls_connector()?;
                let client = imap::connect(
                    (config.imap.host.as_str(), config.imap.port),
                    &config.imap.host,
                    &tls,
                )
                .map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap tls connect failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = mailbox_total_count_from_mailbox(&mut session, &remote_mailbox);
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::StartTls => {
                let client = open_plain_imap_client(&config.imap)?;
                let tls = build_tls_connector()?;
                let client = client.secure(&config.imap.host, &tls).map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap starttls secure failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = mailbox_total_count_from_mailbox(&mut session, &remote_mailbox);
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::Plaintext => {
                let client = open_plain_imap_client(&config.imap)?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = mailbox_total_count_from_mailbox(&mut session, &remote_mailbox);
                let _ = session.logout();
                out
            }
        }
    }

    fn send_reply(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<String, TransactionError> {
        let from_mailbox: Mailbox = config.account_email.parse().map_err(|e| {
            TransactionError::Invalid(format!("smtp from address is invalid: {}", e))
        })?;
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| TransactionError::Invalid(format!("smtp to address is invalid: {}", e)))?;
        let message = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| TransactionError::Invalid(format!("smtp message build failed: {}", e)))?;

        let smtp_builder = match config.smtp.tls_mode {
            MailConnectorTlsMode::Plaintext => SmtpTransport::builder_dangerous(&config.smtp.host),
            MailConnectorTlsMode::StartTls => SmtpTransport::starttls_relay(&config.smtp.host)
                .map_err(|e| {
                    TransactionError::Invalid(format!("smtp starttls relay init failed: {}", e))
                })?,
            MailConnectorTlsMode::Tls => SmtpTransport::relay(&config.smtp.host).map_err(|e| {
                TransactionError::Invalid(format!("smtp tls relay init failed: {}", e))
            })?,
        };
        let mut smtp_builder = smtp_builder
            .port(config.smtp.port)
            .credentials(Credentials::new(
                credentials.smtp_username.clone(),
                smtp_auth_secret(credentials).to_string(),
            ));
        if credentials.auth_mode == MailConnectorAuthMode::Oauth2 {
            smtp_builder = smtp_builder.authentication(vec![Mechanism::Xoauth2]);
        }
        let smtp_transport = smtp_builder.build();

        let response = smtp_transport.send(&message).map_err(|e| {
            TransactionError::Invalid(format!("smtp send failed for '{}': {}", to, e))
        })?;
        let sent_id = response
            .first_word()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| "smtp-ack".to_string());
        Ok(bound_text(&sent_id, 128))
    }

    fn delete_spam(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        max_delete: u32,
    ) -> Result<MailProviderDeleteSpamOutcome, TransactionError> {
        if !is_spam_mailbox_name(mailbox) && !is_primary_mailbox_name(mailbox) {
            return Err(TransactionError::Invalid(format!(
                "mailbox '{}' is not an allowed cleanup target (expected primary/inbox or spam/junk)",
                mailbox
            )));
        }
        let remote_mailbox = normalize_remote_mailbox_name(mailbox);
        let cleanup_scope = cleanup_scope_from_mailbox(mailbox);
        let classification_mailbox = match cleanup_scope {
            CleanupMailboxScope::SpamMailbox => "spam",
            CleanupMailboxScope::PrimaryInbox => "primary",
        };

        match config.imap.tls_mode {
            MailConnectorTlsMode::Tls => {
                let tls = build_tls_connector()?;
                let client = imap::connect(
                    (config.imap.host.as_str(), config.imap.port),
                    &config.imap.host,
                    &tls,
                )
                .map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap tls connect failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = delete_spam_from_imap_session(
                    &mut session,
                    &remote_mailbox,
                    max_delete,
                    cleanup_scope,
                    classification_mailbox,
                );
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::StartTls => {
                let client = open_plain_imap_client(&config.imap)?;
                let tls = build_tls_connector()?;
                let client = client.secure(&config.imap.host, &tls).map_err(|e| {
                    TransactionError::Invalid(format!(
                        "imap starttls secure failed for '{}:{}': {}",
                        config.imap.host, config.imap.port, e
                    ))
                })?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = delete_spam_from_imap_session(
                    &mut session,
                    &remote_mailbox,
                    max_delete,
                    cleanup_scope,
                    classification_mailbox,
                );
                let _ = session.logout();
                out
            }
            MailConnectorTlsMode::Plaintext => {
                let client = open_plain_imap_client(&config.imap)?;
                let mut session = authenticate_imap_session(client, credentials)?;
                let out = delete_spam_from_imap_session(
                    &mut session,
                    &remote_mailbox,
                    max_delete,
                    cleanup_scope,
                    classification_mailbox,
                );
                let _ = session.logout();
                out
            }
        }
    }
}

struct MockMailProviderClient;

impl MailProviderClient for MockMailProviderClient {
    fn read_latest(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        now_ms: u64,
    ) -> Result<MailProviderMessage, TransactionError> {
        let message_id = deterministic_mock_id(&[
            b"mock_read_latest".as_slice(),
            mailbox.as_bytes(),
            config.account_email.as_bytes(),
            credentials.imap_username.as_bytes(),
        ])?;
        Ok(MailProviderMessage {
            message_id,
            from: format!("mock@{}", config.imap.host),
            subject: bound_text(
                &format!("Mock latest message for {}", mailbox),
                MAIL_SUBJECT_MAX_LEN,
            ),
            received_at_ms: now_ms.saturating_sub(60_000),
            preview: bound_text(
                &format!("Mock IMAP read for mailbox '{}'.", mailbox),
                MAIL_PREVIEW_MAX_LEN,
            ),
        })
    }

    fn list_recent(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        limit: usize,
        now_ms: u64,
    ) -> Result<MailProviderListOutcome, TransactionError> {
        let mut out = Vec::with_capacity(limit);
        for idx in 0..limit {
            let message_id = deterministic_mock_id(&[
                b"mock_list_recent".as_slice(),
                mailbox.as_bytes(),
                config.account_email.as_bytes(),
                credentials.imap_username.as_bytes(),
                &(idx as u64).to_be_bytes(),
            ])?;
            out.push(MailProviderMessage {
                message_id,
                from: format!("mock+{}@{}", idx + 1, config.imap.host),
                subject: bound_text(
                    &format!("Mock recent message #{} for {}", idx + 1, mailbox),
                    MAIL_SUBJECT_MAX_LEN,
                ),
                received_at_ms: now_ms.saturating_sub((idx as u64 + 1) * 60_000),
                preview: bound_text(
                    &format!("Mock IMAP list item {} for mailbox '{}'.", idx + 1, mailbox),
                    MAIL_PREVIEW_MAX_LEN,
                ),
            });
        }
        Ok(MailProviderListOutcome {
            messages: out,
            requested_limit: limit,
            evaluated_count: limit,
            parse_error_count: 0,
            parse_confidence_bps: 10_000,
            parse_volume_band: parse_volume_band(limit).to_string(),
            mailbox_total_count: u32::try_from(limit).unwrap_or(u32::MAX),
        })
    }

    fn mailbox_total_count(
        &self,
        _config: &MailConnectorConfig,
        _credentials: &MailProviderCredentials,
        mailbox: &str,
    ) -> Result<MailProviderMailboxTotalCountOutcome, TransactionError> {
        let mailbox_total_count = if is_primary_mailbox_name(mailbox) {
            10_000
        } else if is_spam_mailbox_name(mailbox) {
            2_000
        } else {
            500
        };
        Ok(MailProviderMailboxTotalCountOutcome {
            mailbox_total_count,
            provenance: MailboxTotalCountProvenance {
                status_exists: Some(mailbox_total_count),
                select_exists: None,
                uid_search_count: None,
                search_count: None,
                freshness_marker: "mock_fixed_count".to_string(),
            },
        })
    }

    fn send_reply(
        &self,
        _config: &MailConnectorConfig,
        _credentials: &MailProviderCredentials,
        to: &str,
        subject: &str,
        _body: &str,
    ) -> Result<String, TransactionError> {
        deterministic_mock_id(&[
            b"mock_send_reply".as_slice(),
            to.as_bytes(),
            subject.as_bytes(),
        ])
    }

    fn delete_spam(
        &self,
        _config: &MailConnectorConfig,
        _credentials: &MailProviderCredentials,
        mailbox: &str,
        max_delete: u32,
    ) -> Result<MailProviderDeleteSpamOutcome, TransactionError> {
        if !is_spam_mailbox_name(mailbox) && !is_primary_mailbox_name(mailbox) {
            return Err(TransactionError::Invalid(format!(
                "mailbox '{}' is not an allowed cleanup target (expected primary/inbox or spam/junk)",
                mailbox
            )));
        }
        let cleanup_scope = cleanup_scope_from_mailbox(mailbox);
        if cleanup_scope == CleanupMailboxScope::SpamMailbox {
            let mailbox_total_count_before = max_delete.saturating_add(80);
            let mailbox_total_count_after = mailbox_total_count_before.saturating_sub(max_delete);
            return Ok(MailProviderDeleteSpamOutcome {
                evaluated_count: max_delete,
                deleted_count: max_delete,
                skipped_low_confidence_count: 0,
                high_confidence_deleted_count: max_delete,
                mailbox_total_count_before,
                mailbox_total_count_after,
                mailbox_total_count_delta: mailbox_total_count_before
                    .saturating_sub(mailbox_total_count_after),
                spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
                ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
                cleanup_scope: cleanup_scope_label(cleanup_scope).to_string(),
                preserved_transactional_or_personal_count: 0,
                preserved_trusted_system_count: 0,
                preserved_low_confidence_other_count: 0,
                preserved_due_to_delete_cap_count: 0,
            });
        }
        let deleted_count = max_delete.min(4);
        let evaluated_count = deleted_count.saturating_add(12);
        let skipped_low_confidence_count = evaluated_count.saturating_sub(deleted_count);
        let preserved_transactional_or_personal_count = skipped_low_confidence_count / 2;
        let preserved_trusted_system_count = skipped_low_confidence_count / 5;
        let preserved_low_confidence_other_count = skipped_low_confidence_count
            .saturating_sub(preserved_transactional_or_personal_count)
            .saturating_sub(preserved_trusted_system_count);
        let mailbox_total_count_before = evaluated_count.saturating_add(50);
        let mailbox_total_count_after = mailbox_total_count_before.saturating_sub(deleted_count);
        Ok(MailProviderDeleteSpamOutcome {
            evaluated_count,
            deleted_count,
            skipped_low_confidence_count,
            high_confidence_deleted_count: deleted_count,
            mailbox_total_count_before,
            mailbox_total_count_after,
            mailbox_total_count_delta: mailbox_total_count_before
                .saturating_sub(mailbox_total_count_after),
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label(cleanup_scope).to_string(),
            preserved_transactional_or_personal_count,
            preserved_trusted_system_count,
            preserved_low_confidence_other_count,
            preserved_due_to_delete_cap_count: 0,
        })
    }
}

fn is_mock_provider(config: &MailConnectorConfig) -> bool {
    config
        .metadata
        .get("driver")
        .map(|value| value.trim().eq_ignore_ascii_case("mock"))
        .unwrap_or(false)
}
