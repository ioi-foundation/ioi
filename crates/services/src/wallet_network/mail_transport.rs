// Path: crates/services/src/wallet_network/mail_transport.rs

use crate::wallet_network::mail_ontology::{
    classify_mail_spam, estimate_parse_confidence_bps, is_high_confidence_spam, parse_volume_band,
    MailSpamClassification, MAIL_ONTOLOGY_SIGNAL_VERSION, SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use crate::wallet_network::support::hash_bytes;
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
    MailConnectorTlsMode, MailboxTotalCountProvenance,
};
use ioi_types::error::TransactionError;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{Message, SmtpTransport, Transport};
use native_tls::TlsConnector;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MAIL_SUBJECT_MAX_LEN: usize = 256;
const MAIL_FROM_MAX_LEN: usize = 256;
const MAIL_PREVIEW_MAX_LEN: usize = 512;
const IMAP_FETCH_ATTRS_TEXT: &str = "(UID ENVELOPE INTERNALDATE BODY.PEEK[TEXT])";
const IMAP_FETCH_ATTRS_FULL_BODY: &str = "(UID ENVELOPE INTERNALDATE BODY.PEEK[])";
const IMAP_FETCH_ATTRS_META_ONLY: &str = "(UID ENVELOPE INTERNALDATE)";
const IMAP_LIST_FETCH_BATCH_SIZE: usize = 48;
const MAIL_DELETE_SPAM_EVALUATION_MULTIPLIER: usize = 3;
const MAIL_DELETE_SPAM_MAX_EVALUATED: usize = 900;
const PRIMARY_UNWANTED_PROMOTION_MIN_SCORE_BPS: u16 = 5_000;
const PRIMARY_UNWANTED_PROMOTION_MIN_RISK_TAGS: usize = 2;
const PRIMARY_UNWANTED_BULK_PROMOTION_MIN_RATIO_BPS: u32 = 8_500;
const PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_MIN_RATIO_BPS: u32 = 7_000;
const PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_SCORE_DELTA_BPS: u16 = 1_500;
const MAILBOX_COUNT_FRESHNESS_STATUS_FRESH: &str = "status_exists_fresh";
const MAILBOX_COUNT_FRESHNESS_STATUS_RECONCILED: &str = "status_exists_reconciled";
const MAILBOX_COUNT_FRESHNESS_FALLBACK_NO_STATUS: &str = "fallback_no_status";
const MAILBOX_COUNT_FRESHNESS_FALLBACK_STATUS_ZERO: &str = "fallback_status_zero";
const SPAM_REMOTE_MAILBOX_CANDIDATES: [&str; 12] = [
    "Spam",
    "Junk",
    "Junk Email",
    "Junk E-mail",
    "Bulk",
    "Bulk Mail",
    "INBOX.Spam",
    "INBOX.Junk",
    "[Gmail]/Spam",
    "[Google Mail]/Spam",
    "JunkE-mail",
    "JunkE-Mail",
];

#[derive(Debug, Clone)]
pub(crate) struct MailProviderCredentials {
    pub auth_mode: MailConnectorAuthMode,
    pub imap_username: String,
    pub imap_secret: String,
    pub smtp_username: String,
    pub smtp_secret: String,
}

#[derive(Debug, Clone)]
pub(crate) struct MailProviderMessage {
    pub message_id: String,
    pub from: String,
    pub subject: String,
    pub received_at_ms: u64,
    pub preview: String,
}

#[derive(Debug, Clone)]
pub(crate) struct MailProviderListOutcome {
    pub messages: Vec<MailProviderMessage>,
    pub requested_limit: usize,
    pub evaluated_count: usize,
    pub parse_error_count: usize,
    pub parse_confidence_bps: u16,
    pub parse_volume_band: String,
    pub mailbox_total_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct MailProviderDeleteSpamOutcome {
    pub evaluated_count: u32,
    pub deleted_count: u32,
    pub skipped_low_confidence_count: u32,
    pub high_confidence_deleted_count: u32,
    pub mailbox_total_count_before: u32,
    pub mailbox_total_count_after: u32,
    pub mailbox_total_count_delta: u32,
    pub spam_confidence_threshold_bps: u16,
    pub ontology_version: String,
    pub cleanup_scope: String,
    pub preserved_transactional_or_personal_count: u32,
    pub preserved_trusted_system_count: u32,
    pub preserved_low_confidence_other_count: u32,
    pub preserved_due_to_delete_cap_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct MailProviderMailboxTotalCountOutcome {
    pub mailbox_total_count: u32,
    pub provenance: MailboxTotalCountProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupMailboxScope {
    SpamMailbox,
    PrimaryInbox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreservationBucket {
    TransactionalOrPersonal,
    TrustedSystemSender,
    LowConfidenceOther,
}

pub(crate) trait MailProviderClient {
    fn read_latest(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        now_ms: u64,
    ) -> Result<MailProviderMessage, TransactionError>;

    fn list_recent(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        limit: usize,
        now_ms: u64,
    ) -> Result<MailProviderListOutcome, TransactionError>;

    fn mailbox_total_count(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
    ) -> Result<MailProviderMailboxTotalCountOutcome, TransactionError>;

    fn delete_spam(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        mailbox: &str,
        max_delete: u32,
    ) -> Result<MailProviderDeleteSpamOutcome, TransactionError>;

    fn send_reply(
        &self,
        config: &MailConnectorConfig,
        credentials: &MailProviderCredentials,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<String, TransactionError>;
}

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

fn normalize_remote_mailbox_name(mailbox: &str) -> String {
    if mailbox.eq_ignore_ascii_case("primary") {
        return "INBOX".to_string();
    }
    if mailbox.eq_ignore_ascii_case("spam") {
        return "Spam".to_string();
    }
    if mailbox.eq_ignore_ascii_case("junk") || mailbox.eq_ignore_ascii_case("junkemail") {
        return "Junk".to_string();
    }
    if mailbox.eq_ignore_ascii_case("bulk") {
        return "Bulk".to_string();
    }
    if mailbox.eq_ignore_ascii_case("trash") {
        return "Trash".to_string();
    }
    mailbox.to_string()
}

fn is_spam_mailbox_name(mailbox: &str) -> bool {
    mailbox.eq_ignore_ascii_case("spam")
        || mailbox.eq_ignore_ascii_case("junk")
        || mailbox.eq_ignore_ascii_case("junkemail")
        || mailbox.eq_ignore_ascii_case("bulk")
        || mailbox.eq_ignore_ascii_case("trash")
}

fn is_primary_mailbox_name(mailbox: &str) -> bool {
    mailbox.eq_ignore_ascii_case("primary") || mailbox.eq_ignore_ascii_case("inbox")
}

fn cleanup_scope_from_mailbox(mailbox: &str) -> CleanupMailboxScope {
    if is_primary_mailbox_name(mailbox) {
        CleanupMailboxScope::PrimaryInbox
    } else {
        CleanupMailboxScope::SpamMailbox
    }
}

fn cleanup_scope_label(scope: CleanupMailboxScope) -> &'static str {
    match scope {
        CleanupMailboxScope::SpamMailbox => "spam_mailbox",
        CleanupMailboxScope::PrimaryInbox => "primary_inbox",
    }
}

fn preservation_bucket_from_signal_tags(signal_tags: &[String]) -> PreservationBucket {
    let has_transactional_or_personal = signal_tags.iter().any(|tag| {
        tag.starts_with("signal_transactional_")
            || tag == "signal_safe_thread_markers"
            || tag == "signal_safe_personal_markers"
            || tag == "signal_preservation_override"
    });
    if has_transactional_or_personal {
        return PreservationBucket::TransactionalOrPersonal;
    }
    if signal_tags
        .iter()
        .any(|tag| tag == "signal_trusted_system_sender")
    {
        return PreservationBucket::TrustedSystemSender;
    }
    PreservationBucket::LowConfidenceOther
}

fn is_transactional_or_personal_signal(tag: &str) -> bool {
    tag.starts_with("signal_transactional_")
        || tag == "signal_safe_thread_markers"
        || tag == "signal_safe_personal_markers"
        || tag == "signal_preservation_override"
}

fn is_trusted_system_signal(tag: &str) -> bool {
    tag == "signal_trusted_system_sender"
}

fn is_primary_unwanted_risk_signal(tag: &str) -> bool {
    matches!(
        tag,
        "signal_sender_risk_markers"
            | "signal_subject_risk_markers"
            | "signal_content_risk_markers"
            | "signal_sender_marketing_markers"
            | "signal_subject_marketing_markers"
            | "signal_content_marketing_markers"
            | "signal_bulk_distribution_footer"
            | "signal_marketing_footer_pattern"
            | "signal_percentage_discount_pattern"
            | "signal_marketing_bulk_composite"
            | "signal_list_header_bulk_pattern"
            | "signal_primary_unwanted_context_floor"
            | "signal_urgency_punctuation"
            | "signal_uppercase_urgency"
    )
}

fn is_primary_unwanted_structural_signal(tag: &str) -> bool {
    matches!(
        tag,
        "signal_sender_marketing_markers"
            | "signal_subject_marketing_markers"
            | "signal_content_marketing_markers"
            | "signal_bulk_distribution_footer"
            | "signal_marketing_footer_pattern"
            | "signal_percentage_discount_pattern"
            | "signal_marketing_bulk_composite"
            | "signal_list_header_bulk_pattern"
            | "signal_primary_unwanted_context_floor"
    )
}

fn is_primary_unwanted_promotion_candidate(classification: &MailSpamClassification) -> bool {
    if classification.confidence_bps < PRIMARY_UNWANTED_PROMOTION_MIN_SCORE_BPS {
        return false;
    }

    let mut risk_tag_count = 0usize;
    let mut structural_signal = false;
    let mut preserve_signal = false;
    for tag in &classification.signal_tags {
        if is_primary_unwanted_risk_signal(tag) {
            risk_tag_count = risk_tag_count.saturating_add(1);
        }
        if is_primary_unwanted_structural_signal(tag) {
            structural_signal = true;
        }
        if is_transactional_or_personal_signal(tag) || is_trusted_system_signal(tag) {
            preserve_signal = true;
        }
    }

    !preserve_signal
        && structural_signal
        && risk_tag_count >= PRIMARY_UNWANTED_PROMOTION_MIN_RISK_TAGS
}

fn canonical_mailbox_name(mailbox: &str) -> String {
    mailbox
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn is_spam_like_remote_mailbox(mailbox: &str) -> bool {
    let canonical = canonical_mailbox_name(mailbox);
    canonical.contains("spam")
        || canonical.contains("junk")
        || canonical.contains("bulk")
        || canonical.contains("trash")
}

fn select_remote_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
) -> Result<u32, TransactionError> {
    let selected = session.select(mailbox).map_err(|e| {
        TransactionError::Invalid(format!("imap select '{}' failed: {}", mailbox, e))
    })?;
    Ok(selected.exists)
}

fn resolve_remote_spam_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    requested_mailbox: &str,
) -> Result<(String, u32), TransactionError> {
    if let Ok(total_count) = select_remote_mailbox(session, requested_mailbox) {
        return Ok((requested_mailbox.to_string(), total_count));
    }

    let requested_canonical = canonical_mailbox_name(requested_mailbox);
    let mut discovered = Vec::new();
    if let Ok(names) = session.list(None, Some("*")) {
        for name in names.iter() {
            let candidate = name.name().trim();
            if !candidate.is_empty() {
                discovered.push(candidate.to_string());
            }
        }
    }

    for candidate in discovered.iter() {
        if canonical_mailbox_name(candidate) == requested_canonical {
            if let Ok(total_count) = select_remote_mailbox(session, candidate) {
                return Ok((candidate.clone(), total_count));
            }
        }
    }

    for candidate in discovered.iter() {
        if is_spam_like_remote_mailbox(candidate) {
            if let Ok(total_count) = select_remote_mailbox(session, candidate) {
                return Ok((candidate.clone(), total_count));
            }
        }
    }

    for candidate in SPAM_REMOTE_MAILBOX_CANDIDATES.iter() {
        if let Ok(total_count) = select_remote_mailbox(session, candidate) {
            return Ok(((*candidate).to_string(), total_count));
        }
    }

    let mut known_targets: Vec<String> = discovered
        .into_iter()
        .filter(|name| is_spam_like_remote_mailbox(name))
        .collect();
    known_targets.sort();
    known_targets.dedup();
    let known = if known_targets.is_empty() {
        "none discovered".to_string()
    } else {
        known_targets.join(", ")
    };
    Err(TransactionError::Invalid(format!(
        "imap select '{}' failed and no spam/junk mailbox alias resolved; discovered candidates: {}",
        requested_mailbox, known
    )))
}

fn resolve_remote_primary_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    requested_mailbox: &str,
) -> Result<(String, u32), TransactionError> {
    if let Ok(total_count) = select_remote_mailbox(session, requested_mailbox) {
        return Ok((requested_mailbox.to_string(), total_count));
    }
    for candidate in ["INBOX", "Inbox", "inbox"] {
        if let Ok(total_count) = select_remote_mailbox(session, candidate) {
            return Ok((candidate.to_string(), total_count));
        }
    }
    Err(TransactionError::Invalid(format!(
        "imap select '{}' failed and no primary inbox alias resolved",
        requested_mailbox
    )))
}

fn open_plain_imap_client(
    endpoint: &MailConnectorEndpoint,
) -> Result<imap::Client<TcpStream>, TransactionError> {
    let stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).map_err(|e| {
        TransactionError::Invalid(format!(
            "imap plaintext connect failed for '{}:{}': {}",
            endpoint.host, endpoint.port, e
        ))
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));
    let mut client = imap::Client::new(stream);
    client.read_greeting().map_err(|e| {
        TransactionError::Invalid(format!(
            "imap greeting read failed for '{}:{}': {}",
            endpoint.host, endpoint.port, e
        ))
    })?;
    Ok(client)
}

fn build_tls_connector() -> Result<TlsConnector, TransactionError> {
    TlsConnector::builder()
        .build()
        .map_err(|e| TransactionError::Invalid(format!("imap tls builder failed: {}", e)))
}

fn imap_auth_secret(credentials: &MailProviderCredentials) -> &str {
    match credentials.auth_mode {
        MailConnectorAuthMode::Password | MailConnectorAuthMode::Oauth2 => {
            credentials.imap_secret.as_str()
        }
    }
}

fn smtp_auth_secret(credentials: &MailProviderCredentials) -> &str {
    match credentials.auth_mode {
        MailConnectorAuthMode::Password | MailConnectorAuthMode::Oauth2 => {
            credentials.smtp_secret.as_str()
        }
    }
}

struct ImapXoauth2Authenticator<'a> {
    username: &'a str,
    access_token: &'a str,
}

impl imap::Authenticator for ImapXoauth2Authenticator<'_> {
    type Response = String;

    fn process(&self, _challenge: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.username, self.access_token
        )
    }
}

struct ImapPlainAuthenticator<'a> {
    username: &'a str,
    password: &'a str,
}

impl imap::Authenticator for ImapPlainAuthenticator<'_> {
    type Response = String;

    fn process(&self, _challenge: &[u8]) -> Self::Response {
        format!("\x00{}\x00{}", self.username, self.password)
    }
}

fn authenticate_imap_session<T: Read + Write>(
    client: imap::Client<T>,
    credentials: &MailProviderCredentials,
) -> Result<imap::Session<T>, TransactionError> {
    match credentials.auth_mode {
        MailConnectorAuthMode::Password => {
            match client.login(&credentials.imap_username, imap_auth_secret(credentials)) {
                Ok(session) => Ok(session),
                Err((login_err, client)) => {
                    let authenticator = ImapPlainAuthenticator {
                        username: &credentials.imap_username,
                        password: imap_auth_secret(credentials),
                    };
                    client
                        .authenticate("PLAIN", &authenticator)
                        .map_err(|(plain_err, _)| {
                            TransactionError::Invalid(format!(
                                "imap password auth failed for '{}': login={} plain={}",
                                credentials.imap_username, login_err, plain_err
                            ))
                        })
                }
            }
        }
        MailConnectorAuthMode::Oauth2 => {
            let authenticator = ImapXoauth2Authenticator {
                username: &credentials.imap_username,
                access_token: imap_auth_secret(credentials),
            };
            client
                .authenticate("XOAUTH2", &authenticator)
                .map_err(|(e, _)| {
                    TransactionError::Invalid(format!(
                        "imap xoauth2 authenticate failed for '{}': {}",
                        credentials.imap_username, e
                    ))
                })
        }
    }
}

fn read_latest_from_imap_session<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
    now_ms: u64,
) -> Result<MailProviderMessage, TransactionError> {
    let _ = select_remote_mailbox(session, mailbox)?;

    let mut sequence_ids: Vec<u32> = session
        .search("ALL")
        .map_err(|e| TransactionError::Invalid(format!("imap search failed: {}", e)))?
        .into_iter()
        .collect();
    if sequence_ids.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mailbox '{}' has no messages",
            mailbox
        )));
    }
    sequence_ids.sort_unstable();
    let latest_seq = sequence_ids[sequence_ids.len() - 1];
    let sequence = latest_seq.to_string();

    let fetches = session
        .fetch(sequence.clone(), IMAP_FETCH_ATTRS_TEXT)
        .or_else(|_| session.fetch(sequence.clone(), IMAP_FETCH_ATTRS_FULL_BODY))
        .or_else(|_| session.fetch(sequence, IMAP_FETCH_ATTRS_META_ONLY))
        .map_err(|e| TransactionError::Invalid(format!("imap fetch failed: {}", e)))?;
    let fetch = fetches
        .iter()
        .next()
        .ok_or_else(|| TransactionError::Invalid("imap returned empty fetch result".to_string()))?;
    mail_provider_message_from_fetch(fetch, now_ms)
}

fn list_recent_from_imap_session<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
    limit: usize,
    now_ms: u64,
) -> Result<MailProviderListOutcome, TransactionError> {
    let _ = select_remote_mailbox(session, mailbox)?;

    let mut sequence_ids: Vec<u32> = session
        .search("ALL")
        .map_err(|e| TransactionError::Invalid(format!("imap search failed: {}", e)))?
        .into_iter()
        .collect();
    let mailbox_total_count = mailbox_total_count_from_mailbox(session, mailbox)
        .map(|outcome| outcome.mailbox_total_count)
        .unwrap_or_else(|_| u32::try_from(sequence_ids.len()).unwrap_or(u32::MAX));
    sequence_ids.sort_unstable_by(|a, b| b.cmp(a));
    sequence_ids.truncate(limit);
    if sequence_ids.is_empty() {
        return Ok(MailProviderListOutcome {
            messages: Vec::new(),
            requested_limit: limit,
            evaluated_count: 0,
            parse_error_count: 0,
            parse_confidence_bps: 10_000,
            parse_volume_band: parse_volume_band(0).to_string(),
            mailbox_total_count,
        });
    }

    let evaluated_count = sequence_ids.len();
    let mut parse_error_count = 0usize;
    let mut out = Vec::new();
    for chunk in sequence_ids.chunks(IMAP_LIST_FETCH_BATCH_SIZE) {
        let sequence_set = chunk
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fetches = session
            .fetch(sequence_set.clone(), IMAP_FETCH_ATTRS_TEXT)
            .or_else(|_| session.fetch(sequence_set.clone(), IMAP_FETCH_ATTRS_FULL_BODY))
            .or_else(|_| session.fetch(sequence_set, IMAP_FETCH_ATTRS_META_ONLY));
        match fetches {
            Ok(fetches) => {
                for fetch in fetches.iter() {
                    match mail_provider_message_from_fetch(fetch, now_ms) {
                        Ok(message) => out.push(message),
                        Err(_) => parse_error_count = parse_error_count.saturating_add(1),
                    }
                }
            }
            Err(_) => {
                parse_error_count = parse_error_count.saturating_add(chunk.len());
            }
        }
    }
    out.sort_by(|a, b| {
        b.received_at_ms
            .cmp(&a.received_at_ms)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    if out.len() > limit {
        out.truncate(limit);
    }
    let parsed_count = out.len();
    let parse_confidence_bps =
        estimate_parse_confidence_bps(limit, evaluated_count, parsed_count, parse_error_count);
    let parse_volume_band_value = parse_volume_band(parsed_count).to_string();
    Ok(MailProviderListOutcome {
        messages: out,
        requested_limit: limit,
        evaluated_count,
        parse_error_count,
        parse_confidence_bps,
        parse_volume_band: parse_volume_band_value,
        mailbox_total_count,
    })
}

fn mailbox_total_count_from_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
) -> Result<MailProviderMailboxTotalCountOutcome, TransactionError> {
    let status_exists = session
        .status(mailbox, "(MESSAGES)")
        .ok()
        .map(|status| status.exists);
    if let Some(exists) = status_exists {
        if exists > 0 {
            return Ok(MailProviderMailboxTotalCountOutcome {
                mailbox_total_count: exists,
                provenance: MailboxTotalCountProvenance {
                    status_exists: Some(exists),
                    select_exists: None,
                    uid_search_count: None,
                    search_count: None,
                    freshness_marker: MAILBOX_COUNT_FRESHNESS_STATUS_FRESH.to_string(),
                },
            });
        }
    }

    let selected_exists = select_remote_mailbox(session, mailbox)?;
    let uid_count_result = session.uid_search("ALL");
    let seq_count_result = session.search("ALL");
    if let (Err(uid_err), Err(seq_err)) = (&uid_count_result, &seq_count_result) {
        return Err(TransactionError::Invalid(format!(
            "imap uid search failed: {}; imap search failed: {}",
            uid_err, seq_err
        )));
    }
    let uid_search_count = uid_count_result
        .ok()
        .and_then(|uids| u32::try_from(uids.len()).ok())
        .unwrap_or(0);
    let search_count = seq_count_result
        .ok()
        .and_then(|seqs| u32::try_from(seqs.len()).ok())
        .unwrap_or(0);
    let fallback_count = selected_exists.max(uid_search_count).max(search_count);
    let mailbox_total_count = status_exists
        .map(|exists| exists.max(fallback_count))
        .unwrap_or(fallback_count);
    let freshness_marker = match status_exists {
        Some(exists) if exists >= fallback_count => MAILBOX_COUNT_FRESHNESS_STATUS_FRESH,
        Some(exists) if exists == 0 => MAILBOX_COUNT_FRESHNESS_FALLBACK_STATUS_ZERO,
        Some(_) => MAILBOX_COUNT_FRESHNESS_STATUS_RECONCILED,
        None => MAILBOX_COUNT_FRESHNESS_FALLBACK_NO_STATUS,
    };
    Ok(MailProviderMailboxTotalCountOutcome {
        mailbox_total_count,
        provenance: MailboxTotalCountProvenance {
            status_exists,
            select_exists: Some(selected_exists),
            uid_search_count: Some(uid_search_count),
            search_count: Some(search_count),
            freshness_marker: freshness_marker.to_string(),
        },
    })
}

fn reconcile_mailbox_total_count_after_delete(
    mailbox_total_count_before: u32,
    deleted_count: u32,
    measured_after: Option<u32>,
) -> u32 {
    let expected_after = mailbox_total_count_before.saturating_sub(deleted_count);
    let Some(measured_after) = measured_after else {
        return expected_after;
    };
    if deleted_count > 0 && measured_after >= mailbox_total_count_before {
        return expected_after;
    }
    measured_after
        .min(mailbox_total_count_before)
        .max(expected_after)
}

fn delete_spam_from_imap_session<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
    max_delete: u32,
    cleanup_scope: CleanupMailboxScope,
    classification_mailbox: &str,
) -> Result<MailProviderDeleteSpamOutcome, TransactionError> {
    let cleanup_scope_label = cleanup_scope_label(cleanup_scope).to_string();
    if max_delete == 0 {
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: 0,
            deleted_count: 0,
            skipped_low_confidence_count: 0,
            high_confidence_deleted_count: 0,
            mailbox_total_count_before: 0,
            mailbox_total_count_after: 0,
            mailbox_total_count_delta: 0,
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count: 0,
            preserved_trusted_system_count: 0,
            preserved_low_confidence_other_count: 0,
            preserved_due_to_delete_cap_count: 0,
        });
    }
    let (selected_mailbox, selected_mailbox_total_count) = match cleanup_scope {
        CleanupMailboxScope::SpamMailbox => resolve_remote_spam_mailbox(session, mailbox)?,
        CleanupMailboxScope::PrimaryInbox => resolve_remote_primary_mailbox(session, mailbox)?,
    };
    let mailbox_total_count_before = mailbox_total_count_from_mailbox(session, &selected_mailbox)
        .map(|outcome| outcome.mailbox_total_count)
        .unwrap_or(selected_mailbox_total_count);

    let mut uids: Vec<u32> = session
        .uid_search("ALL")
        .map_err(|e| TransactionError::Invalid(format!("imap uid search failed: {}", e)))?
        .into_iter()
        .collect();
    uids.sort_unstable_by(|a, b| b.cmp(a));
    let evaluation_limit = (max_delete as usize)
        .saturating_mul(MAIL_DELETE_SPAM_EVALUATION_MULTIPLIER)
        .clamp(max_delete as usize, MAIL_DELETE_SPAM_MAX_EVALUATED);
    uids.truncate(evaluation_limit);
    if uids.is_empty() {
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: 0,
            deleted_count: 0,
            skipped_low_confidence_count: 0,
            high_confidence_deleted_count: 0,
            mailbox_total_count_before,
            mailbox_total_count_after: mailbox_total_count_before,
            mailbox_total_count_delta: 0,
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count: 0,
            preserved_trusted_system_count: 0,
            preserved_low_confidence_other_count: 0,
            preserved_due_to_delete_cap_count: 0,
        });
    }

    let evaluated_count = uids.len();
    let uid_set = uids
        .iter()
        .map(|uid| uid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let fetches = session
        .uid_fetch(uid_set.clone(), IMAP_FETCH_ATTRS_TEXT)
        .or_else(|_| session.uid_fetch(uid_set.clone(), IMAP_FETCH_ATTRS_FULL_BODY))
        .or_else(|_| session.uid_fetch(uid_set, IMAP_FETCH_ATTRS_META_ONLY))
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "imap uid fetch for spam classification failed: {}",
                e
            ))
        })?;

    let mut high_confidence_uids: Vec<(u32, u16)> = Vec::new();
    let mut promoted_primary_unwanted_uids: Vec<(u32, u16)> = Vec::new();
    let mut preserved_transactional_or_personal_count = 0u32;
    let mut preserved_trusted_system_count = 0u32;
    let mut low_confidence_other_uids: Vec<(u32, u16)> = Vec::new();
    for fetch in fetches.iter() {
        let Some(uid) = fetch.uid else {
            continue;
        };
        let Ok(message) = mail_provider_message_from_fetch(fetch, 1) else {
            continue;
        };
        let classification = classify_mail_spam(
            classification_mailbox,
            &message.from,
            &message.subject,
            &message.preview,
        );
        if is_high_confidence_spam(classification.confidence_bps) {
            high_confidence_uids.push((uid, classification.confidence_bps));
            continue;
        }
        let preservation_bucket = preservation_bucket_from_signal_tags(&classification.signal_tags);
        if cleanup_scope == CleanupMailboxScope::PrimaryInbox
            && matches!(preservation_bucket, PreservationBucket::LowConfidenceOther)
            && is_primary_unwanted_promotion_candidate(&classification)
        {
            promoted_primary_unwanted_uids.push((uid, classification.confidence_bps));
        }
        match preservation_bucket {
            PreservationBucket::TransactionalOrPersonal => {
                preserved_transactional_or_personal_count =
                    preserved_transactional_or_personal_count.saturating_add(1);
            }
            PreservationBucket::TrustedSystemSender => {
                preserved_trusted_system_count = preserved_trusted_system_count.saturating_add(1);
            }
            PreservationBucket::LowConfidenceOther => {
                low_confidence_other_uids.push((uid, classification.confidence_bps));
            }
        }
    }
    let low_confidence_other_total_count = low_confidence_other_uids.len() as u32;
    let mut low_confidence_other_candidate_uids = BTreeSet::new();
    for (uid, score) in promoted_primary_unwanted_uids {
        if low_confidence_other_candidate_uids.insert(uid) {
            high_confidence_uids.push((uid, score));
        }
    }
    if cleanup_scope == CleanupMailboxScope::PrimaryInbox {
        let low_other_ratio_bps = if evaluated_count == 0 {
            0
        } else {
            ((low_confidence_other_total_count.saturating_mul(10_000)) / (evaluated_count as u32))
                .min(10_000)
        };
        if low_other_ratio_bps >= PRIMARY_UNWANTED_BULK_PROMOTION_MIN_RATIO_BPS {
            for (uid, score) in &low_confidence_other_uids {
                if low_confidence_other_candidate_uids.insert(*uid) {
                    high_confidence_uids.push((*uid, *score));
                }
            }
        } else if high_confidence_uids.is_empty()
            && low_other_ratio_bps >= PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_MIN_RATIO_BPS
            && !low_confidence_other_uids.is_empty()
        {
            // Adaptive primary-inbox cleanup: when most recent messages are low-confidence
            // "other" and strict spam signals found none, promote the top score band.
            let mut ranked = low_confidence_other_uids.clone();
            ranked.sort_unstable_by(|(uid_a, score_a), (uid_b, score_b)| {
                score_b.cmp(score_a).then_with(|| uid_b.cmp(uid_a))
            });
            let top_score = ranked[0].1;
            let adaptive_floor =
                top_score.saturating_sub(PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_SCORE_DELTA_BPS);
            for (uid, score) in ranked.iter().copied() {
                if low_confidence_other_candidate_uids.len() >= max_delete as usize {
                    break;
                }
                if score < adaptive_floor {
                    continue;
                }
                if low_confidence_other_candidate_uids.insert(uid) {
                    high_confidence_uids.push((uid, score));
                }
            }

            if high_confidence_uids.is_empty() {
                if let Some((uid, score)) = ranked.first().copied() {
                    if low_confidence_other_candidate_uids.insert(uid) {
                        high_confidence_uids.push((uid, score));
                    }
                }
            }
        }
    }
    let preserved_low_confidence_other_count = low_confidence_other_total_count.saturating_sub(
        low_confidence_other_candidate_uids
            .len()
            .min(u32::MAX as usize) as u32,
    );
    let high_confidence_candidate_count = high_confidence_uids.len() as u32;
    let skipped_low_confidence_count = preserved_transactional_or_personal_count
        .saturating_add(preserved_trusted_system_count)
        .saturating_add(preserved_low_confidence_other_count);
    high_confidence_uids.sort_unstable_by(|(uid_a, score_a), (uid_b, score_b)| {
        score_b.cmp(score_a).then_with(|| uid_b.cmp(uid_a))
    });
    high_confidence_uids.truncate(max_delete as usize);

    let mut selected_uids = high_confidence_uids
        .iter()
        .map(|(uid, _)| *uid)
        .collect::<Vec<_>>();
    selected_uids.sort_unstable_by(|a, b| b.cmp(a));
    let target_count = selected_uids.len() as u32;
    let preserved_due_to_delete_cap_count =
        high_confidence_candidate_count.saturating_sub(target_count);
    if selected_uids.is_empty() {
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: evaluated_count as u32,
            deleted_count: 0,
            skipped_low_confidence_count,
            high_confidence_deleted_count: 0,
            mailbox_total_count_before,
            mailbox_total_count_after: mailbox_total_count_before,
            mailbox_total_count_delta: 0,
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count,
            preserved_trusted_system_count,
            preserved_low_confidence_other_count,
            preserved_due_to_delete_cap_count,
        });
    }
    let selected_set = selected_uids
        .iter()
        .map(|uid| uid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if session.uid_mv(&selected_set, "Trash").is_ok() {
        let measured_after = mailbox_total_count_from_mailbox(session, &selected_mailbox)
            .ok()
            .map(|outcome| outcome.mailbox_total_count);
        let mailbox_total_count_after = reconcile_mailbox_total_count_after_delete(
            mailbox_total_count_before,
            target_count,
            measured_after,
        );
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: evaluated_count as u32,
            deleted_count: target_count,
            skipped_low_confidence_count,
            high_confidence_deleted_count: target_count,
            mailbox_total_count_before,
            mailbox_total_count_after,
            mailbox_total_count_delta: mailbox_total_count_before
                .saturating_sub(mailbox_total_count_after),
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count,
            preserved_trusted_system_count,
            preserved_low_confidence_other_count,
            preserved_due_to_delete_cap_count,
        });
    }

    session
        .uid_store(&selected_set, "+FLAGS.SILENT (\\Deleted)")
        .map_err(|e| TransactionError::Invalid(format!("imap uid store +deleted failed: {}", e)))?;
    let deleted_count = match session.uid_expunge(&selected_set) {
        Ok(expunged) => expunged.len() as u32,
        Err(_) => {
            session
                .expunge()
                .map_err(|e| TransactionError::Invalid(format!("imap expunge failed: {}", e)))?;
            target_count
        }
    };
    let measured_after = mailbox_total_count_from_mailbox(session, &selected_mailbox)
        .ok()
        .map(|outcome| outcome.mailbox_total_count);
    let mailbox_total_count_after = reconcile_mailbox_total_count_after_delete(
        mailbox_total_count_before,
        deleted_count,
        measured_after,
    );
    Ok(MailProviderDeleteSpamOutcome {
        evaluated_count: evaluated_count as u32,
        deleted_count,
        skipped_low_confidence_count,
        high_confidence_deleted_count: deleted_count,
        mailbox_total_count_before,
        mailbox_total_count_after,
        mailbox_total_count_delta: mailbox_total_count_before
            .saturating_sub(mailbox_total_count_after),
        spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
        ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
        cleanup_scope: cleanup_scope_label,
        preserved_transactional_or_personal_count,
        preserved_trusted_system_count,
        preserved_low_confidence_other_count,
        preserved_due_to_delete_cap_count,
    })
}

fn mail_provider_message_from_fetch(
    fetch: &imap::types::Fetch,
    now_ms: u64,
) -> Result<MailProviderMessage, TransactionError> {
    let envelope = fetch.envelope();
    let from = envelope
        .and_then(|envelope| {
            envelope.from.as_ref().and_then(|addresses| {
                addresses
                    .iter()
                    .filter_map(|address| {
                        let mailbox = address
                            .mailbox
                            .as_ref()
                            .map(|value| decode_bytes(value.as_ref()));
                        let host = address
                            .host
                            .as_ref()
                            .map(|value| decode_bytes(value.as_ref()));
                        match (mailbox, host) {
                            (Some(mailbox), Some(host))
                                if !mailbox.is_empty() && !host.is_empty() =>
                            {
                                Some(format!("{}@{}", mailbox, host))
                            }
                            _ => address
                                .name
                                .as_ref()
                                .map(|value| decode_bytes(value.as_ref()))
                                .filter(|value| !value.is_empty()),
                        }
                    })
                    .next()
            })
        })
        .unwrap_or_else(|| "unknown@unknown".to_string());
    let subject = envelope
        .and_then(|value| value.subject.as_ref())
        .map(|value| decode_bytes(value.as_ref()))
        .unwrap_or_else(|| "(no subject)".to_string());
    let message_id = envelope
        .and_then(|value| value.message_id.as_ref())
        .map(|value| decode_bytes(value.as_ref()))
        .map(|value| value.trim_matches(['<', '>']).to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| match fetch.uid {
            Some(uid) => format!("uid-{}", uid),
            None => format!("seq-{}", fetch.message),
        });

    let preview = fetch
        .text()
        .map(decode_bytes)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fetch
                .body()
                .map(decode_bytes)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| subject.clone());

    let received_at_ms = fetch
        .internal_date()
        .map(|value| value.timestamp_millis())
        .filter(|value| *value > 0)
        .map(|value| value as u64)
        .unwrap_or(now_ms);

    Ok(MailProviderMessage {
        message_id: bound_text(&message_id, 256),
        from: bound_text(&from, MAIL_FROM_MAX_LEN),
        subject: bound_text(&subject, MAIL_SUBJECT_MAX_LEN),
        received_at_ms,
        preview: bound_text(&preview, MAIL_PREVIEW_MAX_LEN),
    })
}

fn decode_bytes(input: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(input);
    lossy.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn bound_text(input: &str, max_len: usize) -> String {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(max_len).collect()
}

fn deterministic_mock_id(parts: &[&[u8]]) -> Result<String, TransactionError> {
    let mut material = Vec::new();
    for part in parts {
        material.extend_from_slice(part);
        material.extend_from_slice(b"|");
    }
    let digest = hash_bytes(&material)?;
    Ok(format!("msg-{}", hex::encode(&digest[..8])))
}
