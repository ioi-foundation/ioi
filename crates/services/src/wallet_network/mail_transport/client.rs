use super::imap_ops::{
    authenticate_imap_session, build_tls_connector, delete_spam_from_imap_session,
    list_recent_from_imap_session, mailbox_total_count_from_mailbox, open_plain_imap_client,
    read_latest_from_imap_session, smtp_auth_secret,
};
use super::mailbox::{
    cleanup_scope_from_mailbox, is_primary_mailbox_name, is_spam_mailbox_name,
    normalize_remote_mailbox_name, CleanupMailboxScope,
};
use super::model::{
    MailProviderClient, MailProviderCredentials, MailProviderDeleteSpamOutcome,
    MailProviderListOutcome, MailProviderMailboxTotalCountOutcome, MailProviderMessage,
};
use super::util::bound_text;
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
    MailConnectorTlsMode,
};
use ioi_types::error::TransactionError;
use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::Address;
use lettre::{Message, SmtpTransport, Transport};

pub(crate) struct ImapSmtpMailProviderClient;

const SMTP_STARTTLS_PORT: u16 = 587;
const SMTP_TLS_PORT: u16 = 465;

pub(crate) fn mail_provider_for_config(
    config: &MailConnectorConfig,
) -> Result<Box<dyn MailProviderClient>, TransactionError> {
    match config.provider {
        MailConnectorProvider::ImapSmtp => Ok(Box::new(ImapSmtpMailProviderClient)),
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
        let from_mailbox = smtp_from_mailbox(config)?;
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| TransactionError::Invalid(format!("smtp to address is invalid: {}", e)))?;
        let message = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| TransactionError::Invalid(format!("smtp message build failed: {}", e)))?;
        let selected_endpoint = select_smtp_delivery_endpoint(&config.smtp, credentials)?;
        let sent_id =
            send_via_smtp_endpoint(&selected_endpoint, credentials, &message).map_err(|error| {
                TransactionError::Invalid(format!(
                    "smtp send failed for '{}': {}:{} ({}) => {}",
                    to,
                    selected_endpoint.host,
                    selected_endpoint.port,
                    smtp_tls_mode_label(selected_endpoint.tls_mode),
                    error
                ))
            })?;
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

fn smtp_from_mailbox(config: &MailConnectorConfig) -> Result<Mailbox, TransactionError> {
    let address: Address = config
        .account_email
        .parse()
        .map_err(|e| TransactionError::Invalid(format!("smtp from address is invalid: {}", e)))?;
    let display_name = config
        .sender_display_name
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    Ok(Mailbox::new(display_name, address))
}

fn send_via_smtp_endpoint(
    endpoint: &MailConnectorEndpoint,
    credentials: &MailProviderCredentials,
    message: &Message,
) -> Result<String, String> {
    let smtp_builder = smtp_transport_builder(endpoint)?;
    let mut smtp_builder = smtp_builder
        .port(endpoint.port)
        .credentials(Credentials::new(
            credentials.smtp_username.clone(),
            smtp_auth_secret(credentials).to_string(),
        ));
    if credentials.auth_mode == MailConnectorAuthMode::Oauth2 {
        smtp_builder = smtp_builder.authentication(vec![Mechanism::Xoauth2]);
    }
    let smtp_transport = smtp_builder.build();
    let response = smtp_transport
        .send(message)
        .map_err(|err| err.to_string())?;
    Ok(response
        .first_word()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| "smtp-ack".to_string()))
}

fn probe_smtp_endpoint(
    endpoint: &MailConnectorEndpoint,
    credentials: &MailProviderCredentials,
) -> Result<bool, String> {
    let smtp_builder = smtp_transport_builder(endpoint)?;
    let mut smtp_builder = smtp_builder
        .port(endpoint.port)
        .credentials(Credentials::new(
            credentials.smtp_username.clone(),
            smtp_auth_secret(credentials).to_string(),
        ));
    if credentials.auth_mode == MailConnectorAuthMode::Oauth2 {
        smtp_builder = smtp_builder.authentication(vec![Mechanism::Xoauth2]);
    }
    smtp_builder
        .build()
        .test_connection()
        .map_err(|err| err.to_string())
}

fn smtp_transport_builder(
    endpoint: &MailConnectorEndpoint,
) -> Result<lettre::transport::smtp::SmtpTransportBuilder, String> {
    match endpoint.tls_mode {
        MailConnectorTlsMode::Plaintext => Ok(SmtpTransport::builder_dangerous(&endpoint.host)),
        MailConnectorTlsMode::StartTls => SmtpTransport::starttls_relay(&endpoint.host)
            .map_err(|e| format!("smtp starttls relay init failed: {}", e)),
        MailConnectorTlsMode::Tls => SmtpTransport::relay(&endpoint.host)
            .map_err(|e| format!("smtp tls relay init failed: {}", e)),
    }
}

fn select_smtp_delivery_endpoint(
    endpoint: &MailConnectorEndpoint,
    credentials: &MailProviderCredentials,
) -> Result<MailConnectorEndpoint, TransactionError> {
    let candidates = smtp_endpoint_probe_candidates(endpoint);
    let mut failures = Vec::new();

    for candidate in candidates {
        match probe_smtp_endpoint(&candidate, credentials) {
            Ok(true) => return Ok(candidate),
            Ok(false) => failures.push(format!(
                "{}:{} ({}) => probe returned disconnected",
                candidate.host,
                candidate.port,
                smtp_tls_mode_label(candidate.tls_mode)
            )),
            Err(error) => failures.push(format!(
                "{}:{} ({}) => {}",
                candidate.host,
                candidate.port,
                smtp_tls_mode_label(candidate.tls_mode),
                error
            )),
        }
    }

    Err(TransactionError::Invalid(format!(
        "smtp provider selection failed for '{}:{}' (configured mode {}): {}",
        endpoint.host,
        endpoint.port,
        smtp_tls_mode_label(endpoint.tls_mode),
        failures.join("; ")
    )))
}

fn smtp_endpoint_probe_candidates(endpoint: &MailConnectorEndpoint) -> Vec<MailConnectorEndpoint> {
    let mut attempts = vec![endpoint.clone()];
    if let Some(alternate_mode) = alternate_secure_smtp_tls_mode(endpoint.tls_mode) {
        push_unique_smtp_endpoint(
            &mut attempts,
            MailConnectorEndpoint {
                host: endpoint.host.clone(),
                port: endpoint.port,
                tls_mode: alternate_mode,
            },
        );
        push_unique_smtp_endpoint(
            &mut attempts,
            MailConnectorEndpoint {
                host: endpoint.host.clone(),
                port: standard_smtp_port_for_tls_mode(alternate_mode),
                tls_mode: alternate_mode,
            },
        );
    }
    attempts
}

fn push_unique_smtp_endpoint(
    attempts: &mut Vec<MailConnectorEndpoint>,
    candidate: MailConnectorEndpoint,
) {
    if attempts.iter().any(|existing| {
        existing.host == candidate.host
            && existing.port == candidate.port
            && existing.tls_mode == candidate.tls_mode
    }) {
        return;
    }
    attempts.push(candidate);
}

fn alternate_secure_smtp_tls_mode(mode: MailConnectorTlsMode) -> Option<MailConnectorTlsMode> {
    match mode {
        MailConnectorTlsMode::Plaintext => None,
        MailConnectorTlsMode::StartTls => Some(MailConnectorTlsMode::Tls),
        MailConnectorTlsMode::Tls => Some(MailConnectorTlsMode::StartTls),
    }
}

fn standard_smtp_port_for_tls_mode(mode: MailConnectorTlsMode) -> u16 {
    match mode {
        MailConnectorTlsMode::Plaintext | MailConnectorTlsMode::StartTls => SMTP_STARTTLS_PORT,
        MailConnectorTlsMode::Tls => SMTP_TLS_PORT,
    }
}

fn smtp_tls_mode_label(mode: MailConnectorTlsMode) -> &'static str {
    match mode {
        MailConnectorTlsMode::Plaintext => "plaintext",
        MailConnectorTlsMode::StartTls => "starttls",
        MailConnectorTlsMode::Tls => "tls",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::MailConnectorSecretAliases;

    #[test]
    fn smtp_probe_candidates_try_opposite_mode_on_same_port_first() {
        let attempts = smtp_endpoint_probe_candidates(&MailConnectorEndpoint {
            host: "smtp.aol.com".to_string(),
            port: 587,
            tls_mode: MailConnectorTlsMode::Tls,
        });
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].port, 587);
        assert_eq!(attempts[0].tls_mode, MailConnectorTlsMode::Tls);
        assert_eq!(attempts[1].port, 587);
        assert_eq!(attempts[1].tls_mode, MailConnectorTlsMode::StartTls);
    }

    #[test]
    fn smtp_probe_candidates_add_standard_secure_port_when_needed() {
        let attempts = smtp_endpoint_probe_candidates(&MailConnectorEndpoint {
            host: "smtp.aol.com".to_string(),
            port: 465,
            tls_mode: MailConnectorTlsMode::Tls,
        });
        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[0].port, 465);
        assert_eq!(attempts[0].tls_mode, MailConnectorTlsMode::Tls);
        assert_eq!(attempts[1].port, 465);
        assert_eq!(attempts[1].tls_mode, MailConnectorTlsMode::StartTls);
        assert_eq!(attempts[2].port, 587);
        assert_eq!(attempts[2].tls_mode, MailConnectorTlsMode::StartTls);
    }

    #[test]
    fn smtp_probe_candidates_mirror_starttls_to_wrapper_tls() {
        let attempts = smtp_endpoint_probe_candidates(&MailConnectorEndpoint {
            host: "smtp.example.com".to_string(),
            port: 587,
            tls_mode: MailConnectorTlsMode::StartTls,
        });
        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[1].port, 587);
        assert_eq!(attempts[1].tls_mode, MailConnectorTlsMode::Tls);
        assert_eq!(attempts[2].port, 465);
        assert_eq!(attempts[2].tls_mode, MailConnectorTlsMode::Tls);
    }

    #[test]
    fn smtp_from_mailbox_uses_mailbox_sender_display_name() {
        let mailbox = smtp_from_mailbox(&MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode: MailConnectorAuthMode::Password,
            account_email: "levi@example.com".to_string(),
            sender_display_name: Some("Levi Josman".to_string()),
            imap: MailConnectorEndpoint {
                host: "imap.example.com".to_string(),
                port: 993,
                tls_mode: MailConnectorTlsMode::Tls,
            },
            smtp: MailConnectorEndpoint {
                host: "smtp.example.com".to_string(),
                port: 587,
                tls_mode: MailConnectorTlsMode::StartTls,
            },
            secret_aliases: MailConnectorSecretAliases {
                imap_username_alias: "imap.user".to_string(),
                imap_password_alias: "imap.pass".to_string(),
                smtp_username_alias: "smtp.user".to_string(),
                smtp_password_alias: "smtp.pass".to_string(),
            },
            metadata: Default::default(),
        })
        .expect("from mailbox should parse");

        assert_eq!(mailbox.name.as_deref(), Some("Levi Josman"));
        assert_eq!(mailbox.email.to_string(), "levi@example.com");
    }
}
