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
