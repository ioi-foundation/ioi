use super::constants::{
    MAIL_CONNECTOR_ALIAS_MAX_LEN, MAIL_CONNECTOR_DEFAULT_MAILBOX, MAIL_CONNECTOR_SECRET_ID_PREFIX,
    MAIL_DELETE_SPAM_DEFAULT_LIMIT, MAIL_DELETE_SPAM_MAX_LIMIT,
};
use ioi_types::app::{MailConnectorAuthMode, MailConnectorTlsMode};

pub(crate) fn normalize_delete_limit(value: Option<u32>) -> u32 {
    value
        .unwrap_or(MAIL_DELETE_SPAM_DEFAULT_LIMIT)
        .clamp(1, MAIL_DELETE_SPAM_MAX_LIMIT)
}

pub(crate) fn parse_mail_connector_auth_mode(
    raw: Option<&str>,
) -> Result<MailConnectorAuthMode, String> {
    match raw
        .unwrap_or("password")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "password" | "pass" => Ok(MailConnectorAuthMode::Password),
        "oauth2" | "xoauth2" | "oauth" => Ok(MailConnectorAuthMode::Oauth2),
        other => Err(format!(
            "Invalid authMode '{}': expected password or oauth2",
            other
        )),
    }
}

pub(crate) fn parse_mail_connector_tls_mode(
    raw: Option<&str>,
    default_mode: MailConnectorTlsMode,
) -> Result<MailConnectorTlsMode, String> {
    let mode = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(match default_mode {
            MailConnectorTlsMode::Plaintext => "plaintext",
            MailConnectorTlsMode::StartTls => "starttls",
            MailConnectorTlsMode::Tls => "tls",
        })
        .to_ascii_lowercase();
    match mode.as_str() {
        "plaintext" | "plain" => Ok(MailConnectorTlsMode::Plaintext),
        "starttls" | "start_tls" | "start-tls" => Ok(MailConnectorTlsMode::StartTls),
        "tls" | "ssl" => Ok(MailConnectorTlsMode::Tls),
        other => Err(format!(
            "Invalid TLS mode '{}': expected plaintext, starttls, or tls",
            other
        )),
    }
}

pub(crate) fn mailbox_or_default(raw: Option<String>) -> String {
    let mailbox = raw
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(MAIL_CONNECTOR_DEFAULT_MAILBOX)
        .to_ascii_lowercase();
    if mailbox.is_empty() {
        MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()
    } else {
        mailbox
    }
}

fn alias_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let normalized = out.trim_matches('-').to_string();
    if normalized.is_empty() {
        MAIL_CONNECTOR_DEFAULT_MAILBOX.to_string()
    } else {
        normalized
    }
}

fn bounded_alias(mut alias: String) -> String {
    if alias.len() > MAIL_CONNECTOR_ALIAS_MAX_LEN {
        alias.truncate(MAIL_CONNECTOR_ALIAS_MAX_LEN);
    }
    alias
}

pub(crate) fn alias_for_mailbox(mailbox: &str, path: &str) -> String {
    let segment = alias_segment(mailbox);
    bounded_alias(format!("mail.{}.{}", segment, path))
}

pub(crate) fn secret_id_for_mailbox(mailbox: &str, suffix: &str) -> String {
    format!(
        "{}-{}-{}-{}",
        MAIL_CONNECTOR_SECRET_ID_PREFIX,
        alias_segment(mailbox),
        suffix,
        uuid::Uuid::new_v4().simple()
    )
}

pub(crate) fn tls_mode_label(mode: MailConnectorTlsMode) -> &'static str {
    match mode {
        MailConnectorTlsMode::Plaintext => "plaintext",
        MailConnectorTlsMode::StartTls => "starttls",
        MailConnectorTlsMode::Tls => "tls",
    }
}
