// Path: crates/services/src/wallet_network/handlers/connectors/shared.rs

use crate::wallet_network::keys::{mail_connector_key, secret_alias_key, secret_key};
use crate::wallet_network::mail_ontology::classify_mail_spam;
use crate::wallet_network::mail_transport::{MailProviderCredentials, MailProviderMessage};
use crate::wallet_network::support::load_typed;
use crate::wallet_network::LeaseActionReplayWindowState;
use ioi_api::state::StateAccess;
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorRecord,
    MailConnectorSecretAliases, MailMessageSummary, VaultSecretRecord,
};
use ioi_types::error::TransactionError;
use std::collections::BTreeMap;

pub(super) const LEASE_OPERATION_TRACK_LIMIT: usize = 256;
const LEASE_ACTION_NONCE_TRACK_LIMIT: usize = 256;
const UNORDERED_CONNECTOR_ACTION_REPLAY_WINDOW: u64 = 512;
const MAIL_LIST_RECENT_DEFAULT_LIMIT: usize = 25;
const MAIL_LIST_RECENT_MAX_LIMIT: usize = 200;
const MAIL_DELETE_SPAM_DEFAULT_LIMIT: u32 = 25;
const MAIL_DELETE_SPAM_MAX_LIMIT: u32 = 500;
const MAIL_CONNECTOR_MAX_ALIAS_LEN: usize = 128;
const MAIL_CONNECTOR_SENSITIVE_METADATA_KEYWORDS: [&str; 6] = [
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
];
const MAIL_READ_CAPABILITY_ALIASES: [&str; 4] =
    ["mail.read.latest", "mail:read", "mail.read", "email:read"];
const MAIL_LIST_CAPABILITY_ALIASES: [&str; 8] = [
    "mail.list.recent",
    "mail:list",
    "mail.list",
    "email:list",
    "mail.read.latest",
    "mail:read",
    "mail.read",
    "email:read",
];
const MAIL_DELETE_CAPABILITY_ALIASES: [&str; 7] = [
    "mail.delete.spam",
    "mail.delete",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.modify",
    "email:modify",
];
const MAIL_DELETE_MAILBOX_ALIASES: [&str; 7] = [
    "primary",
    "inbox",
    "spam",
    "junk",
    "junkemail",
    "bulk",
    "trash",
];
const MAIL_REPLY_CAPABILITY_ALIASES: [&str; 9] = [
    "mail.reply",
    "mail.send",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.compose",
    "email:compose",
    "mail.modify",
    "email:modify",
];

pub(super) fn enforce_connector_action_replay_window(
    replay_window: &mut LeaseActionReplayWindowState,
    op_seq: u64,
    op_nonce: Option<[u8; 32]>,
) -> Result<(), TransactionError> {
    match replay_window.ordering {
        ioi_types::app::wallet_network::SessionChannelOrdering::Ordered => {
            let expected_seq =
                if replay_window.seen_seqs.is_empty() && replay_window.highest_seq == 0 {
                    1
                } else {
                    replay_window.highest_seq.saturating_add(1)
                };
            if op_seq != expected_seq {
                return Err(TransactionError::Invalid(format!(
                    "ordered action op_seq {} does not match expected {}",
                    op_seq, expected_seq
                )));
            }
            replay_window.highest_seq = op_seq;
            replay_window.seen_seqs.clear();
            replay_window.seen_seqs.insert(op_seq);
        }
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered => {
            if replay_window.seen_seqs.contains(&op_seq) {
                return Err(TransactionError::Invalid(
                    "unordered action replay detected for op_seq".to_string(),
                ));
            }
            if op_seq.saturating_add(UNORDERED_CONNECTOR_ACTION_REPLAY_WINDOW)
                < replay_window.highest_seq
            {
                return Err(TransactionError::Invalid(
                    "unordered action op_seq is outside replay window".to_string(),
                ));
            }
            replay_window.highest_seq = replay_window.highest_seq.max(op_seq);
            replay_window.seen_seqs.insert(op_seq);
            let min_allowed = replay_window
                .highest_seq
                .saturating_sub(UNORDERED_CONNECTOR_ACTION_REPLAY_WINDOW);
            replay_window.seen_seqs.retain(|seq| *seq >= min_allowed);
        }
    }

    if let Some(op_nonce) = op_nonce {
        if replay_window
            .seen_nonces
            .iter()
            .any(|seen| *seen == op_nonce)
        {
            return Err(TransactionError::Invalid(
                "action op_nonce replay detected".to_string(),
            ));
        }
        replay_window.seen_nonces.push(op_nonce);
        if replay_window.seen_nonces.len() > LEASE_ACTION_NONCE_TRACK_LIMIT {
            let excess = replay_window.seen_nonces.len() - LEASE_ACTION_NONCE_TRACK_LIMIT;
            replay_window.seen_nonces.drain(0..excess);
        }
    }
    Ok(())
}

pub(super) fn normalize_mailbox(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "primary".to_string();
    }
    trimmed.to_ascii_lowercase()
}

pub(super) fn mail_provider_message_to_summary(
    message: MailProviderMessage,
    mailbox: &str,
) -> MailMessageSummary {
    let spam_classification =
        classify_mail_spam(mailbox, &message.from, &message.subject, &message.preview);
    MailMessageSummary {
        message_id: message.message_id,
        from: message.from,
        subject: message.subject,
        received_at_ms: message.received_at_ms,
        preview: message.preview,
        spam_confidence_bps: spam_classification.confidence_bps,
        spam_confidence_band: spam_classification.confidence_band.to_string(),
        spam_signal_tags: spam_classification.signal_tags,
    }
}

pub(super) fn load_mail_connector_record(
    state: &dyn StateAccess,
    mailbox: &str,
) -> Result<MailConnectorRecord, TransactionError> {
    let key = mail_connector_key(mailbox);
    let connector: MailConnectorRecord = load_typed(state, &key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "mail connector for mailbox '{}' is not configured",
            mailbox
        ))
    })?;
    if connector.mailbox != mailbox {
        return Err(TransactionError::Invalid(
            "mail connector mailbox binding mismatch".to_string(),
        ));
    }
    Ok(connector)
}

pub(super) fn resolve_mail_provider_credentials(
    state: &dyn StateAccess,
    connector: &MailConnectorRecord,
) -> Result<MailProviderCredentials, TransactionError> {
    let imap_secret = resolve_secret_alias_utf8(
        state,
        &connector.config.secret_aliases.imap_password_alias,
        "imap_password_alias",
    )?;
    let smtp_secret = resolve_secret_alias_utf8(
        state,
        &connector.config.secret_aliases.smtp_password_alias,
        "smtp_password_alias",
    )?;
    Ok(MailProviderCredentials {
        auth_mode: connector.config.auth_mode,
        imap_username: resolve_secret_alias_utf8(
            state,
            &connector.config.secret_aliases.imap_username_alias,
            "imap_username_alias",
        )?,
        imap_secret,
        smtp_username: resolve_secret_alias_utf8(
            state,
            &connector.config.secret_aliases.smtp_username_alias,
            "smtp_username_alias",
        )?,
        smtp_secret,
    })
}

pub(super) fn ensure_connector_secret_aliases_registered(
    state: &dyn StateAccess,
    aliases: &MailConnectorSecretAliases,
) -> Result<(), TransactionError> {
    for (alias, field_name) in [
        (&aliases.imap_username_alias, "imap_username_alias"),
        (&aliases.imap_password_alias, "imap_password_alias"),
        (&aliases.smtp_username_alias, "smtp_username_alias"),
        (&aliases.smtp_password_alias, "smtp_password_alias"),
    ] {
        ensure_secret_alias_registered(state, alias, field_name)?;
    }
    Ok(())
}

fn ensure_secret_alias_registered(
    state: &dyn StateAccess,
    alias: &str,
    field_name: &str,
) -> Result<(), TransactionError> {
    let secret_id: String = load_typed(state, &secret_alias_key(alias))?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "mail connector secret alias '{}' for '{}' is not registered",
            alias.trim(),
            field_name
        ))
    })?;
    let secret: VaultSecretRecord =
        load_typed(state, &secret_key(&secret_id))?.ok_or_else(|| {
            TransactionError::Invalid(format!(
                "mail connector secret alias '{}' maps to unknown secret_id '{}'",
                alias.trim(),
                secret_id
            ))
        })?;
    if secret.ciphertext.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret '{}' has empty ciphertext",
            secret_id
        )));
    }
    Ok(())
}

fn resolve_secret_alias_utf8(
    state: &dyn StateAccess,
    alias: &str,
    field_name: &str,
) -> Result<String, TransactionError> {
    let secret_id: String = load_typed(state, &secret_alias_key(alias))?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "mail connector secret alias '{}' for '{}' is not registered",
            alias.trim(),
            field_name
        ))
    })?;
    let secret: VaultSecretRecord =
        load_typed(state, &secret_key(&secret_id))?.ok_or_else(|| {
            TransactionError::Invalid(format!(
                "mail connector secret alias '{}' maps to unknown secret_id '{}'",
                alias.trim(),
                secret_id
            ))
        })?;
    if secret.ciphertext.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret '{}' has empty ciphertext",
            secret_id
        )));
    }
    let value = String::from_utf8(secret.ciphertext).map_err(|_| {
        TransactionError::Invalid(format!(
            "mail connector secret '{}' is not utf-8 decodable",
            secret_id
        ))
    })?;
    if value.trim().is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret '{}' resolves to empty text",
            secret_id
        )));
    }
    Ok(value)
}

pub(super) fn normalize_mail_connector_config(
    config: MailConnectorConfig,
) -> Result<MailConnectorConfig, TransactionError> {
    let account_email = config.account_email.trim().to_ascii_lowercase();
    if account_email.is_empty() {
        return Err(TransactionError::Invalid(
            "mail connector account_email must not be empty".to_string(),
        ));
    }

    let imap = normalize_mail_connector_endpoint("imap", config.imap)?;
    let smtp = normalize_mail_connector_endpoint("smtp", config.smtp)?;
    let secret_aliases = normalize_mail_connector_secret_aliases(config.secret_aliases)?;
    let metadata = normalize_mail_connector_metadata(config.metadata)?;

    Ok(MailConnectorConfig {
        provider: config.provider,
        auth_mode: normalize_mail_connector_auth_mode(config.auth_mode),
        account_email,
        imap,
        smtp,
        secret_aliases,
        metadata,
    })
}

fn normalize_mail_connector_auth_mode(mode: MailConnectorAuthMode) -> MailConnectorAuthMode {
    mode
}

fn normalize_mail_connector_endpoint(
    label: &str,
    endpoint: MailConnectorEndpoint,
) -> Result<MailConnectorEndpoint, TransactionError> {
    let host = endpoint.host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector {} host must not be empty",
            label
        )));
    }
    if endpoint.port == 0 {
        return Err(TransactionError::Invalid(format!(
            "mail connector {} port must be > 0",
            label
        )));
    }
    Ok(MailConnectorEndpoint {
        host,
        port: endpoint.port,
        tls_mode: endpoint.tls_mode,
    })
}

fn normalize_mail_connector_secret_aliases(
    aliases: MailConnectorSecretAliases,
) -> Result<MailConnectorSecretAliases, TransactionError> {
    Ok(MailConnectorSecretAliases {
        imap_username_alias: normalize_required_secret_alias(
            &aliases.imap_username_alias,
            "imap_username_alias",
        )?,
        imap_password_alias: normalize_required_secret_alias(
            &aliases.imap_password_alias,
            "imap_password_alias",
        )?,
        smtp_username_alias: normalize_required_secret_alias(
            &aliases.smtp_username_alias,
            "smtp_username_alias",
        )?,
        smtp_password_alias: normalize_required_secret_alias(
            &aliases.smtp_password_alias,
            "smtp_password_alias",
        )?,
    })
}

fn normalize_required_secret_alias(
    alias: &str,
    field_name: &str,
) -> Result<String, TransactionError> {
    let normalized = alias.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret alias '{}' must not be empty",
            field_name
        )));
    }
    if normalized.len() > MAIL_CONNECTOR_MAX_ALIAS_LEN {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret alias '{}' exceeds {} characters",
            field_name, MAIL_CONNECTOR_MAX_ALIAS_LEN
        )));
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(TransactionError::Invalid(format!(
            "mail connector secret alias '{}' contains invalid characters",
            field_name
        )));
    }
    Ok(normalized)
}

fn normalize_mail_connector_metadata(
    metadata: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, TransactionError> {
    let mut normalized = BTreeMap::new();
    for (key, value) in metadata {
        let normalized_key = key.trim().to_ascii_lowercase();
        if normalized_key.is_empty() {
            continue;
        }
        if contains_sensitive_connector_metadata_key(&normalized_key) {
            return Err(TransactionError::Invalid(format!(
                "mail connector metadata key '{}' is not allowed for secret safety; use secret aliases instead",
                normalized_key
            )));
        }
        normalized.insert(normalized_key, value.trim().to_string());
    }
    Ok(normalized)
}

fn contains_sensitive_connector_metadata_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    MAIL_CONNECTOR_SENSITIVE_METADATA_KEYWORDS
        .iter()
        .any(|keyword| normalized.contains(keyword))
}

pub(super) fn normalize_mail_list_limit(limit: u32) -> usize {
    if limit == 0 {
        return MAIL_LIST_RECENT_DEFAULT_LIMIT;
    }
    (limit as usize).clamp(1, MAIL_LIST_RECENT_MAX_LIMIT)
}

pub(super) fn contains_mail_read_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_READ_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

pub(super) fn contains_mail_list_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_LIST_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

pub(super) fn contains_mail_delete_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_DELETE_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

pub(super) fn enforce_delete_cleanup_mailbox_target(mailbox: &str) -> Result<(), TransactionError> {
    if MAIL_DELETE_MAILBOX_ALIASES
        .iter()
        .any(|allowed| mailbox.eq_ignore_ascii_case(allowed))
    {
        return Ok(());
    }
    Err(TransactionError::Invalid(format!(
        "mail_delete_spam requires primary/inbox or spam/junk mailbox target; got '{}'",
        mailbox
    )))
}

pub(super) fn contains_mail_reply_capability(capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        MAIL_REPLY_CAPABILITY_ALIASES
            .iter()
            .any(|allowed| normalized == *allowed)
    })
}

pub(super) fn enforce_mailbox_constraint(
    expected_mailbox: Option<&String>,
    mailbox: &str,
) -> Result<(), TransactionError> {
    let Some(expected_mailbox) = expected_mailbox else {
        return Ok(());
    };
    let expected = normalize_mailbox(expected_mailbox);
    if expected == mailbox {
        return Ok(());
    }
    Err(TransactionError::Invalid(format!(
        "mailbox '{}' is outside lease/channel constraints",
        mailbox
    )))
}

pub(super) fn normalize_delete_limit(limit: u32) -> u32 {
    if limit == 0 {
        return MAIL_DELETE_SPAM_DEFAULT_LIMIT;
    }
    limit.clamp(1, MAIL_DELETE_SPAM_MAX_LIMIT)
}
