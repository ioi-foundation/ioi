// Path: crates/types/src/app/wallet_network/mail_connector.rs

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Supported mail connector provider implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum MailConnectorProvider {
    /// Standard IMAP (read/list/delete) + SMTP (send/reply) pair.
    ImapSmtp,
}

/// Authentication mode for mail connector credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum MailConnectorAuthMode {
    /// Username plus password/app-password style authentication.
    Password,
    /// OAuth2 bearer-token authentication (XOAUTH2/OAUTHBEARER capable providers).
    Oauth2,
}

/// Transport security mode for a mail endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum MailConnectorTlsMode {
    /// Plaintext transport (discouraged; local/dev only).
    Plaintext,
    /// Opportunistic STARTTLS upgrade.
    StartTls,
    /// TLS from connection start.
    Tls,
}

/// Mail endpoint address and transport mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailConnectorEndpoint {
    /// Endpoint hostname (for example: `imap.gmail.com`).
    pub host: String,
    /// Endpoint port (for example: `993` for IMAP/TLS).
    pub port: u16,
    /// Transport security mode.
    pub tls_mode: MailConnectorTlsMode,
}

/// Secret-alias references consumed by mail connector execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailConnectorSecretAliases {
    /// Alias for IMAP auth username/account id.
    pub imap_username_alias: String,
    /// Alias for IMAP auth secret (password for `password`, bearer token for `oauth2`).
    pub imap_password_alias: String,
    /// Alias for SMTP auth username/account id.
    pub smtp_username_alias: String,
    /// Alias for SMTP auth secret (password for `password`, bearer token for `oauth2`).
    pub smtp_password_alias: String,
}

/// Mail connector configuration stored in wallet.network state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailConnectorConfig {
    /// Connector provider type.
    pub provider: MailConnectorProvider,
    /// Authentication mode used for IMAP/SMTP sessions.
    pub auth_mode: MailConnectorAuthMode,
    /// Account/from email address associated with this connector.
    pub account_email: String,
    /// IMAP endpoint config for read/list/delete operations.
    pub imap: MailConnectorEndpoint,
    /// SMTP endpoint config for send/reply operations.
    pub smtp: MailConnectorEndpoint,
    /// Secret alias references for connector auth material.
    pub secret_aliases: MailConnectorSecretAliases,
    /// Optional provider-specific metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Persisted connector record bound to a logical mailbox name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailConnectorRecord {
    /// Logical mailbox name (for example: `primary`).
    pub mailbox: String,
    /// Connector configuration payload.
    pub config: MailConnectorConfig,
    /// Initial insertion timestamp.
    pub created_at_ms: u64,
    /// Last upsert timestamp.
    pub updated_at_ms: u64,
}

/// Request to insert or update a mail connector configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailConnectorUpsertParams {
    /// Logical mailbox name (defaults to `primary` when empty).
    #[serde(default)]
    pub mailbox: String,
    /// Connector configuration payload.
    pub config: MailConnectorConfig,
}

/// Request to fetch the stored mail connector configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailConnectorGetParams {
    /// Stable request identifier for replay detection.
    pub request_id: [u8; 32],
    /// Logical mailbox name (defaults to `primary` when empty).
    #[serde(default)]
    pub mailbox: String,
}

/// Persisted lookup receipt for `mail_connector_get@v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailConnectorGetReceipt {
    /// Stable request identifier.
    pub request_id: [u8; 32],
    /// Logical mailbox that was resolved.
    pub mailbox: String,
    /// Lookup execution timestamp.
    pub fetched_at_ms: u64,
    /// Snapshot of the connector record at lookup time.
    pub connector: MailConnectorRecord,
}

/// Connector-first operation request for reading the latest mail message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailReadLatestParams {
    /// Stable operation identifier for replay detection.
    pub operation_id: [u8; 32],
    /// Channel identifier carrying this operation.
    pub channel_id: [u8; 32],
    /// Lease authorizing this operation.
    pub lease_id: [u8; 32],
    /// Monotonic operation sequence within this lease context.
    pub op_seq: u64,
    /// Optional operation nonce for additional replay binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_nonce: Option<[u8; 32]>,
    /// Mailbox logical name (defaults to `primary` when empty).
    #[serde(default)]
    pub mailbox: String,
    /// Optional caller-supplied request timestamp.
    #[serde(default)]
    pub requested_at_ms: u64,
}

/// Normalized summary payload for a single mail message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailMessageSummary {
    /// Deterministic message identifier.
    pub message_id: String,
    /// Normalized sender identity.
    pub from: String,
    /// Message subject line.
    pub subject: String,
    /// Message receive/update timestamp.
    pub received_at_ms: u64,
    /// Short, sanitized preview text.
    pub preview: String,
    /// Spam-classifier confidence in basis points (0..=10000).
    #[serde(default)]
    pub spam_confidence_bps: u16,
    /// Normalized confidence band (`high|medium|low`).
    #[serde(default)]
    pub spam_confidence_band: String,
    /// Ontology signal tags contributing to classification.
    #[serde(default)]
    pub spam_signal_tags: Vec<String>,
}

/// Persisted receipt for a connector mail-read operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailReadLatestReceipt {
    /// Stable operation identifier.
    pub operation_id: [u8; 32],
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Lease identifier used for authorization.
    pub lease_id: [u8; 32],
    /// Mailbox requested.
    pub mailbox: String,
    /// Audience/signer bound to the lease.
    pub audience: [u8; 32],
    /// Execution timestamp.
    pub executed_at_ms: u64,
    /// Result summary.
    pub message: MailMessageSummary,
}

/// Connector-first operation request for listing recent mail messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailListRecentParams {
    /// Stable operation identifier for replay detection.
    pub operation_id: [u8; 32],
    /// Channel identifier carrying this operation.
    pub channel_id: [u8; 32],
    /// Lease authorizing this operation.
    pub lease_id: [u8; 32],
    /// Monotonic operation sequence within this lease context.
    pub op_seq: u64,
    /// Optional operation nonce for additional replay binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_nonce: Option<[u8; 32]>,
    /// Mailbox logical name (defaults to `primary` when empty).
    #[serde(default)]
    pub mailbox: String,
    /// Maximum number of recent messages requested.
    #[serde(default)]
    pub limit: u32,
    /// Optional caller-supplied request timestamp.
    #[serde(default)]
    pub requested_at_ms: u64,
}

/// Persisted receipt for a connector mail-list operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailListRecentReceipt {
    /// Stable operation identifier.
    pub operation_id: [u8; 32],
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Lease identifier used for authorization.
    pub lease_id: [u8; 32],
    /// Mailbox requested.
    pub mailbox: String,
    /// Audience/signer bound to the lease.
    pub audience: [u8; 32],
    /// Execution timestamp.
    pub executed_at_ms: u64,
    /// Result summaries ordered from most recent to older.
    #[serde(default)]
    pub messages: Vec<MailMessageSummary>,
    /// Effective requested limit after normalization.
    #[serde(default)]
    pub requested_limit: u32,
    /// Number of messages evaluated for this list operation.
    #[serde(default)]
    pub evaluated_count: u32,
    /// Number of parse failures tolerated while collecting the list.
    #[serde(default)]
    pub parse_error_count: u32,
    /// Parse-confidence score in basis points (0..=10000).
    #[serde(default)]
    pub parse_confidence_bps: u16,
    /// Parse volume band (`small|medium|large`).
    #[serde(default)]
    pub parse_volume_band: String,
    /// Absolute mailbox message count at execution time.
    #[serde(default)]
    pub mailbox_total_count: u32,
    /// Ontology signal version used for parse metadata.
    #[serde(default)]
    pub ontology_version: String,
}

/// Connector-first operation request for retrieving absolute mailbox total count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailboxTotalCountParams {
    /// Stable operation identifier for replay detection.
    pub operation_id: [u8; 32],
    /// Channel identifier carrying this operation.
    pub channel_id: [u8; 32],
    /// Lease authorizing this operation.
    pub lease_id: [u8; 32],
    /// Monotonic operation sequence within this lease context.
    pub op_seq: u64,
    /// Optional operation nonce for additional replay binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_nonce: Option<[u8; 32]>,
    /// Mailbox logical name (defaults to `primary` when empty).
    #[serde(default)]
    pub mailbox: String,
    /// Optional caller-supplied request timestamp.
    #[serde(default)]
    pub requested_at_ms: u64,
}

/// Raw provenance for a mailbox-total-count observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct MailboxTotalCountProvenance {
    /// IMAP STATUS(MESSAGES) observation when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_exists: Option<u32>,
    /// IMAP SELECT-reported message count when mailbox selection succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub select_exists: Option<u32>,
    /// Count derived from UID SEARCH ALL when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_search_count: Option<u32>,
    /// Count derived from SEARCH ALL when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_count: Option<u32>,
    /// Freshness marker describing how authoritative the reported count is.
    #[serde(default)]
    pub freshness_marker: String,
}

/// Persisted receipt for a connector mailbox-total-count operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailboxTotalCountReceipt {
    /// Stable operation identifier.
    pub operation_id: [u8; 32],
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Lease identifier used for authorization.
    pub lease_id: [u8; 32],
    /// Mailbox requested.
    pub mailbox: String,
    /// Audience/signer bound to the lease.
    pub audience: [u8; 32],
    /// Execution timestamp.
    pub executed_at_ms: u64,
    /// Absolute mailbox message count at execution time.
    pub mailbox_total_count: u32,
    /// Provenance details for the reported mailbox count.
    #[serde(default)]
    pub provenance: MailboxTotalCountProvenance,
}

/// Connector-first operation request for deleting high-confidence unwanted mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailDeleteSpamParams {
    /// Stable operation identifier for replay detection.
    pub operation_id: [u8; 32],
    /// Channel identifier carrying this operation.
    pub channel_id: [u8; 32],
    /// Lease authorizing this operation.
    pub lease_id: [u8; 32],
    /// Monotonic operation sequence within this lease context.
    pub op_seq: u64,
    /// Optional operation nonce for additional replay binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_nonce: Option<[u8; 32]>,
    /// Mailbox logical name (`primary`/`inbox` or spam-like mailbox; defaults to `primary` when empty).
    #[serde(default)]
    pub mailbox: String,
    /// Maximum number of high-confidence unwanted messages to delete.
    #[serde(default)]
    pub max_delete: u32,
    /// Optional caller-supplied request timestamp.
    #[serde(default)]
    pub requested_at_ms: u64,
}

/// Persisted receipt for a connector mail-delete operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailDeleteSpamReceipt {
    /// Stable operation identifier.
    pub operation_id: [u8; 32],
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Lease identifier used for authorization.
    pub lease_id: [u8; 32],
    /// Mailbox requested.
    pub mailbox: String,
    /// Audience/signer bound to the lease.
    pub audience: [u8; 32],
    /// Execution timestamp.
    pub executed_at_ms: u64,
    /// Number of high-confidence unwanted messages deleted.
    pub deleted_count: u32,
    /// Number of candidate messages evaluated for spam confidence.
    #[serde(default)]
    pub evaluated_count: u32,
    /// Count deleted under high-confidence spam policy.
    #[serde(default)]
    pub high_confidence_deleted_count: u32,
    /// Count skipped because confidence did not reach threshold.
    #[serde(default)]
    pub skipped_low_confidence_count: u32,
    /// Absolute mailbox message count immediately before delete execution.
    #[serde(default)]
    pub mailbox_total_count_before: u32,
    /// Absolute mailbox message count immediately after delete execution.
    #[serde(default)]
    pub mailbox_total_count_after: u32,
    /// Absolute mailbox reduction derived from before/after counts.
    #[serde(default)]
    pub mailbox_total_count_delta: u32,
    /// Applied spam confidence threshold in basis points.
    #[serde(default)]
    pub spam_confidence_threshold_bps: u16,
    /// Ontology signal version used for spam classification.
    #[serde(default)]
    pub ontology_version: String,
    /// Cleanup scope used by the provider (`spam_mailbox` or `primary_inbox`).
    #[serde(default)]
    pub cleanup_scope: String,
    /// Messages preserved due to transactional or personal-safe evidence.
    #[serde(default)]
    pub preserved_transactional_or_personal_count: u32,
    /// Messages preserved due to trusted system-sender evidence.
    #[serde(default)]
    pub preserved_trusted_system_count: u32,
    /// Messages preserved due to low confidence without stronger preserve signals.
    #[serde(default)]
    pub preserved_low_confidence_other_count: u32,
    /// High-confidence candidates not deleted due to max-delete cap.
    #[serde(default)]
    pub preserved_due_to_delete_cap_count: u32,
    /// Explicit preserved-reason breakdown used for auditing.
    #[serde(default)]
    pub preserved_reason_counts: BTreeMap<String, u32>,
}

/// Connector-first operation request for sending a reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailReplyParams {
    /// Stable operation identifier for replay detection.
    pub operation_id: [u8; 32],
    /// Channel identifier carrying this operation.
    pub channel_id: [u8; 32],
    /// Lease authorizing this operation.
    pub lease_id: [u8; 32],
    /// Monotonic operation sequence within this lease context.
    pub op_seq: u64,
    /// Optional operation nonce for additional replay binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_nonce: Option<[u8; 32]>,
    /// Mailbox logical name (defaults to `primary` when empty).
    #[serde(default)]
    pub mailbox: String,
    /// Recipient mailbox/address.
    pub to: String,
    /// Reply subject line.
    pub subject: String,
    /// Reply body text.
    pub body: String,
    /// Optional message id being replied to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
    /// Optional caller-supplied request timestamp.
    #[serde(default)]
    pub requested_at_ms: u64,
}

/// Persisted receipt for a connector mail-reply operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct MailReplyReceipt {
    /// Stable operation identifier.
    pub operation_id: [u8; 32],
    /// Channel identifier.
    pub channel_id: [u8; 32],
    /// Lease identifier used for authorization.
    pub lease_id: [u8; 32],
    /// Mailbox requested.
    pub mailbox: String,
    /// Audience/signer bound to the lease.
    pub audience: [u8; 32],
    /// Execution timestamp.
    pub executed_at_ms: u64,
    /// Recipient mailbox/address.
    pub to: String,
    /// Reply subject line.
    pub subject: String,
    /// Deterministic id of the sent reply message.
    pub sent_message_id: String,
}
