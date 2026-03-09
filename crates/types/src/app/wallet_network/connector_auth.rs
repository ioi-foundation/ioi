use super::{MailConnectorRecord, VaultPolicyRule, VaultSecretRecord};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Durable connector auth protocol managed by wallet.network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorAuthProtocol {
    /// Username plus password/app-password style authentication.
    StaticPassword,
    /// Short-lived bearer token only.
    OAuth2Bearer,
    /// Refreshable OAuth2 credential set.
    OAuth2Refresh,
    /// API key style credential.
    ApiKey,
    /// Provider-specific auth mechanism.
    Custom(String),
}

/// Durable auth state for a connector integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorAuthState {
    /// Durable credentials are available and usable.
    Connected,
    /// The connector exists but requires user authentication.
    NeedsAuth,
    /// Durable credentials exist but are known expired.
    Expired,
    /// Durable credentials were explicitly revoked.
    Revoked,
    /// Durable credentials exist but require operator attention.
    Degraded,
}

/// Canonical auth record for a connector/provider binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthRecord {
    /// Stable connector id (for example: `google.workspace` or `mail.primary`).
    pub connector_id: String,
    /// Provider family namespace (for example: `google.workspace` or `mail.wallet_network`).
    pub provider_family: String,
    /// Durable auth protocol.
    pub auth_protocol: ConnectorAuthProtocol,
    /// Current durable auth state.
    pub state: ConnectorAuthState,
    /// Optional human-readable account label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    /// Optional logical mailbox binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
    /// Granted/known scopes for the provider session.
    #[serde(default)]
    pub granted_scopes: Vec<String>,
    /// Secret aliases used by this connector auth record.
    #[serde(default)]
    pub credential_aliases: BTreeMap<String, String>,
    /// Provider-specific metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// First creation timestamp.
    pub created_at_ms: u64,
    /// Last update timestamp.
    pub updated_at_ms: u64,
    /// Optional provider/session expiry for the durable credential set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// Optional last validation/refresh timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_validated_at_ms: Option<u64>,
}

/// Request to insert or update a connector auth record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthUpsertParams {
    /// Canonical auth record to insert or update.
    pub record: ConnectorAuthRecord,
}

/// Request to fetch a connector auth record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthGetParams {
    /// Stable request identifier for replay protection.
    pub request_id: [u8; 32],
    /// Connector id to fetch.
    pub connector_id: String,
}

/// Persisted connector auth lookup receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthGetReceipt {
    /// Stable request identifier.
    pub request_id: [u8; 32],
    /// Connector id that was fetched.
    pub connector_id: String,
    /// Lookup execution timestamp.
    pub fetched_at_ms: u64,
    /// Snapshot of the fetched connector auth record.
    pub record: ConnectorAuthRecord,
}

/// Request to list connector auth records, optionally filtered by provider family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthListParams {
    /// Stable request identifier for replay protection.
    pub request_id: [u8; 32],
    /// Optional provider family filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_family: Option<String>,
}

/// Persisted connector auth list receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthListReceipt {
    /// Stable request identifier.
    pub request_id: [u8; 32],
    /// Listing execution timestamp.
    pub listed_at_ms: u64,
    /// Returned connector auth records.
    #[serde(default)]
    pub records: Vec<ConnectorAuthRecord>,
}

/// Portable wallet auth bundle for backup/import-export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthExportBundle {
    /// Bundle format version.
    pub version: u32,
    /// Bundle creation timestamp.
    pub exported_at_ms: u64,
    /// Exported connector auth records.
    #[serde(default)]
    pub connector_auth_records: Vec<ConnectorAuthRecord>,
    /// Exported mail connector records.
    #[serde(default)]
    pub mail_connectors: Vec<MailConnectorRecord>,
    /// Exported wallet policy rules.
    #[serde(default)]
    pub policy_rules: Vec<VaultPolicyRule>,
    /// Exported secret records.
    #[serde(default)]
    pub secret_records: Vec<VaultSecretRecord>,
}

/// Request to export connector auth records and their dependent artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthExportParams {
    /// Stable request identifier for replay protection.
    pub request_id: [u8; 32],
    /// Optional explicit connector id allowlist; empty exports all records.
    #[serde(default)]
    pub connector_ids: Vec<String>,
    /// Passphrase used to wrap the export bundle.
    pub passphrase: String,
}

/// Persisted export receipt containing the encrypted portable bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthExportReceipt {
    /// Stable request identifier.
    pub request_id: [u8; 32],
    /// Export execution timestamp.
    pub exported_at_ms: u64,
    /// Connector ids included in the bundle.
    #[serde(default)]
    pub connector_ids: Vec<String>,
    /// Encrypted portable bundle bytes.
    pub encrypted_bundle: Vec<u8>,
}

/// Request to import an encrypted connector auth bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthImportParams {
    /// Stable request identifier for replay protection.
    pub request_id: [u8; 32],
    /// Encrypted portable bundle bytes.
    pub encrypted_bundle: Vec<u8>,
    /// Passphrase used to unwrap the bundle.
    pub passphrase: String,
    /// Whether existing records may be replaced.
    #[serde(default)]
    pub replace_existing: bool,
}

/// Persisted import receipt summarizing restored artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ConnectorAuthImportReceipt {
    /// Stable request identifier.
    pub request_id: [u8; 32],
    /// Import execution timestamp.
    pub imported_at_ms: u64,
    /// Imported connector ids.
    #[serde(default)]
    pub connector_ids: Vec<String>,
    /// Imported secret ids.
    #[serde(default)]
    pub secret_ids: Vec<String>,
    /// Imported policy rule ids.
    #[serde(default)]
    pub policy_rule_ids: Vec<String>,
    /// Imported mailboxes.
    #[serde(default)]
    pub mailboxes: Vec<String>,
}
