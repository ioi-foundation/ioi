use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailMessageView {
    pub message_id: String,
    pub from: String,
    pub subject: String,
    pub received_at_ms: u64,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailReadLatestResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub message: WalletMailMessageView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailListRecentResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub messages: Vec<WalletMailMessageView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailDeleteSpamResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub deleted_count: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailReplyResult {
    pub operation_id_hex: String,
    pub channel_id_hex: String,
    pub lease_id_hex: String,
    pub mailbox: String,
    pub audience_hex: String,
    pub executed_at_ms: u64,
    pub to: String,
    pub subject: String,
    pub sent_message_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMailConfigureAccountResult {
    pub mailbox: String,
    pub account_email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_display_name: Option<String>,
    pub auth_mode: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_tls_mode: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_tls_mode: String,
    pub imap_username_alias: String,
    pub imap_secret_alias: String,
    pub smtp_username_alias: String,
    pub smtp_secret_alias: String,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletConnectorAuthRecordView {
    pub connector_id: String,
    pub provider_family: String,
    pub auth_protocol: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
    pub granted_scopes: Vec<String>,
    pub credential_aliases: std::collections::BTreeMap<String, String>,
    pub metadata: std::collections::BTreeMap<String, String>,
    pub updated_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_validated_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletConnectorAuthGetResult {
    pub fetched_at_ms: u64,
    pub record: WalletConnectorAuthRecordView,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletConnectorAuthListResult {
    pub listed_at_ms: u64,
    pub records: Vec<WalletConnectorAuthRecordView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletConnectorAuthExportResult {
    pub request_id_hex: String,
    pub exported_at_ms: u64,
    pub connector_ids: Vec<String>,
    pub bundle_base64: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletConnectorAuthImportResult {
    pub request_id_hex: String,
    pub imported_at_ms: u64,
    pub connector_ids: Vec<String>,
    pub secret_ids: Vec<String>,
    pub policy_rule_ids: Vec<String>,
    pub mailboxes: Vec<String>,
}
