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
