use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailboxTotalCountProvenance,
};
use ioi_types::error::TransactionError;

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
