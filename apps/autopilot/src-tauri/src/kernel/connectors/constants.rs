pub(crate) const MAIL_READ_RECEIPT_PREFIX: &[u8] = b"mail_read_receipt::";
pub(crate) const MAIL_LIST_RECEIPT_PREFIX: &[u8] = b"mail_list_receipt::";
pub(crate) const MAIL_DELETE_RECEIPT_PREFIX: &[u8] = b"mail_delete_receipt::";
pub(crate) const MAIL_REPLY_RECEIPT_PREFIX: &[u8] = b"mail_reply_receipt::";

pub(crate) const MAIL_DELETE_SPAM_DEFAULT_LIMIT: u32 = 25;
pub(crate) const MAIL_DELETE_SPAM_MAX_LIMIT: u32 = 500;

pub(crate) const MAIL_APPROVAL_DEFAULT_TTL_SECONDS: u64 = 300;
pub(crate) const MAIL_APPROVAL_MAX_TTL_SECONDS: u64 = 3_600;

pub(crate) const MAIL_CONNECTOR_DEFAULT_MAILBOX: &str = "primary";
pub(crate) const MAIL_CONNECTOR_SECRET_ID_PREFIX: &str = "autopilot-mail";
pub(crate) const MAIL_CONNECTOR_ALIAS_MAX_LEN: usize = 128;
