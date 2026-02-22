pub(super) const MAIL_SUBJECT_MAX_LEN: usize = 256;
pub(super) const MAIL_FROM_MAX_LEN: usize = 256;
pub(super) const MAIL_PREVIEW_MAX_LEN: usize = 512;
pub(super) const IMAP_FETCH_ATTRS_TEXT: &str = "(UID ENVELOPE INTERNALDATE BODY.PEEK[TEXT])";
pub(super) const IMAP_FETCH_ATTRS_FULL_BODY: &str = "(UID ENVELOPE INTERNALDATE BODY.PEEK[])";
pub(super) const IMAP_FETCH_ATTRS_META_ONLY: &str = "(UID ENVELOPE INTERNALDATE)";
pub(super) const IMAP_LIST_FETCH_BATCH_SIZE: usize = 48;
pub(super) const MAIL_DELETE_SPAM_EVALUATION_MULTIPLIER: usize = 3;
pub(super) const MAIL_DELETE_SPAM_MAX_EVALUATED: usize = 900;
pub(super) const PRIMARY_UNWANTED_PROMOTION_MIN_SCORE_BPS: u16 = 5_000;
pub(super) const PRIMARY_UNWANTED_PROMOTION_MIN_RISK_TAGS: usize = 2;
pub(super) const PRIMARY_UNWANTED_BULK_PROMOTION_MIN_RATIO_BPS: u32 = 8_500;
pub(super) const PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_MIN_RATIO_BPS: u32 = 7_000;
pub(super) const PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_SCORE_DELTA_BPS: u16 = 1_500;
pub(super) const MAILBOX_COUNT_FRESHNESS_STATUS_FRESH: &str = "status_exists_fresh";
pub(super) const MAILBOX_COUNT_FRESHNESS_STATUS_RECONCILED: &str = "status_exists_reconciled";
pub(super) const MAILBOX_COUNT_FRESHNESS_FALLBACK_NO_STATUS: &str = "fallback_no_status";
pub(super) const MAILBOX_COUNT_FRESHNESS_FALLBACK_STATUS_ZERO: &str = "fallback_status_zero";
pub(super) const SPAM_REMOTE_MAILBOX_CANDIDATES: [&str; 12] = [
    "Spam",
    "Junk",
    "Junk Email",
    "Junk E-mail",
    "Bulk",
    "Bulk Mail",
    "INBOX.Spam",
    "INBOX.Junk",
    "[Gmail]/Spam",
    "[Google Mail]/Spam",
    "JunkE-mail",
    "JunkE-Mail",
];
