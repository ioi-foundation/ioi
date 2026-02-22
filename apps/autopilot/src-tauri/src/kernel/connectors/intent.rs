use ioi_types::app::ActionTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MailIntentKind {
    ReadLatest,
    ListRecent,
    DeleteSpam,
    Reply,
    Unknown,
}

impl MailIntentKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReadLatest => "mail.read_latest",
            Self::ListRecent => "mail.list_recent",
            Self::DeleteSpam => "mail.delete_spam",
            Self::Reply => "mail.reply",
            Self::Unknown => "mail.unknown",
        }
    }

    pub(crate) fn requires_step_up_approval(self) -> bool {
        matches!(self, Self::DeleteSpam | Self::Reply)
    }

    pub(crate) fn action_target(self) -> ActionTarget {
        match self {
            Self::ReadLatest => ActionTarget::Custom("mail::read_latest".to_string()),
            Self::ListRecent => ActionTarget::Custom("mail::list_recent".to_string()),
            Self::DeleteSpam => ActionTarget::Custom("mail::delete_spam".to_string()),
            Self::Reply => ActionTarget::Custom("mail::reply".to_string()),
            Self::Unknown => ActionTarget::Custom("mail::unknown".to_string()),
        }
    }
}

pub(crate) fn classify_mail_intent(query: &str) -> MailIntentKind {
    let q = query.to_ascii_lowercase();

    let is_delete = q.contains("delete") || q.contains("remove") || q.contains("trash");
    let is_spam = q.contains("spam") || q.contains("junk");
    if is_delete && is_spam {
        return MailIntentKind::DeleteSpam;
    }

    if q.contains("reply") || q.contains("respond to") || q.contains("email bob") {
        return MailIntentKind::Reply;
    }

    if q.contains("latest")
        || q.contains("last email")
        || q.contains("read latest")
        || q.contains("most recent")
    {
        return MailIntentKind::ReadLatest;
    }

    if q.contains("inbox")
        || q.contains("list")
        || q.contains("recent email")
        || q.contains("recent messages")
        || q.contains("check mail")
    {
        return MailIntentKind::ListRecent;
    }

    MailIntentKind::Unknown
}

pub(crate) fn extract_reply_target(query: &str) -> String {
    let lowered = query.to_ascii_lowercase();
    if let Some(idx) = lowered.find("reply to ") {
        let tail = query[idx + 9..].trim();
        if !tail.is_empty() {
            return tail
                .split_whitespace()
                .next()
                .unwrap_or("recipient")
                .to_string();
        }
    }
    if let Some(idx) = lowered.find("respond to ") {
        let tail = query[idx + 11..].trim();
        if !tail.is_empty() {
            return tail
                .split_whitespace()
                .next()
                .unwrap_or("recipient")
                .to_string();
        }
    }
    "recipient".to_string()
}
