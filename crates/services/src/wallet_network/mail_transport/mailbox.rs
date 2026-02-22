use super::constants::{
    PRIMARY_UNWANTED_PROMOTION_MIN_RISK_TAGS, PRIMARY_UNWANTED_PROMOTION_MIN_SCORE_BPS,
    SPAM_REMOTE_MAILBOX_CANDIDATES,
};
use crate::wallet_network::mail_ontology::MailSpamClassification;
use ioi_types::error::TransactionError;
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CleanupMailboxScope {
    SpamMailbox,
    PrimaryInbox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreservationBucket {
    TransactionalOrPersonal,
    TrustedSystemSender,
    LowConfidenceOther,
}

pub(super) fn normalize_remote_mailbox_name(mailbox: &str) -> String {
    if mailbox.eq_ignore_ascii_case("primary") {
        return "INBOX".to_string();
    }
    if mailbox.eq_ignore_ascii_case("spam") {
        return "Spam".to_string();
    }
    if mailbox.eq_ignore_ascii_case("junk") || mailbox.eq_ignore_ascii_case("junkemail") {
        return "Junk".to_string();
    }
    if mailbox.eq_ignore_ascii_case("bulk") {
        return "Bulk".to_string();
    }
    if mailbox.eq_ignore_ascii_case("trash") {
        return "Trash".to_string();
    }
    mailbox.to_string()
}

pub(super) fn is_spam_mailbox_name(mailbox: &str) -> bool {
    mailbox.eq_ignore_ascii_case("spam")
        || mailbox.eq_ignore_ascii_case("junk")
        || mailbox.eq_ignore_ascii_case("junkemail")
        || mailbox.eq_ignore_ascii_case("bulk")
        || mailbox.eq_ignore_ascii_case("trash")
}

pub(super) fn is_primary_mailbox_name(mailbox: &str) -> bool {
    mailbox.eq_ignore_ascii_case("primary") || mailbox.eq_ignore_ascii_case("inbox")
}

pub(super) fn cleanup_scope_from_mailbox(mailbox: &str) -> CleanupMailboxScope {
    if is_primary_mailbox_name(mailbox) {
        CleanupMailboxScope::PrimaryInbox
    } else {
        CleanupMailboxScope::SpamMailbox
    }
}

pub(super) fn cleanup_scope_label(scope: CleanupMailboxScope) -> &'static str {
    match scope {
        CleanupMailboxScope::SpamMailbox => "spam_mailbox",
        CleanupMailboxScope::PrimaryInbox => "primary_inbox",
    }
}

pub(super) fn preservation_bucket_from_signal_tags(signal_tags: &[String]) -> PreservationBucket {
    let has_transactional_or_personal = signal_tags.iter().any(|tag| {
        tag.starts_with("signal_transactional_")
            || tag == "signal_safe_thread_markers"
            || tag == "signal_safe_personal_markers"
            || tag == "signal_preservation_override"
    });
    if has_transactional_or_personal {
        return PreservationBucket::TransactionalOrPersonal;
    }
    if signal_tags
        .iter()
        .any(|tag| tag == "signal_trusted_system_sender")
    {
        return PreservationBucket::TrustedSystemSender;
    }
    PreservationBucket::LowConfidenceOther
}

pub(super) fn is_transactional_or_personal_signal(tag: &str) -> bool {
    tag.starts_with("signal_transactional_")
        || tag == "signal_safe_thread_markers"
        || tag == "signal_safe_personal_markers"
        || tag == "signal_preservation_override"
}

pub(super) fn is_trusted_system_signal(tag: &str) -> bool {
    tag == "signal_trusted_system_sender"
}

fn is_primary_unwanted_risk_signal(tag: &str) -> bool {
    matches!(
        tag,
        "signal_sender_risk_markers"
            | "signal_subject_risk_markers"
            | "signal_content_risk_markers"
            | "signal_sender_marketing_markers"
            | "signal_subject_marketing_markers"
            | "signal_content_marketing_markers"
            | "signal_bulk_distribution_footer"
            | "signal_marketing_footer_pattern"
            | "signal_percentage_discount_pattern"
            | "signal_marketing_bulk_composite"
            | "signal_list_header_bulk_pattern"
            | "signal_primary_unwanted_context_floor"
            | "signal_urgency_punctuation"
            | "signal_uppercase_urgency"
    )
}

fn is_primary_unwanted_structural_signal(tag: &str) -> bool {
    matches!(
        tag,
        "signal_sender_marketing_markers"
            | "signal_subject_marketing_markers"
            | "signal_content_marketing_markers"
            | "signal_bulk_distribution_footer"
            | "signal_marketing_footer_pattern"
            | "signal_percentage_discount_pattern"
            | "signal_marketing_bulk_composite"
            | "signal_list_header_bulk_pattern"
            | "signal_primary_unwanted_context_floor"
    )
}

pub(super) fn is_primary_unwanted_promotion_candidate(
    classification: &MailSpamClassification,
) -> bool {
    if classification.confidence_bps < PRIMARY_UNWANTED_PROMOTION_MIN_SCORE_BPS {
        return false;
    }

    let mut risk_tag_count = 0usize;
    let mut structural_signal = false;
    let mut preserve_signal = false;
    for tag in &classification.signal_tags {
        if is_primary_unwanted_risk_signal(tag) {
            risk_tag_count = risk_tag_count.saturating_add(1);
        }
        if is_primary_unwanted_structural_signal(tag) {
            structural_signal = true;
        }
        if is_transactional_or_personal_signal(tag) || is_trusted_system_signal(tag) {
            preserve_signal = true;
        }
    }

    !preserve_signal
        && structural_signal
        && risk_tag_count >= PRIMARY_UNWANTED_PROMOTION_MIN_RISK_TAGS
}

fn canonical_mailbox_name(mailbox: &str) -> String {
    mailbox
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn is_spam_like_remote_mailbox(mailbox: &str) -> bool {
    let canonical = canonical_mailbox_name(mailbox);
    canonical.contains("spam")
        || canonical.contains("junk")
        || canonical.contains("bulk")
        || canonical.contains("trash")
}

pub(super) fn select_remote_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
) -> Result<u32, TransactionError> {
    let selected = session.select(mailbox).map_err(|e| {
        TransactionError::Invalid(format!("imap select '{}' failed: {}", mailbox, e))
    })?;
    Ok(selected.exists)
}

pub(super) fn resolve_remote_spam_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    requested_mailbox: &str,
) -> Result<(String, u32), TransactionError> {
    if let Ok(total_count) = select_remote_mailbox(session, requested_mailbox) {
        return Ok((requested_mailbox.to_string(), total_count));
    }

    let requested_canonical = canonical_mailbox_name(requested_mailbox);
    let mut discovered = Vec::new();
    if let Ok(names) = session.list(None, Some("*")) {
        for name in names.iter() {
            let candidate = name.name().trim();
            if !candidate.is_empty() {
                discovered.push(candidate.to_string());
            }
        }
    }

    for candidate in &discovered {
        if canonical_mailbox_name(candidate) == requested_canonical {
            if let Ok(total_count) = select_remote_mailbox(session, candidate) {
                return Ok((candidate.clone(), total_count));
            }
        }
    }

    for candidate in &discovered {
        if is_spam_like_remote_mailbox(candidate) {
            if let Ok(total_count) = select_remote_mailbox(session, candidate) {
                return Ok((candidate.clone(), total_count));
            }
        }
    }

    for candidate in SPAM_REMOTE_MAILBOX_CANDIDATES {
        if let Ok(total_count) = select_remote_mailbox(session, candidate) {
            return Ok((candidate.to_string(), total_count));
        }
    }

    let mut known_targets: Vec<String> = discovered
        .into_iter()
        .filter(|name| is_spam_like_remote_mailbox(name))
        .collect();
    known_targets.sort();
    known_targets.dedup();
    let known = if known_targets.is_empty() {
        "none discovered".to_string()
    } else {
        known_targets.join(", ")
    };
    Err(TransactionError::Invalid(format!(
        "imap select '{}' failed and no spam/junk mailbox alias resolved; discovered candidates: {}",
        requested_mailbox, known
    )))
}

pub(super) fn resolve_remote_primary_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    requested_mailbox: &str,
) -> Result<(String, u32), TransactionError> {
    if let Ok(total_count) = select_remote_mailbox(session, requested_mailbox) {
        return Ok((requested_mailbox.to_string(), total_count));
    }
    for candidate in ["INBOX", "Inbox", "inbox"] {
        if let Ok(total_count) = select_remote_mailbox(session, candidate) {
            return Ok((candidate.to_string(), total_count));
        }
    }
    Err(TransactionError::Invalid(format!(
        "imap select '{}' failed and no primary inbox alias resolved",
        requested_mailbox
    )))
}
