// Path: crates/services/src/wallet_network/mail_ontology.rs

pub(crate) const MAIL_ONTOLOGY_SIGNAL_VERSION: &str = "mail_ontology_v1";
pub(crate) const SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS: u16 = 8_500;
pub(crate) const SPAM_MEDIUM_CONFIDENCE_THRESHOLD_BPS: u16 = 6_500;
pub(crate) const LARGE_VOLUME_MESSAGE_THRESHOLD: usize = 64;
pub(crate) const MEDIUM_VOLUME_MESSAGE_THRESHOLD: usize = 24;

// Spam/junk folders are pre-filtered by provider-side classifiers; raise prior so
// one additional reusable risk signal can cross high-confidence delete threshold.
const MAILBOX_SPAM_PRIOR_BPS: i32 = 7_600;
const MAILBOX_PRIMARY_PRIOR_BPS: i32 = 1_100;
const SCORE_FLOOR_BPS: i32 = 0;
const SCORE_CEIL_BPS: i32 = 10_000;
const MAX_SIGNAL_TAGS: usize = 8;

const SPAM_SENDER_RISK_MARKERS: [&str; 18] = [
    "no-reply",
    "noreply",
    "do-not-reply",
    "donotreply",
    "mailer-daemon",
    "support-team",
    "alert-center",
    "security-team",
    "admin-update",
    "service-team",
    "alert-team",
    "security-alert",
    "verification",
    "promo",
    "offers",
    "deal",
    "lottery",
    "sweepstake",
];

const SPAM_SUBJECT_RISK_MARKERS: [&str; 30] = [
    "urgent action required",
    "verify your account",
    "account suspended",
    "account locked",
    "payment failed",
    "invoice attached",
    "final warning",
    "claim your reward",
    "you have won",
    "winner",
    "limited time",
    "exclusive offer",
    "congratulations",
    "act now",
    "crypto",
    "bitcoin",
    "gift card",
    "wire transfer",
    "banking alert",
    "delivery failed",
    "password reset",
    "security alert",
    "suspicious activity",
    "confirm identity",
    "account suspension",
    "free trial",
    "refund pending",
    "tax refund",
    "investment opportunity",
    "risk free",
];

const SPAM_CONTENT_RISK_MARKERS: [&str; 22] = [
    "click here",
    "open attachment",
    "verify now",
    "confirm now",
    "login now",
    "update payment",
    "provide your password",
    "enter your code",
    "identity verification",
    "immediate action",
    "your account will be closed",
    "expires today",
    "respond within 24 hours",
    "reset your password",
    "wire now",
    "payment required",
    "send gift cards",
    "unusual sign in",
    "fraud alert",
    "secure message",
    "claim now",
    "unsubscribe",
];

const SAFE_THREAD_MARKERS: [&str; 18] = [
    "re:",
    "fwd:",
    "follow up",
    "following up",
    "meeting",
    "agenda",
    "notes",
    "minutes",
    "project update",
    "status update",
    "schedule",
    "calendar",
    "receipt",
    "statement",
    "invoice #",
    "order #",
    "tracking number",
    "shipping update",
];

const SAFE_PERSONAL_MARKERS: [&str; 10] = [
    "thanks",
    "thank you",
    "let me know",
    "see you",
    "tomorrow",
    "next week",
    "quick question",
    "attached is",
    "per our conversation",
    "as discussed",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MailSpamClassification {
    pub confidence_bps: u16,
    pub confidence_band: &'static str,
    pub signal_tags: Vec<String>,
}

fn marker_hits(text: &str, markers: &[&str]) -> usize {
    markers.iter().filter(|marker| text.contains(**marker)).count()
}

fn push_tag(tags: &mut Vec<String>, tag: &str) {
    if tags.len() >= MAX_SIGNAL_TAGS {
        return;
    }
    if tags.iter().any(|existing| existing == tag) {
        return;
    }
    tags.push(tag.to_string());
}

fn clamp_score_bps(score: i32) -> u16 {
    score.clamp(SCORE_FLOOR_BPS, SCORE_CEIL_BPS) as u16
}

fn mailbox_spam_prior(mailbox: &str) -> bool {
    matches!(
        mailbox.trim().to_ascii_lowercase().as_str(),
        "spam" | "junk" | "junkemail" | "bulk" | "trash"
    )
}

pub(crate) fn spam_confidence_band(score_bps: u16) -> &'static str {
    if score_bps >= SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS {
        "high"
    } else if score_bps >= SPAM_MEDIUM_CONFIDENCE_THRESHOLD_BPS {
        "medium"
    } else {
        "low"
    }
}

pub(crate) fn is_high_confidence_spam(score_bps: u16) -> bool {
    score_bps >= SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS
}

pub(crate) fn classify_mail_spam(
    mailbox: &str,
    from: &str,
    subject: &str,
    preview: &str,
) -> MailSpamClassification {
    let from_lc = from.trim().to_ascii_lowercase();
    let subject_lc = subject.trim().to_ascii_lowercase();
    let preview_lc = preview.trim().to_ascii_lowercase();
    let combined = format!(" {} {} {} ", from_lc, subject_lc, preview_lc);
    let mut score = if mailbox_spam_prior(mailbox) {
        MAILBOX_SPAM_PRIOR_BPS
    } else {
        MAILBOX_PRIMARY_PRIOR_BPS
    };
    let mut tags = Vec::new();
    if mailbox_spam_prior(mailbox) {
        push_tag(&mut tags, "signal_mailbox_spam_prior");
    } else {
        push_tag(&mut tags, "signal_mailbox_primary_prior");
    }

    let sender_risk_hits = marker_hits(&from_lc, &SPAM_SENDER_RISK_MARKERS);
    if sender_risk_hits > 0 {
        score += (sender_risk_hits.min(3) as i32) * 850;
        push_tag(&mut tags, "signal_sender_risk_markers");
    }

    let subject_risk_hits = marker_hits(&combined, &SPAM_SUBJECT_RISK_MARKERS);
    if subject_risk_hits > 0 {
        score += (subject_risk_hits.min(4) as i32) * 900;
        push_tag(&mut tags, "signal_subject_risk_markers");
    }

    let content_risk_hits = marker_hits(&combined, &SPAM_CONTENT_RISK_MARKERS);
    if content_risk_hits > 0 {
        score += (content_risk_hits.min(4) as i32) * 700;
        push_tag(&mut tags, "signal_content_risk_markers");
    }

    let exclamation_hits = combined.matches('!').count();
    if exclamation_hits >= 3 {
        score += 500;
        push_tag(&mut tags, "signal_urgency_punctuation");
    }

    let uppercase_chars = subject.chars().filter(|ch| ch.is_ascii_uppercase()).count();
    let subject_chars = subject.chars().count().max(1);
    if uppercase_chars * 10 >= subject_chars * 6 && subject_chars >= 12 {
        score += 400;
        push_tag(&mut tags, "signal_uppercase_urgency");
    }

    let safe_thread_hits = marker_hits(&combined, &SAFE_THREAD_MARKERS);
    if safe_thread_hits > 0 {
        score -= (safe_thread_hits.min(3) as i32) * 1_000;
        push_tag(&mut tags, "signal_safe_thread_markers");
    }

    let safe_personal_hits = marker_hits(&combined, &SAFE_PERSONAL_MARKERS);
    if safe_personal_hits > 0 {
        score -= (safe_personal_hits.min(3) as i32) * 700;
        push_tag(&mut tags, "signal_safe_personal_markers");
    }

    if from_lc.contains("@calendar.") || from_lc.contains("@notifications.") {
        score -= 900;
        push_tag(&mut tags, "signal_trusted_system_sender");
    }

    if mailbox_spam_prior(mailbox) && score < SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS as i32 {
        score = SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS as i32;
        push_tag(&mut tags, "signal_spam_mailbox_confidence_floor");
    }

    let confidence_bps = clamp_score_bps(score);
    let confidence_band = spam_confidence_band(confidence_bps);
    MailSpamClassification {
        confidence_bps,
        confidence_band,
        signal_tags: tags,
    }
}

pub(crate) fn parse_volume_band(message_count: usize) -> &'static str {
    if message_count >= LARGE_VOLUME_MESSAGE_THRESHOLD {
        "large"
    } else if message_count >= MEDIUM_VOLUME_MESSAGE_THRESHOLD {
        "medium"
    } else {
        "small"
    }
}

pub(crate) fn parse_confidence_band(score_bps: u16) -> &'static str {
    if score_bps >= 8_500 {
        "high"
    } else if score_bps >= 6_500 {
        "medium"
    } else {
        "low"
    }
}

pub(crate) fn estimate_parse_confidence_bps(
    requested_limit: usize,
    evaluated_count: usize,
    parsed_count: usize,
    parse_error_count: usize,
) -> u16 {
    if evaluated_count == 0 {
        return 10_000;
    }
    let denominator = evaluated_count.max(parsed_count.saturating_add(parse_error_count));
    if denominator == 0 {
        return 10_000;
    }

    let coverage_bps = ((parsed_count.saturating_mul(10_000)) / denominator) as i32;
    let error_penalty = (parse_error_count.min(64) as i32) * 120;
    let request_bonus = if requested_limit >= LARGE_VOLUME_MESSAGE_THRESHOLD {
        180
    } else if requested_limit >= MEDIUM_VOLUME_MESSAGE_THRESHOLD {
        100
    } else {
        0
    };
    let parsed_volume_bonus = if parsed_count >= LARGE_VOLUME_MESSAGE_THRESHOLD {
        420
    } else if parsed_count >= MEDIUM_VOLUME_MESSAGE_THRESHOLD {
        240
    } else if parsed_count >= 10 {
        80
    } else {
        0
    };
    clamp_score_bps(coverage_bps - error_penalty + request_bonus + parsed_volume_bonus)
}

#[cfg(test)]
mod tests {
    use super::{
        classify_mail_spam, estimate_parse_confidence_bps, is_high_confidence_spam,
        parse_confidence_band, parse_volume_band,
    };

    #[test]
    fn spam_classifier_scores_risky_mail_above_conversational_mail() {
        let risky = classify_mail_spam(
            "primary",
            "security-alert-team@example-support.co",
            "URGENT ACTION REQUIRED: Verify your account now",
            "Click here and confirm now to avoid account suspension.",
        );
        let conversational = classify_mail_spam(
            "primary",
            "teammate@example.com",
            "Re: Project update for next week",
            "Thanks for the notes. Let's follow up tomorrow.",
        );
        assert!(risky.confidence_bps > conversational.confidence_bps);
        assert!(risky.confidence_bps >= 6_500);
        assert_eq!(conversational.confidence_band, "low");
    }

    #[test]
    fn spam_mailbox_prior_can_reach_high_confidence() {
        let classified = classify_mail_spam(
            "spam",
            "promo-bot@example-offers.net",
            "You have won a gift card - claim now",
            "Limited time. Click here to claim your reward now!!!",
        );
        assert!(is_high_confidence_spam(classified.confidence_bps));
        assert_eq!(classified.confidence_band, "high");
    }

    #[test]
    fn parse_confidence_rewards_large_clean_batches() {
        let high = estimate_parse_confidence_bps(120, 120, 118, 2);
        let low = estimate_parse_confidence_bps(120, 120, 42, 78);
        assert!(high > low);
        assert_eq!(parse_confidence_band(high), "high");
        assert_eq!(parse_confidence_band(low), "low");
    }

    #[test]
    fn parse_volume_bands_are_stable() {
        assert_eq!(parse_volume_band(5), "small");
        assert_eq!(parse_volume_band(24), "medium");
        assert_eq!(parse_volume_band(64), "large");
    }
}
