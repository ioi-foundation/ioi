// Path: crates/services/src/wallet_network/mail_ontology.rs

pub(crate) const MAIL_ONTOLOGY_SIGNAL_VERSION: &str = "mail_ontology_v2";
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
const SENDER_RISK_WEIGHT_BPS: i32 = 850;
const SUBJECT_RISK_WEIGHT_BPS: i32 = 900;
const CONTENT_RISK_WEIGHT_BPS: i32 = 700;
const MARKETING_SENDER_WEIGHT_BPS: i32 = 500;
const MARKETING_SUBJECT_WEIGHT_BPS: i32 = 550;
const MARKETING_CONTENT_WEIGHT_BPS: i32 = 600;
const BULK_DISTRIBUTION_WEIGHT_BPS: i32 = 450;
const MARKETING_FOOTER_PATTERN_BONUS_BPS: i32 = 900;
const PERCENTAGE_DISCOUNT_PATTERN_BONUS_BPS: i32 = 650;
const TRANSACTIONAL_SUBJECT_WEIGHT_BPS: i32 = 800;
const TRANSACTIONAL_CONTENT_WEIGHT_BPS: i32 = 700;
const TRANSACTIONAL_SENDER_CONTEXT_BONUS_BPS: i32 = 900;
const TRANSACTIONAL_OVER_MARKETING_BIAS_BPS: i32 = 500;
const URGENCY_PUNCTUATION_BONUS_BPS: i32 = 500;
const UPPERCASE_URGENCY_BONUS_BPS: i32 = 400;
const SAFE_THREAD_WEIGHT_BPS: i32 = 1_000;
const SAFE_PERSONAL_WEIGHT_BPS: i32 = 700;
const TRUSTED_SYSTEM_SENDER_BONUS_BPS: i32 = 900;
const MARKETING_BULK_COMPOSITE_BONUS_BPS: i32 = 700;
const STRONG_PRESERVATION_HITS_THRESHOLD: usize = 3;
const LIGHT_RISK_HITS_THRESHOLD: usize = 2;
const SPAM_CONTEXT_FLOOR_MIN_RISK_HITS: usize = 1;
const SPAM_CONTEXT_FLOOR_MAX_PRESERVATION_HITS: usize = 0;
const PRIMARY_UNWANTED_CONTEXT_FLOOR_MIN_MARKETING_HITS: usize = 2;
const PRIMARY_UNWANTED_CONTEXT_FLOOR_MIN_RISK_HITS: usize = 3;
const PRIMARY_UNWANTED_CONTEXT_FLOOR_MAX_PRESERVATION_HITS: usize = 0;
const PRESERVATION_OVERRIDE_CAP_BPS: i32 = 6_400;

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

const MARKETING_SENDER_RISK_MARKERS: [&str; 23] = [
    "newsletter",
    "digest",
    "promo",
    "deals",
    "offers",
    "sale",
    "campaign",
    "mailer",
    "broadcast",
    "mailchimp",
    "sendgrid",
    "constantcontact",
    "hubspot",
    "marketo",
    "noreply",
    "no-reply",
    "donotreply",
    "do-not-reply",
    "updates",
    "announce",
    "specials",
    "shop",
    "store",
];

const MARKETING_SUBJECT_RISK_MARKERS: [&str; 27] = [
    "flash sale",
    "sale ends",
    "limited-time",
    "limited time",
    "special offer",
    "exclusive offer",
    "promo code",
    "coupon",
    "save",
    "% off",
    "discount",
    "deal",
    "deals",
    "shop now",
    "buy now",
    "new arrivals",
    "last chance",
    "ending soon",
    "free shipping",
    "clearance",
    "newsletter",
    "daily deals",
    "weekly deals",
    "black friday",
    "cyber monday",
    "sponsored",
    "advertisement",
];

const MARKETING_CONTENT_RISK_MARKERS: [&str; 29] = [
    "unsubscribe",
    "list-unsubscribe",
    "list unsubscribe",
    "list-id:",
    "precedence: bulk",
    "feedback-id:",
    "x-campaign",
    "x-newsletter",
    "manage preferences",
    "email preferences",
    "update preferences",
    "opt out",
    "view in browser",
    "view this email",
    "advertisement",
    "sponsored",
    "promotional",
    "special offer",
    "shop now",
    "buy now",
    "this email was sent to",
    "you are receiving this email",
    "if you no longer wish to receive",
    "all rights reserved",
    "privacy policy",
    "terms of service",
    "copyright",
    "view online",
    "open this email in your browser",
];

const BULK_DISTRIBUTION_FOOTER_MARKERS: [&str; 17] = [
    "list-unsubscribe",
    "list unsubscribe",
    "list-id:",
    "precedence: bulk",
    "feedback-id:",
    "manage preferences",
    "email preferences",
    "update preferences",
    "opt out",
    "view in browser",
    "view this email",
    "you are receiving this email",
    "this email was sent to",
    "if you no longer wish to receive",
    "all rights reserved",
    "privacy policy",
    "terms of service",
];

const TRANSACTIONAL_SUBJECT_SAFE_MARKERS: [&str; 28] = [
    "receipt",
    "order #",
    "order confirmation",
    "invoice",
    "statement",
    "billing statement",
    "payment confirmation",
    "payment receipt",
    "tracking number",
    "shipping update",
    "delivery update",
    "your package",
    "appointment confirmation",
    "reservation confirmed",
    "booking confirmation",
    "service confirmation",
    "subscription receipt",
    "renewal confirmation",
    "account statement",
    "tax document",
    "verification code",
    "security code",
    "one-time code",
    "one time code",
    "otp",
    "passcode",
    "authentication code",
    "sign-in code",
];

const TRANSACTIONAL_CONTENT_SAFE_MARKERS: [&str; 27] = [
    "thank you for your purchase",
    "order total",
    "billing address",
    "shipping address",
    "tracking number",
    "estimated delivery",
    "invoice number",
    "statement period",
    "payment received",
    "amount paid",
    "receipt attached",
    "order summary",
    "line items",
    "shipment details",
    "transaction id",
    "service period",
    "renewal date",
    "next billing date",
    "reservation details",
    "appointment details",
    "verification code",
    "security code",
    "one-time code",
    "one time code",
    "this code expires",
    "do not share this code",
    "authentication code",
];

const TRANSACTIONAL_SENDER_SAFE_MARKERS: [&str; 12] = [
    "receipts",
    "billing",
    "invoices",
    "orders",
    "statements",
    "support",
    "service",
    "tracking",
    "shipment",
    "reservations",
    "appointments",
    "account",
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
    markers
        .iter()
        .filter(|marker| text.contains(**marker))
        .count()
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
    let mailbox_is_spam_prior = mailbox_spam_prior(mailbox);
    let mut score = if mailbox_is_spam_prior {
        MAILBOX_SPAM_PRIOR_BPS
    } else {
        MAILBOX_PRIMARY_PRIOR_BPS
    };
    let mut tags = Vec::new();
    if mailbox_is_spam_prior {
        push_tag(&mut tags, "signal_mailbox_spam_prior");
    } else {
        push_tag(&mut tags, "signal_mailbox_primary_prior");
    }

    let sender_risk_hits = marker_hits(&from_lc, &SPAM_SENDER_RISK_MARKERS);
    if sender_risk_hits > 0 {
        score += (sender_risk_hits.min(3) as i32) * SENDER_RISK_WEIGHT_BPS;
        push_tag(&mut tags, "signal_sender_risk_markers");
    }

    let subject_risk_hits = marker_hits(&combined, &SPAM_SUBJECT_RISK_MARKERS);
    if subject_risk_hits > 0 {
        score += (subject_risk_hits.min(4) as i32) * SUBJECT_RISK_WEIGHT_BPS;
        push_tag(&mut tags, "signal_subject_risk_markers");
    }

    let content_risk_hits = marker_hits(&combined, &SPAM_CONTENT_RISK_MARKERS);
    if content_risk_hits > 0 {
        score += (content_risk_hits.min(4) as i32) * CONTENT_RISK_WEIGHT_BPS;
        push_tag(&mut tags, "signal_content_risk_markers");
    }

    let marketing_sender_hits = marker_hits(&from_lc, &MARKETING_SENDER_RISK_MARKERS);
    if marketing_sender_hits > 0 {
        score += (marketing_sender_hits.min(4) as i32) * MARKETING_SENDER_WEIGHT_BPS;
        push_tag(&mut tags, "signal_sender_marketing_markers");
    }

    let marketing_subject_hits = marker_hits(&combined, &MARKETING_SUBJECT_RISK_MARKERS);
    if marketing_subject_hits > 0 {
        score += (marketing_subject_hits.min(5) as i32) * MARKETING_SUBJECT_WEIGHT_BPS;
        push_tag(&mut tags, "signal_subject_marketing_markers");
    }

    let marketing_content_hits = marker_hits(&combined, &MARKETING_CONTENT_RISK_MARKERS);
    if marketing_content_hits > 0 {
        score += (marketing_content_hits.min(5) as i32) * MARKETING_CONTENT_WEIGHT_BPS;
        push_tag(&mut tags, "signal_content_marketing_markers");
    }

    let bulk_distribution_hits = marker_hits(&combined, &BULK_DISTRIBUTION_FOOTER_MARKERS);
    if bulk_distribution_hits > 0 {
        score += (bulk_distribution_hits.min(4) as i32) * BULK_DISTRIBUTION_WEIGHT_BPS;
        push_tag(&mut tags, "signal_bulk_distribution_footer");
    }

    let has_marketing_footer_pattern = combined.contains("unsubscribe")
        && (combined.contains("manage preferences")
            || combined.contains("email preferences")
            || combined.contains("view in browser")
            || combined.contains("opt out"));
    if has_marketing_footer_pattern {
        score += MARKETING_FOOTER_PATTERN_BONUS_BPS;
        push_tag(&mut tags, "signal_marketing_footer_pattern");
    }

    let has_percentage_discount_pattern = subject_lc.contains('%')
        && (subject_lc.contains("off")
            || subject_lc.contains("discount")
            || subject_lc.contains("save"));
    if has_percentage_discount_pattern {
        score += PERCENTAGE_DISCOUNT_PATTERN_BONUS_BPS;
        push_tag(&mut tags, "signal_percentage_discount_pattern");
    }

    let has_list_header_bulk_pattern = combined.contains("list-unsubscribe")
        || combined.contains("list unsubscribe")
        || combined.contains("list-id:")
        || combined.contains("precedence: bulk");
    if has_list_header_bulk_pattern {
        push_tag(&mut tags, "signal_list_header_bulk_pattern");
    }

    let transactional_subject_hits = marker_hits(&combined, &TRANSACTIONAL_SUBJECT_SAFE_MARKERS);
    if transactional_subject_hits > 0 {
        score -= (transactional_subject_hits.min(4) as i32) * TRANSACTIONAL_SUBJECT_WEIGHT_BPS;
        push_tag(&mut tags, "signal_transactional_subject_markers");
    }

    let transactional_content_hits = marker_hits(&combined, &TRANSACTIONAL_CONTENT_SAFE_MARKERS);
    if transactional_content_hits > 0 {
        score -= (transactional_content_hits.min(4) as i32) * TRANSACTIONAL_CONTENT_WEIGHT_BPS;
        push_tag(&mut tags, "signal_transactional_content_markers");
    }

    let transactional_sender_hits = marker_hits(&from_lc, &TRANSACTIONAL_SENDER_SAFE_MARKERS);
    let transactional_sender_context_applies = transactional_sender_hits > 0
        && (transactional_subject_hits > 0 || transactional_content_hits > 0);
    if transactional_sender_context_applies {
        score -= TRANSACTIONAL_SENDER_CONTEXT_BONUS_BPS;
        push_tag(&mut tags, "signal_transactional_sender_context");
    }

    let transactional_total_hits = transactional_subject_hits
        .saturating_add(transactional_content_hits)
        .saturating_add(usize::from(transactional_sender_context_applies));
    let marketing_total_hits = marketing_sender_hits
        .saturating_add(marketing_subject_hits)
        .saturating_add(marketing_content_hits);

    if transactional_subject_hits.saturating_add(transactional_content_hits) >= 2
        && marketing_subject_hits.saturating_add(marketing_content_hits) <= 1
    {
        score -= TRANSACTIONAL_OVER_MARKETING_BIAS_BPS;
        push_tag(&mut tags, "signal_transactional_over_marketing_bias");
    }

    if marketing_total_hits >= 3 && bulk_distribution_hits > 0 && transactional_total_hits == 0 {
        score += MARKETING_BULK_COMPOSITE_BONUS_BPS;
        push_tag(&mut tags, "signal_marketing_bulk_composite");
    }

    let exclamation_hits = combined.matches('!').count();
    let has_urgency_punctuation = exclamation_hits >= 3;
    if exclamation_hits >= 3 {
        score += URGENCY_PUNCTUATION_BONUS_BPS;
        push_tag(&mut tags, "signal_urgency_punctuation");
    }

    let uppercase_chars = subject.chars().filter(|ch| ch.is_ascii_uppercase()).count();
    let subject_chars = subject.chars().count().max(1);
    let has_uppercase_urgency = uppercase_chars * 10 >= subject_chars * 6 && subject_chars >= 12;
    if has_uppercase_urgency {
        score += UPPERCASE_URGENCY_BONUS_BPS;
        push_tag(&mut tags, "signal_uppercase_urgency");
    }

    let safe_thread_hits = marker_hits(&combined, &SAFE_THREAD_MARKERS);
    if safe_thread_hits > 0 {
        score -= (safe_thread_hits.min(3) as i32) * SAFE_THREAD_WEIGHT_BPS;
        push_tag(&mut tags, "signal_safe_thread_markers");
    }

    let safe_personal_hits = marker_hits(&combined, &SAFE_PERSONAL_MARKERS);
    if safe_personal_hits > 0 {
        score -= (safe_personal_hits.min(3) as i32) * SAFE_PERSONAL_WEIGHT_BPS;
        push_tag(&mut tags, "signal_safe_personal_markers");
    }

    let trusted_system_sender =
        from_lc.contains("@calendar.") || from_lc.contains("@notifications.");
    if trusted_system_sender {
        score -= TRUSTED_SYSTEM_SENDER_BONUS_BPS;
        push_tag(&mut tags, "signal_trusted_system_sender");
    }

    let risk_total_hits = sender_risk_hits
        .saturating_add(subject_risk_hits)
        .saturating_add(content_risk_hits)
        .saturating_add(marketing_total_hits)
        .saturating_add(bulk_distribution_hits)
        .saturating_add(usize::from(has_marketing_footer_pattern))
        .saturating_add(usize::from(has_percentage_discount_pattern))
        .saturating_add(usize::from(has_list_header_bulk_pattern))
        .saturating_add(usize::from(has_urgency_punctuation))
        .saturating_add(usize::from(has_uppercase_urgency));
    let preservation_total_hits = transactional_total_hits
        .saturating_add(safe_thread_hits)
        .saturating_add(safe_personal_hits)
        .saturating_add(usize::from(trusted_system_sender));

    if preservation_total_hits >= STRONG_PRESERVATION_HITS_THRESHOLD
        && risk_total_hits <= LIGHT_RISK_HITS_THRESHOLD
        && score >= SPAM_MEDIUM_CONFIDENCE_THRESHOLD_BPS as i32
    {
        score = score.min(PRESERVATION_OVERRIDE_CAP_BPS);
        push_tag(&mut tags, "signal_preservation_override");
    }

    if mailbox_is_spam_prior
        && risk_total_hits >= SPAM_CONTEXT_FLOOR_MIN_RISK_HITS
        && preservation_total_hits <= SPAM_CONTEXT_FLOOR_MAX_PRESERVATION_HITS
        && score < SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS as i32
    {
        score = SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS as i32;
        push_tag(&mut tags, "signal_spam_mailbox_context_floor");
    }

    let has_primary_unwanted_floor_signal = has_marketing_footer_pattern
        || has_percentage_discount_pattern
        || bulk_distribution_hits > 0
        || has_list_header_bulk_pattern;
    if !mailbox_is_spam_prior
        && marketing_total_hits >= PRIMARY_UNWANTED_CONTEXT_FLOOR_MIN_MARKETING_HITS
        && risk_total_hits >= PRIMARY_UNWANTED_CONTEXT_FLOOR_MIN_RISK_HITS
        && preservation_total_hits <= PRIMARY_UNWANTED_CONTEXT_FLOOR_MAX_PRESERVATION_HITS
        && has_primary_unwanted_floor_signal
        && score < SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS as i32
    {
        score = SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS as i32;
        push_tag(&mut tags, "signal_primary_unwanted_context_floor");
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
    fn marketing_newsletter_in_primary_can_reach_high_confidence() {
        let classified = classify_mail_spam(
            "primary",
            "daily-deals-newsletter@offers.example.com",
            "Flash sale: 40% OFF today only",
            "Shop now and save big. Unsubscribe or manage preferences. View in browser.",
        );
        assert!(is_high_confidence_spam(classified.confidence_bps));
        assert!(classified
            .signal_tags
            .iter()
            .any(|tag| tag == "signal_marketing_footer_pattern"));
    }

    #[test]
    fn transactional_receipt_with_order_context_remains_low_confidence() {
        let classified = classify_mail_spam(
            "primary",
            "receipts@shop.example.com",
            "Receipt for Order #48219",
            "Thanks for your purchase. Tracking number: 1Z999. See you next week.",
        );
        assert_eq!(classified.confidence_band, "low");
    }

    #[test]
    fn transactional_mail_with_footer_stays_below_high_confidence() {
        let classified = classify_mail_spam(
            "primary",
            "billing@utility.example.com",
            "Billing statement for account 12345",
            "Statement period and amount paid included. Manage preferences and privacy policy.",
        );
        assert!(!is_high_confidence_spam(classified.confidence_bps));
    }

    #[test]
    fn transactional_personal_mail_in_spam_mailbox_not_forced_high_confidence() {
        let classified = classify_mail_spam(
            "spam",
            "receipts@shop.example.com",
            "Receipt for Order #48219",
            "Thank you for your purchase. Order total, billing address, tracking number, and shipment details are included. Let me know if you need help next week.",
        );
        assert!(!is_high_confidence_spam(classified.confidence_bps));
        assert!(classified
            .signal_tags
            .iter()
            .any(|tag| tag.starts_with("signal_transactional_")));
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
