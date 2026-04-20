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
