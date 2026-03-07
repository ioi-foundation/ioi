use super::*;

include!("projection/anchors.rs");

include!("projection/compatibility.rs");

include!("projection/probe_terms.rs");

include!("projection/url_classification.rs");

#[cfg(test)]
mod tests {
    use super::candidate_time_sensitive_resolvable_payload;

    #[test]
    fn time_sensitive_resolvable_payload_rejects_low_priority_forum_surface() {
        assert!(!candidate_time_sensitive_resolvable_payload(
            "https://www.reddit.com/r/CryptoCurrency/comments/14zq3b4/why_is_the_bitcoin_price_falling_what_is_the/",
            "Why is the Bitcoin price falling?",
            "Current BTC price is $68,123, but this thread is community speculation about where it goes next.",
        ));
    }

    #[test]
    fn time_sensitive_resolvable_payload_accepts_observation_surface() {
        assert!(candidate_time_sensitive_resolvable_payload(
            "https://www.example.com/markets/bitcoin-price",
            "Bitcoin price",
            "BTC price today is $68,123.45 as of 14:32 UTC.",
        ));
    }

    #[test]
    fn time_sensitive_resolvable_payload_rejects_marketing_percentages_on_price_pages() {
        assert!(!candidate_time_sensitive_resolvable_payload(
            "https://crypto.com/en/price/bitcoin",
            "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International",
            "99% 0% fee first 30 days The purpose of this website is solely to display information regarding the products and services available",
        ));
    }
}
