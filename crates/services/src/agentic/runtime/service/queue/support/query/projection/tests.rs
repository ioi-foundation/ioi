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
fn time_sensitive_resolvable_payload_accepts_current_role_holder_surface() {
    assert!(candidate_time_sensitive_resolvable_payload(
        "https://www.un.org/sg/en/content/sg/biography",
        "Secretary-General biography | United Nations",
        "António Guterres currently serves as the Secretary-General of the United Nations.",
    ));
}

#[test]
fn time_sensitive_resolvable_payload_accepts_structural_weather_detail_surface() {
    assert!(candidate_time_sensitive_resolvable_payload(
        "https://www.weather-atlas.com/en/south-carolina-usa/anderson",
        "Weather today - Anderson, SC",
        "Current weather and hourly forecast page for Anderson, SC.",
    ));
}

#[test]
fn time_sensitive_resolvable_payload_accepts_market_quote_detail_surface() {
    assert!(candidate_time_sensitive_resolvable_payload(
        "https://www.coincodex.com/crypto/bitcoin/",
        "Bitcoin Price: Live BTC/USD Rate, Market Cap & BTC Price Chart | CoinCodex",
        "Bitcoin price today is $68,026 with a trading volume of $56.53B and market cap of $1.36T. BTC price decreased -4.1% in the last 24 hours.",
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
