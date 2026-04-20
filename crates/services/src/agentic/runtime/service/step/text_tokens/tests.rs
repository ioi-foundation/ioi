use super::{
    is_iso_date_token, looks_like_clock_time, token_has_numeric_payload, token_is_numeric_literal,
};

#[test]
fn token_detection_behaves_consistently() {
    assert!(looks_like_clock_time("10:42"));
    assert!(!looks_like_clock_time("10:4"));
    assert!(is_iso_date_token("2026-02-28"));
    assert!(!is_iso_date_token("2026/02/28"));
    assert!(token_has_numeric_payload("$123.45"));
    assert!(!token_has_numeric_payload("abc123"));
    assert!(token_is_numeric_literal("1,234.50"));
    assert!(!token_is_numeric_literal("10:42"));
}
