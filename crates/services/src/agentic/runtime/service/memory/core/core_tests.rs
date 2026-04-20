use super::content_looks_secret_like;

#[test]
fn secret_detector_ignores_secretary_general_phrasing() {
    assert!(!content_looks_secret_like(
        "Who is the current Secretary-General of the UN?"
    ));
}

#[test]
fn secret_detector_keeps_explicit_secret_indicators() {
    assert!(content_looks_secret_like("client secret: abc123"));
    assert!(content_looks_secret_like("Bearer abc123"));
    assert!(content_looks_secret_like("password is hunter2"));
    assert!(content_looks_secret_like("Authorization: Bearer abc123"));
}
