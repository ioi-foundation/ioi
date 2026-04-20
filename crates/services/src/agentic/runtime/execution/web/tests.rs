use super::{redact_url_for_receipt, strip_userinfo_from_urlish};
use reqwest::Url;

#[test]
fn redact_url_for_receipt_strips_query_fragment_and_userinfo() {
    let u = Url::parse("https://user:pass@example.com/path?x=1#frag").expect("parse");
    let redacted = redact_url_for_receipt(&u).to_string();
    assert_eq!(redacted, "https://example.com/path");
}

#[test]
fn strip_userinfo_from_urlish_removes_authority_userinfo() {
    let stripped = strip_userinfo_from_urlish("https://user:pass@example.com/path?x=1");
    assert_eq!(stripped, "https://example.com/path?x=1");
}
