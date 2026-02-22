use ioi_crypto::algorithms::hash::sha256;
use scraper::ElementRef;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

pub(crate) fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|raw| {
            let normalized = raw.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn sha256_hex(input: &[u8]) -> String {
    sha256(input)
        .map(|d| hex::encode(d.as_ref()))
        .unwrap_or_default()
}

pub(crate) fn normalize_url_for_id(url: &str) -> String {
    let trimmed = url.trim();
    let Ok(mut parsed) = Url::parse(trimmed) else {
        return trimmed.to_string();
    };
    parsed.set_fragment(None);
    // Url normalizes scheme/host casing; `to_string` is stable for the same logical URL.
    parsed.to_string()
}

pub(crate) fn source_id_for_url(url: &str) -> String {
    sha256_hex(normalize_url_for_id(url).as_bytes())
}

pub(crate) fn domain_for_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

pub(crate) fn text_content(elem: ElementRef<'_>) -> String {
    elem.text().collect::<Vec<_>>().join(" ")
}

pub(crate) fn compact_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
