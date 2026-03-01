use super::*;

pub(super) fn successful_source_url_set(pending: &PendingSearchCompletion) -> BTreeSet<String> {
    pending
        .successful_reads
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect()
}

pub(super) fn blocked_unverified_url_set(
    pending: &PendingSearchCompletion,
    successful_urls: &BTreeSet<String>,
) -> BTreeSet<String> {
    pending
        .blocked_urls
        .iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty() && !successful_urls.contains(url))
        .collect()
}

pub(super) fn is_blocked_unverified_url(
    url: &str,
    blocked_unverified_urls: &BTreeSet<String>,
) -> bool {
    blocked_unverified_urls.contains(url.trim())
}

pub(super) fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    let marker = "source_url=";
    let lower = excerpt.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let candidate = excerpt
        .get(start..)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "|,;:!?)]}\"'".contains(ch))
        .trim();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn source_has_human_challenge_signal(url: &str, title: &str, excerpt: &str) -> bool {
    let surface = format!("{} {} {}", url, title, excerpt).to_ascii_lowercase();
    [
        "please enable js",
        "please enable javascript",
        "enable javascript",
        "verify you are human",
        "access denied",
        "captcha",
        "recaptcha",
        "cloudflare",
        "dd={'rt':'c'",
    ]
    .iter()
    .any(|marker| surface.contains(marker))
}

pub(super) fn headline_low_quality_signal(url: &str, title: &str, excerpt: &str) -> bool {
    if source_has_human_challenge_signal(url, title, excerpt) {
        return true;
    }
    let signals = analyze_source_record_signals(url, title, excerpt);
    if is_multi_item_listing_url(url) {
        return signals.low_priority_dominates();
    }
    signals.low_priority_dominates() && !has_primary_status_authority(signals)
}

pub(super) fn headline_source_is_low_quality(source: &PendingSearchReadSummary) -> bool {
    headline_low_quality_signal(
        source.url.as_str(),
        source.title.as_deref().unwrap_or_default(),
        source.excerpt.as_str(),
    )
}
