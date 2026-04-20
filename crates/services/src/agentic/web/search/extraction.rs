use crate::agentic::runtime::service::step::queue::web_pipeline::resolved_query_contract_with_locality_hint;
use crate::agentic::web::util::domain_for_url;
use ioi_types::app::agentic::WebSource;
use url::Url;

pub(super) fn provider_search_query_with_locality_hint(
    query: &str,
    locality_hint: Option<&str>,
) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let resolved = resolved_query_contract_with_locality_hint(trimmed, locality_hint);
    let resolved_trimmed = resolved.trim();
    if resolved_trimmed.is_empty() {
        trimmed.to_string()
    } else {
        resolved_trimmed.to_string()
    }
}

pub(super) fn canonical_source_domain(source: &WebSource) -> Option<String> {
    let from_source = source
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let domain = from_source
        .or_else(|| domain_for_url(&source.url).map(|value| value.to_ascii_lowercase()))?;
    Some(domain.strip_prefix("www.").unwrap_or(&domain).to_string())
}

fn looks_like_placeholder_article_slug_segment(segment: &str) -> bool {
    let trimmed = segment.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let tokenized = trimmed
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokenized.is_empty() {
        return false;
    }
    let role_tokens = [
        "article", "story", "news", "headline", "post", "report", "item",
    ];
    let placeholder_tokens = [
        "title",
        "slug",
        "name",
        "text",
        "content",
        "page",
        "link",
        "sample",
        "placeholder",
    ];
    let has_role = tokenized.iter().any(|token| role_tokens.contains(token));
    let has_placeholder = tokenized
        .iter()
        .any(|token| placeholder_tokens.contains(token));
    let all_generic = tokenized
        .iter()
        .all(|token| role_tokens.contains(token) || placeholder_tokens.contains(token));

    tokenized.len() >= 2 && has_role && has_placeholder && all_generic
}

pub(super) fn looks_like_headline_article_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.trim().is_empty() {
        return false;
    }
    let host = host.to_ascii_lowercase();
    let path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if path.is_empty() {
        return false;
    }
    if host == "news.google.com" && path.starts_with("rss/") {
        return false;
    }
    let segments = path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }
    let hub_markers = [
        "news",
        "latest",
        "home",
        "homepage",
        "index",
        "index.html",
        "video",
        "videos",
        "live",
        "world",
        "us",
        "top-stories",
        "top-news",
    ];
    let marker_segment = |segment: &str| {
        if segment.is_empty() {
            return false;
        }
        if hub_markers.contains(&segment) {
            return true;
        }
        segment
            .split('-')
            .all(|token| !token.is_empty() && hub_markers.contains(&token))
    };
    if hub_markers.iter().any(|marker| path == *marker) {
        return false;
    }
    if segments
        .last()
        .map(|segment| marker_segment(segment))
        .unwrap_or(false)
    {
        return false;
    }
    if segments
        .last()
        .copied()
        .map(looks_like_placeholder_article_slug_segment)
        .unwrap_or(false)
    {
        return false;
    }

    true
}

pub(super) fn headline_article_path_depth(url: &str) -> usize {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return 0;
    };
    parsed
        .path()
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .count()
}

#[cfg(test)]
#[path = "extraction/tests.rs"]
mod tests;
