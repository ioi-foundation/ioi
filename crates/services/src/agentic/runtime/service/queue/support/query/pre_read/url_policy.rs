pub(crate) fn looks_like_deep_article_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_search_hub_url(trimmed) {
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
    if host.eq_ignore_ascii_case("news.google.com")
        && parsed
            .path()
            .to_ascii_lowercase()
            .starts_with("/rss/articles/")
    {
        return true;
    }

    let normalized_path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if normalized_path.is_empty() {
        return false;
    }
    let segments = normalized_path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }
    if segments.len() <= 2
        && segments
            .first()
            .copied()
            .map(|segment| {
                matches!(
                    segment,
                    "show" | "shows" | "watch" | "video" | "videos" | "live" | "tv"
                )
            })
            .unwrap_or(false)
    {
        return false;
    }

    let path_hub_markers = [
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
        if path_hub_markers.contains(&segment) {
            return true;
        }
        segment
            .split('-')
            .all(|token| !token.is_empty() && path_hub_markers.contains(&token))
    };
    if segments.len() <= 2 && segments.iter().all(|segment| marker_segment(segment)) {
        return false;
    }

    let first_segment = segments.first().copied().unwrap_or_default();
    let last_segment = segments.last().copied().unwrap_or_default();
    let slug_segments = last_segment
        .split('-')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    let section_segment = |segment: &str| {
        matches!(
            segment,
            "world"
                | "us"
                | "u-s"
                | "politics"
                | "business"
                | "tech"
                | "technology"
                | "science"
                | "health"
                | "sports"
                | "entertainment"
                | "metro"
                | "local"
                | "international"
        )
    };
    let article_marker_segment = |segment: &str| {
        matches!(segment, "article" | "articles" | "story" | "stories" | "news")
    };
    let last_segment_detailish = last_segment.ends_with(".html")
        || last_segment.ends_with(".htm")
        || last_segment.chars().any(|ch| ch.is_ascii_digit())
        || !slug_segments.is_empty();
    if segments.len() >= 2
        && last_segment_detailish
        && (article_marker_segment(first_segment)
            || segments
                .iter()
                .rev()
                .nth(1)
                .copied()
                .map(article_marker_segment)
                .unwrap_or(false))
    {
        return true;
    }
    if slug_segments.len() >= 3 {
        return true;
    }
    if segments.len() == 2
        && section_segment(first_segment)
        && slug_segments.len() >= 2
        && !marker_segment(last_segment)
    {
        return true;
    }
    if segments.len() >= 2 {
        let penultimate_segment = segments[segments.len() - 2];
        let penultimate_slug_segments = penultimate_segment
            .split('-')
            .filter(|segment| !segment.trim().is_empty())
            .collect::<Vec<_>>();
        let trailing_id_like = last_segment.chars().any(|ch| ch.is_ascii_digit())
            || last_segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'));
        if penultimate_slug_segments.len() >= 3 && trailing_id_like {
            return true;
        }
    }

    let has_deep_path = segments.len() >= 3;
    let has_article_marker = segments.iter().any(|segment| {
        segment.chars().any(|ch| ch.is_ascii_digit())
            || segment.contains("article")
            || segment.contains("story")
            || segment.contains("feature")
            || segment.contains("update")
    });
    has_deep_path && has_article_marker
}

fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
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

fn source_domain_key_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    source_url_from_metadata_excerpt(excerpt).and_then(|candidate| canonical_domain_key(&candidate))
}

fn candidate_distinct_domain_key_from_excerpt(url: &str, excerpt: &str) -> Option<String> {
    let url_domain = canonical_domain_key(url);
    let hinted_domain = source_domain_key_from_metadata_excerpt(excerpt);
    match (url_domain, hinted_domain) {
        (Some(url_domain), Some(hinted_domain)) if url_domain != hinted_domain => {
            Some(hinted_domain)
        }
        (Some(url_domain), _) => Some(url_domain),
        (None, Some(hinted_domain)) => Some(hinted_domain),
        (None, None) => None,
    }
}
