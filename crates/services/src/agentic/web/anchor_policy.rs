use crate::agentic::desktop::service::step::signals::{
    analyze_query_facets, query_semantic_anchor_tokens,
};
use ioi_types::app::agentic::WebSource;
use std::collections::HashSet;
use url::Url;

use super::constants::{
    QUERY_SCOPE_MARKERS, SEARCH_ANCHOR_GROUNDED_MIN_OVERLAP, SEARCH_ANCHOR_LOCALITY_MIN_OVERLAP,
    SEARCH_ANCHOR_MIN_TOKEN_CHARS, SEARCH_ANCHOR_REQUIRED_OVERLAP_CAP,
    SEARCH_ANCHOR_REQUIRED_OVERLAP_RATIO_DENOMINATOR, SEARCH_ANCHOR_SEMANTIC_MIN_OVERLAP,
    SEARCH_ANCHOR_STOPWORDS, SEARCH_ANCHOR_TIME_SENSITIVE_MIN_OVERLAP,
};

fn search_anchor_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < SEARCH_ANCHOR_MIN_TOKEN_CHARS {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if SEARCH_ANCHOR_STOPWORDS.contains(&normalized.as_str()) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn semantic_search_anchor_tokens(text: &str) -> HashSet<String> {
    let semantic_tokens = query_semantic_anchor_tokens(text)
        .into_iter()
        .filter(|token| token.len() >= SEARCH_ANCHOR_MIN_TOKEN_CHARS)
        .filter(|token| !token.chars().all(|ch| ch.is_ascii_digit()))
        .filter(|token| !SEARCH_ANCHOR_STOPWORDS.contains(&token.as_str()))
        .collect::<HashSet<_>>();
    if semantic_tokens.is_empty() {
        search_anchor_tokens(text)
    } else {
        semantic_tokens
    }
}

pub(crate) fn query_is_generic_headline_lookup(query: &str) -> bool {
    let tokens = search_anchor_tokens(query);
    if tokens.is_empty() {
        return false;
    }
    let has_headline_anchor = tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "news" | "headline" | "headlines" | "stories"
        )
    });
    if !has_headline_anchor {
        return false;
    }
    let generic_tokens = [
        "news",
        "headline",
        "headlines",
        "top",
        "latest",
        "today",
        "breaking",
        "story",
        "stories",
        "updates",
        "update",
    ];
    let non_generic_count = tokens
        .iter()
        .filter(|token| !generic_tokens.contains(&token.as_str()))
        .count();
    non_generic_count <= 1
}

fn headline_source_has_news_signal(source: &WebSource) -> bool {
    let title = source.title.as_deref().unwrap_or_default();
    let snippet = source.snippet.as_deref().unwrap_or_default();
    let source_text = format!(" {} {} {} ", source.url, title, snippet).to_ascii_lowercase();
    let keyword_signal = [
        " news ",
        " headline ",
        " headlines ",
        " breaking ",
        "/news/",
        "/world/",
        "/politics/",
        "/business/",
        "/us/",
    ]
    .iter()
    .any(|marker| source_text.contains(marker));
    keyword_signal || headline_url_has_article_structure(source.url.as_str())
}

fn headline_url_has_article_structure(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    let path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if path.is_empty() {
        return false;
    }
    let segments = path
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }

    let taxonomy_markers = [
        "category",
        "categories",
        "topic",
        "topics",
        "tag",
        "tags",
        "section",
        "sections",
        "author",
        "authors",
        "collection",
        "collections",
        "hub",
        "hubs",
        "search",
        "results",
    ];
    if segments.iter().any(|segment| {
        let normalized = segment.replace('-', " ");
        normalized
            .split_whitespace()
            .any(|token| taxonomy_markers.contains(&token))
    }) {
        return false;
    }

    let listing_markers = [
        "news",
        "latest",
        "headlines",
        "headline",
        "home",
        "world",
        "us",
        "politics",
        "business",
        "technology",
        "tech",
        "health",
        "sports",
        "entertainment",
        "video",
        "videos",
        "index",
        "top-stories",
        "top-news",
        "latest-news",
    ];
    if segments.len() <= 2
        && segments.iter().all(|segment| {
            let normalized = segment.replace('-', " ");
            normalized
                .split_whitespace()
                .all(|token| listing_markers.contains(&token))
        })
    {
        return false;
    }

    let has_year_segment = segments.iter().any(|segment| {
        segment.starts_with("20")
            && segment.len() == 4
            && segment
                .chars()
                .skip(2)
                .take(2)
                .all(|ch| ch.is_ascii_digit())
    });
    let has_slug_segment = segments.iter().any(|segment| {
        segment
            .split('-')
            .filter(|token| !token.trim().is_empty() && token.len() >= 3)
            .count()
            >= 3
    });
    let has_alphanumeric_id_segment = segments.iter().any(|segment| {
        segment.len() >= 10
            && segment.chars().any(|ch| ch.is_ascii_alphabetic())
            && segment.chars().any(|ch| ch.is_ascii_digit())
    });
    let terminal = segments.last().copied().unwrap_or_default();
    let terminal_slug_tokens = terminal
        .split('-')
        .filter(|token| !token.trim().is_empty() && token.len() >= 3)
        .count();
    let terminal_has_structure = terminal_slug_tokens >= 3
        || terminal.chars().filter(|ch| ch.is_ascii_digit()).count() >= 4
        || (terminal.len() >= 10
            && terminal.chars().any(|ch| ch.is_ascii_alphabetic())
            && terminal.chars().any(|ch| ch.is_ascii_digit()));
    let has_article_path_keyword = path.contains("/article/")
        || path.contains("/story/")
        || path.contains("/live/")
        || path.contains("/news/")
        || path.contains("/world/")
        || path.contains("/politics/")
        || path.contains("/business/")
        || path.contains("/us/");

    has_alphanumeric_id_segment
        || (has_year_segment && terminal_has_structure)
        || (has_article_path_keyword && terminal_has_structure && segments.len() >= 2)
        || (segments.len() >= 3 && has_slug_segment && terminal_has_structure)
}

fn scope_anchor_start(query_lower: &str) -> Option<usize> {
    for marker in QUERY_SCOPE_MARKERS {
        if let Some(idx) = query_lower.rfind(marker) {
            return Some(idx + marker.len());
        }
    }
    None
}

fn query_scope_tokens(query: &str) -> HashSet<String> {
    let normalized = format!(" {} ", query.trim().to_ascii_lowercase());
    let Some(start) = scope_anchor_start(&normalized) else {
        return HashSet::new();
    };
    search_anchor_tokens(&normalized[start..])
}

fn required_source_anchor_overlap(query: &str, query_token_count: usize) -> usize {
    if query_token_count == 0 {
        return 0;
    }

    let facets = analyze_query_facets(query);
    let mut required_overlap =
        (query_token_count + SEARCH_ANCHOR_REQUIRED_OVERLAP_RATIO_DENOMINATOR - 1)
            / SEARCH_ANCHOR_REQUIRED_OVERLAP_RATIO_DENOMINATOR;
    required_overlap = required_overlap
        .max(1)
        .min(SEARCH_ANCHOR_REQUIRED_OVERLAP_CAP)
        .min(query_token_count);
    if facets.grounded_external_required {
        required_overlap = required_overlap.max(SEARCH_ANCHOR_GROUNDED_MIN_OVERLAP);
    }
    if facets.time_sensitive_public_fact {
        required_overlap = required_overlap.max(SEARCH_ANCHOR_TIME_SENSITIVE_MIN_OVERLAP);
    }
    if facets.locality_sensitive_public_fact {
        required_overlap = required_overlap.max(SEARCH_ANCHOR_LOCALITY_MIN_OVERLAP);
    }

    required_overlap.min(query_token_count)
}

fn source_anchor_overlap_count(
    query_tokens: &HashSet<String>,
    source_tokens: &HashSet<String>,
) -> usize {
    if query_tokens.is_empty() {
        return 0;
    }
    query_tokens
        .iter()
        .filter(|token| source_tokens.contains(*token))
        .count()
}

fn source_anchor_overlap_metrics(
    source: &WebSource,
    query_tokens: &HashSet<String>,
    semantic_query_tokens: &HashSet<String>,
) -> (usize, usize) {
    let title = source.title.as_deref().unwrap_or_default();
    let snippet = source.snippet.as_deref().unwrap_or_default();
    let source_tokens = search_anchor_tokens(&format!("{} {} {}", source.url, title, snippet));
    let anchor_overlap = source_anchor_overlap_count(query_tokens, &source_tokens);
    let semantic_overlap = if semantic_query_tokens.is_empty() {
        0
    } else {
        semantic_query_tokens
            .iter()
            .filter(|token| source_tokens.contains(*token))
            .count()
    };
    (anchor_overlap, semantic_overlap)
}

#[cfg(test)]
fn source_matches_query_anchors(
    source: &WebSource,
    query_tokens: &HashSet<String>,
    semantic_query_tokens: &HashSet<String>,
    required_overlap: usize,
) -> bool {
    let (anchor_overlap, semantic_overlap) =
        source_anchor_overlap_metrics(source, query_tokens, semantic_query_tokens);
    if anchor_overlap < required_overlap {
        return false;
    }

    if semantic_query_tokens.is_empty() {
        return true;
    }

    semantic_overlap >= SEARCH_ANCHOR_SEMANTIC_MIN_OVERLAP
}

pub(crate) fn filter_provider_sources_by_query_anchors(
    query: &str,
    sources: Vec<WebSource>,
) -> Vec<WebSource> {
    if query_is_generic_headline_lookup(query) {
        return sources
            .into_iter()
            .filter(headline_source_has_news_signal)
            .collect();
    }
    let semantic_tokens = semantic_search_anchor_tokens(query);
    let query_scope_tokens = query_scope_tokens(query);
    let mut query_tokens = semantic_tokens.clone();
    query_tokens.extend(query_scope_tokens.iter().cloned());
    if query_tokens.is_empty() {
        return sources;
    }
    let semantic_query_tokens = semantic_tokens
        .difference(&query_scope_tokens)
        .cloned()
        .collect::<HashSet<_>>();
    let semantic_query_tokens = if semantic_query_tokens.is_empty() {
        semantic_tokens
    } else {
        semantic_query_tokens
    };
    let required_overlap = required_source_anchor_overlap(query, query_tokens.len());
    let mut strict_matches = Vec::new();
    let mut fallback_ranked = Vec::new();

    for source in sources {
        let (anchor_overlap, semantic_overlap) =
            source_anchor_overlap_metrics(&source, &query_tokens, &semantic_query_tokens);
        let strict_match = anchor_overlap >= required_overlap
            && (semantic_query_tokens.is_empty()
                || semantic_overlap >= SEARCH_ANCHOR_SEMANTIC_MIN_OVERLAP);
        if strict_match {
            strict_matches.push(source);
            continue;
        }
        if anchor_overlap > 0 || semantic_overlap > 0 {
            fallback_ranked.push((source, anchor_overlap, semantic_overlap));
        }
    }

    if !strict_matches.is_empty() {
        return strict_matches;
    }

    fallback_ranked.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.0.url.cmp(&right.0.url))
    });
    fallback_ranked
        .into_iter()
        .map(|(source, _, _)| source)
        .collect()
}

#[cfg(test)]
pub(crate) fn provider_sources_match_query_anchors(query: &str, sources: &[WebSource]) -> bool {
    let semantic_tokens = semantic_search_anchor_tokens(query);
    let query_scope_tokens = query_scope_tokens(query);
    let mut query_tokens = semantic_tokens.clone();
    query_tokens.extend(query_scope_tokens.iter().cloned());
    if query_tokens.is_empty() {
        return true;
    }
    let semantic_query_tokens = semantic_tokens
        .difference(&query_scope_tokens)
        .cloned()
        .collect::<HashSet<_>>();
    let semantic_query_tokens = if semantic_query_tokens.is_empty() {
        semantic_tokens
    } else {
        semantic_query_tokens
    };
    let required_overlap = required_source_anchor_overlap(query, query_tokens.len());

    sources.iter().any(|source| {
        source_matches_query_anchors(
            source,
            &query_tokens,
            &semantic_query_tokens,
            required_overlap,
        )
    })
}
