use crate::agentic::desktop::service::step::signals::{
    analyze_query_facets, query_semantic_anchor_tokens,
};
use ioi_types::app::agentic::WebSource;
use std::collections::HashSet;

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
