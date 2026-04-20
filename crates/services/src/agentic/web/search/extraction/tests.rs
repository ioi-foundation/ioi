use super::{
    headline_article_path_depth, looks_like_headline_article_url,
    provider_search_query_with_locality_hint,
};

#[test]
fn provider_search_query_with_locality_hint_leaves_queries_unchanged_without_scope() {
    let query = provider_search_query_with_locality_hint("today's top news headlines", None);
    assert_eq!(query, "today's top news headlines");
}

#[test]
fn provider_search_query_resolves_runtime_locality_placeholders() {
    let query = provider_search_query_with_locality_hint(
        "best-reviewed Italian restaurants near me",
        Some("Anderson, SC"),
    );
    assert_eq!(query, "best-reviewed Italian restaurants in Anderson, SC");
}

#[test]
fn looks_like_headline_article_url_rejects_wrapper_and_hub_paths() {
    assert!(!looks_like_headline_article_url(
        "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5"
    ));
    assert!(!looks_like_headline_article_url("https://www.nbcnews.com/"));
}

#[test]
fn looks_like_headline_article_url_accepts_story_paths() {
    assert!(looks_like_headline_article_url(
        "https://www.reuters.com/world/europe/example-story-2026-03-01/"
    ));
    assert!(
        headline_article_path_depth(
            "https://www.reuters.com/world/europe/example-story-2026-03-01/"
        ) >= 3
    );
}
