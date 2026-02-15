use url::Url;

pub(super) fn is_search_intent(goal: &str) -> bool {
    let goal_lc = goal.to_ascii_lowercase();
    [
        "search for",
        "search ",
        "look up",
        "lookup ",
        "find information",
        "find online",
        "web search",
        "google ",
        "duckduckgo",
        "bing ",
    ]
    .iter()
    .any(|needle| goal_lc.contains(needle))
}

pub(super) fn extract_navigation_url(args: &serde_json::Value) -> Option<String> {
    args.get("url")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

pub(super) fn search_query_from_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let keys = ["q", "query", "p", "text", "wd", "k"];
    parsed
        .query_pairs()
        .find(|(k, v)| keys.contains(&k.as_ref()) && !v.trim().is_empty())
        .map(|(_, v)| v.to_string())
}

pub(super) fn is_search_results_url(url: &str) -> bool {
    let parsed = match Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };

    let scheme_ok = matches!(parsed.scheme(), "http" | "https");
    if !scheme_ok {
        return false;
    }

    let host_lc = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let path_lc = parsed.path().to_ascii_lowercase();
    let has_search_engine_host = [
        "duckduckgo.com",
        "google.",
        "bing.com",
        "search.yahoo.com",
        "search.brave.com",
        "startpage.com",
    ]
    .iter()
    .any(|needle| host_lc.contains(needle));
    if !has_search_engine_host {
        return false;
    }

    let has_query = search_query_from_url(url).is_some();
    has_query || path_lc.contains("/search")
}

#[cfg(test)]
mod tests {
    use super::{is_search_intent, is_search_results_url, search_query_from_url};

    #[test]
    fn detects_search_intent_keywords() {
        assert!(is_search_intent("Search for internet of intelligence"));
        assert!(is_search_intent("please look up rust async runtime"));
        assert!(!is_search_intent("open calculator"));
    }

    #[test]
    fn detects_search_result_urls() {
        assert!(is_search_results_url(
            "https://duckduckgo.com/?q=internet+of+intelligence"
        ));
        assert!(is_search_results_url(
            "https://www.google.com/search?q=internet+of+intelligence"
        ));
        assert!(!is_search_results_url("https://example.com/docs/ioi"));
    }

    #[test]
    fn extracts_search_query_from_url() {
        assert_eq!(
            search_query_from_url("https://duckduckgo.com/?q=internet+of+intelligence").as_deref(),
            Some("internet of intelligence")
        );
    }
}
