use ioi_types::app::agentic::{IntentScopeProfile, ResolvedIntentState};
use url::Url;

pub(crate) fn is_search_scope(resolved_intent: Option<&ResolvedIntentState>) -> bool {
    resolved_intent
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false)
}

pub(crate) fn extract_navigation_url(args: &serde_json::Value) -> Option<String> {
    args.get("url")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

pub(crate) fn search_query_from_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let keys = ["q", "query", "p", "text", "wd", "k"];
    parsed
        .query_pairs()
        .find(|(k, v)| keys.contains(&k.as_ref()) && !v.trim().is_empty())
        .map(|(_, v)| v.to_string())
}

pub(crate) fn is_search_results_url(url: &str) -> bool {
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
#[path = "search/tests.rs"]
mod tests;
