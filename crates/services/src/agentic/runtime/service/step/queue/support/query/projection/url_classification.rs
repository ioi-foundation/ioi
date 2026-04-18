pub(crate) fn is_search_hub_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();
    let is_google_news_article_wrapper =
        host == "news.google.com" && path.starts_with("/rss/articles/");
    let has_query = parsed
        .query_pairs()
        .any(|(key, _)| key == "q" || key == "query" || key == "text");

    let is_ddg_hub = host.contains("duckduckgo.")
        && (path == "/" || path.starts_with("/html") || path.starts_with("/lite"));
    let is_bing_hub = host.ends_with("bing.com") && (path == "/" || path.starts_with("/search"));
    let is_google_hub = host.contains("google.")
        && (path == "/"
            || path.starts_with("/search")
            || path == "/url"
            || path.starts_with("/rss/search"));
    let is_google_news_hub = host == "news.google.com"
        && !is_google_news_article_wrapper
        && (path == "/"
            || path.starts_with("/topics")
            || path.starts_with("/topstories")
            || path.starts_with("/home")
            || path.starts_with("/news")
            || path.starts_with("/rss/"));
    let is_publication_listing_hub = matches!(
        path.as_str(),
        "/publications/final-pubs"
            | "/publications/draft-pubs"
            | "/publications/drafts-open-for-comment"
            | "/publications/fips"
            | "/publications/sp"
            | "/publications/ir"
            | "/publications/cswp"
            | "/publications/itl-bulletin"
            | "/publications/project-description"
            | "/publications/journal-article"
            | "/publications/conference-paper"
            | "/publications/book"
    );
    let is_generic_query_search_hub = path.contains("/search")
        || path.ends_with("/search")
        || path.starts_with("/find")
        || path.contains("/results");

    is_google_news_hub
        || is_publication_listing_hub
        || ((is_ddg_hub || is_bing_hub || is_google_hub || is_generic_query_search_hub)
            && has_query)
}

pub(crate) fn is_multi_item_listing_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if path.is_empty() {
        return true;
    }
    let segments = path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| segment.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return true;
    }

    const LISTING_MARKERS: &[&str] = &[
        "news",
        "latest",
        "headline",
        "headlines",
        "top",
        "story",
        "stories",
        "world",
        "us",
        "u-s",
        "politics",
        "business",
        "tech",
        "technology",
        "science",
        "health",
        "sports",
        "entertainment",
        "video",
        "videos",
        "category",
        "categories",
        "section",
        "sections",
        "topic",
        "topics",
        "home",
        "index",
        "live",
    ];

    let marker_segment = |segment: &str| {
        if segment.is_empty() {
            return false;
        }
        if LISTING_MARKERS.contains(&segment) {
            return true;
        }
        segment
            .split('-')
            .all(|token| !token.is_empty() && LISTING_MARKERS.contains(&token))
    };

    let short_listing = segments.len() <= 2
        && segments.iter().all(|segment| {
            if segment.chars().any(|ch| ch.is_ascii_digit()) {
                return false;
            }
            marker_segment(segment)
        });
    if short_listing {
        return true;
    }

    segments.len() <= 2
        && segments
            .last()
            .map(|segment| {
                segment.ends_with("-news")
                    || segment.ends_with("-headlines")
                    || segment.ends_with("-stories")
            })
            .unwrap_or(false)
}

#[cfg(test)]
mod url_classification_tests {
    use super::*;

    #[test]
    fn publication_index_pages_are_search_hubs() {
        for url in [
            "https://csrc.nist.gov/publications/final-pubs",
            "https://csrc.nist.gov/publications/draft-pubs",
            "https://csrc.nist.gov/publications/drafts-open-for-comment",
            "https://csrc.nist.gov/publications/fips",
            "https://csrc.nist.gov/publications/sp",
            "https://csrc.nist.gov/publications/ir",
            "https://csrc.nist.gov/publications/cswp",
            "https://csrc.nist.gov/publications/itl-bulletin",
            "https://csrc.nist.gov/publications/project-description",
            "https://csrc.nist.gov/publications/journal-article",
            "https://csrc.nist.gov/publications/conference-paper",
            "https://csrc.nist.gov/publications/book",
        ] {
            assert!(is_search_hub_url(url), "url={url}");
        }
    }

    #[test]
    fn direct_fips_publication_page_is_not_search_hub() {
        assert!(!is_search_hub_url(
            "https://csrc.nist.gov/pubs/fips/203/final"
        ));
    }

    #[test]
    fn time_sensitive_resolvable_payload_rejects_generic_role_definition_page() {
        assert!(!candidate_time_sensitive_resolvable_payload(
            "https://en.wikipedia.org/wiki/Secretary-General_of_the_United_Nations",
            "Secretary-General of the United Nations - Wikipedia",
            "The secretary-general of the United Nations is the Head of the United Nations Secretariat."
        ));
    }

    #[test]
    fn time_sensitive_resolvable_payload_accepts_named_current_role_holder() {
        assert!(candidate_time_sensitive_resolvable_payload(
            "https://ask.un.org/faq/14625",
            "Who is and has been Secretary-General of the United Nations? - Ask DAG!",
            "António Guterres is the current Secretary-General of the United Nations."
        ));
    }
}

pub(crate) fn is_citable_web_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    parsed
        .host_str()
        .map(|host| !host.trim().is_empty())
        .unwrap_or(false)
}

pub(crate) fn candidate_time_sensitive_resolvable_payload(
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    fn observation_surface_signal(schema: &MetricSchemaProfile) -> bool {
        let observation_strength = schema
            .observation_hits
            .saturating_add(schema.timestamp_hits);
        if observation_strength == 0 {
            return false;
        }
        let horizon_pressure = schema.horizon_hits.saturating_add(schema.range_hits);
        if observation_strength <= horizon_pressure {
            return false;
        }
        schema.axis_hits.len() >= TIME_SENSITIVE_RESOLVABLE_SURFACE_MIN_AXIS
    }

    fn schema_has_price_without_quote(schema: &MetricSchemaProfile, text: &str) -> bool {
        schema.axis_hits.contains(&MetricAxis::Price) && !has_price_quote_payload(text)
    }

    fn price_detail_surface_signal(url: &str, title: &str, excerpt: &str) -> bool {
        let trimmed = url.trim();
        if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
            return false;
        }
        let Ok(parsed) = Url::parse(trimmed) else {
            return false;
        };

        let path = parsed.path().to_ascii_lowercase();
        let combined = compact_whitespace(&format!("{} {}", title, excerpt)).to_ascii_lowercase();
        let explicit_price_surface = combined.contains(" price today ")
            || combined.contains(" price today is ")
            || combined.contains(" live price ")
            || combined.contains(" live btc usd rate ")
            || combined.contains(" btc to usd ")
            || combined.contains(" currently at ");
        let quote_context = combined.contains('$')
            || combined.contains(" usd ")
            || combined.contains(" btc usd ")
            || combined.contains(" to usd ")
            || combined.contains(" rate ");
        let path_detail_surface = path.contains("/price/") || path.contains("/crypto/");
        let numeric_signal = combined.chars().any(|ch| ch.is_ascii_digit());

        path_detail_surface && explicit_price_surface && quote_context && numeric_signal
    }

    fn weather_detail_surface_signal(url: &str, title: &str, excerpt: &str) -> bool {
        let trimmed = url.trim();
        if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
            return false;
        }
        let Ok(parsed) = Url::parse(trimmed) else {
            return false;
        };

        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        let path = parsed.path().to_ascii_lowercase();
        let query = parsed.query().unwrap_or_default().to_ascii_lowercase();
        let combined = compact_whitespace(&format!("{} {}", title, excerpt)).to_ascii_lowercase();
        let weather_surface_signal = combined.contains("current weather")
            || combined.contains("current conditions")
            || combined.contains("weather today")
            || combined.contains("weather report")
            || combined.contains("hourly forecast")
            || combined.contains("local radar");
        let structural_weather_detail = host == "wttr.in"
            || path.contains("/weather/today")
            || path.contains("/mapclick.php")
            || path.contains("/forecasts/latest")
            || path.contains("/hourly")
            || query.contains("cityname=")
            || query.contains("inputstring=");
        let title_locality_tokens = ordered_normalized_locality_tokens(title);
        let path_locality_tokens = ordered_normalized_locality_tokens(parsed.path());
        let query_locality_tokens = ordered_normalized_locality_tokens(parsed.query().unwrap_or_default());
        let locality_signal = title_locality_tokens.len() >= 2
            || path_locality_tokens.len() >= 2
            || query_locality_tokens.len() >= 2;

        locality_signal && (weather_surface_signal || structural_weather_detail)
    }

    if source_has_human_challenge_signal(url, title, excerpt) {
        return false;
    }
    let source_signals = analyze_source_record_signals(url, title, excerpt);
    if source_signals.low_priority_hits > 0 || source_signals.low_priority_dominates() {
        return false;
    }

    let source_text = format!("{} {}", title, excerpt);
    let source_schema = analyze_metric_schema(&source_text);
    let source_price_axis = source_schema.axis_hits.contains(&MetricAxis::Price);
    let title_lower = title.to_ascii_lowercase();
    let excerpt_lower = excerpt.to_ascii_lowercase();
    let title_pricing_context = source_price_axis
        || title_lower.contains("pricing")
        || title_lower.contains("billing")
        || title_lower.contains("rate card")
        || title_lower.contains("token cost");
    let excerpt_currency_dense = excerpt.chars().any(|ch| ch.is_ascii_digit())
        && (excerpt.contains('$') || excerpt_lower.contains("usd"))
        && (excerpt_lower.contains(" input")
            || excerpt_lower.contains(" output")
            || excerpt_lower.contains(" cached"));
    if source_price_axis {
        if has_price_quote_payload(&source_text) || price_detail_surface_signal(url, title, excerpt)
        {
            return true;
        }
        return false;
    }
    if title_pricing_context && excerpt_currency_dense {
        return true;
    } else if !source_price_axis && has_subject_currentness_payload(&source_text) {
        return true;
    } else if source_schema.has_current_observation_payload()
        || (!source_price_axis
            && source_schema.numeric_token_hits > 0
            && source_schema.unit_hits > 0)
    {
        return true;
    } else if weather_detail_surface_signal(url, title, excerpt) {
        return true;
    }

    let excerpt_schema = analyze_metric_schema(excerpt);
    let excerpt_has_price_without_quote = schema_has_price_without_quote(&excerpt_schema, excerpt);
    if excerpt_schema.axis_hits.contains(&MetricAxis::Price) {
        if has_price_quote_payload(excerpt) || price_detail_surface_signal(url, title, excerpt) {
            return true;
        }
        return false;
    } else if has_subject_currentness_payload(excerpt) {
        return true;
    } else if observation_surface_signal(&excerpt_schema) && !excerpt_has_price_without_quote {
        return true;
    }

    if !excerpt.trim().is_empty() {
        return false;
    }

    let title_schema = analyze_metric_schema(title);
    if title_schema.axis_hits.contains(&MetricAxis::Price) {
        return has_price_quote_payload(title) || price_detail_surface_signal(url, title, excerpt);
    }
    if has_subject_currentness_payload(title) {
        return true;
    }
    observation_surface_signal(&title_schema)
        && !schema_has_price_without_quote(&title_schema, title)
}
