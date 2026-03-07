use base64::{engine::general_purpose, Engine as _};
use url::Url;

pub fn build_ddg_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://duckduckgo.com/html/".to_string();
    }

    let mut url = Url::parse("https://duckduckgo.com/html/").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

pub(crate) fn build_brave_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://search.brave.com/search".to_string();
    }
    let mut url = Url::parse("https://search.brave.com/search").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

pub(crate) fn build_google_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://www.google.com/search".to_string();
    }
    let mut url = Url::parse("https://www.google.com/search").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

pub(crate) fn build_google_news_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    let mut url = Url::parse("https://www.google.com/search").expect("static base url parses");
    {
        let mut query_pairs = url.query_pairs_mut();
        if !trimmed.is_empty() {
            query_pairs.append_pair("q", trimmed);
        }
        query_pairs
            .append_pair("tbm", "nws")
            .append_pair("hl", "en-US")
            .append_pair("gl", "US");
    }
    url.to_string()
}

pub(crate) fn build_bing_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://www.bing.com/search".to_string();
    }
    let mut url = Url::parse("https://www.bing.com/search").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

pub(crate) fn build_bing_search_rss_url(query: &str) -> String {
    let trimmed = query.trim();
    let mut url = Url::parse("https://www.bing.com/search").expect("static base url parses");
    {
        let mut query_pairs = url.query_pairs_mut();
        if !trimmed.is_empty() {
            query_pairs.append_pair("q", trimmed);
        }
        query_pairs.append_pair("format", "rss");
    }
    url.to_string()
}

pub(crate) fn build_bing_news_rss_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://www.bing.com/news/search?format=rss".to_string();
    }
    let mut url = Url::parse("https://www.bing.com/news/search").expect("static base url parses");
    url.query_pairs_mut()
        .append_pair("q", trimmed)
        .append_pair("format", "rss");
    url.to_string()
}

pub fn build_default_search_url(query: &str) -> String {
    let provider = std::env::var("IOI_WEB_DEFAULT_SEARCH_PROVIDER")
        .ok()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "duckduckgo".to_string());

    match provider.as_str() {
        "google" => build_google_serp_url(query),
        "bing" => build_bing_serp_url(query),
        "duckduckgo" | "ddg" | _ => build_ddg_serp_url(query),
    }
}

pub(crate) fn build_google_news_rss_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://news.google.com/rss".to_string();
    }

    let mut url = Url::parse("https://news.google.com/rss/search").expect("static base url parses");
    url.query_pairs_mut()
        .append_pair("q", trimmed)
        .append_pair("hl", "en-US")
        .append_pair("gl", "US")
        .append_pair("ceid", "US:en");
    url.to_string()
}

pub(crate) fn build_google_news_top_stories_rss_url() -> String {
    let mut url = Url::parse("https://news.google.com/rss").expect("static base url parses");
    url.query_pairs_mut()
        .append_pair("hl", "en-US")
        .append_pair("gl", "US")
        .append_pair("ceid", "US:en");
    url.to_string()
}

pub(crate) fn build_wttr_locality_current_conditions_url(scope: &str) -> String {
    let trimmed = scope.trim();
    let mut url = Url::parse("https://wttr.in/").expect("static base url parses");
    url.set_path(&format!("/{}", trimmed));
    url.query_pairs_mut().append_pair(
        "format",
        "%l: temp %t humidity %h wind %w pressure %P as of %T",
    );
    url.to_string()
}

pub(crate) fn build_weather_gov_locality_lookup_url(scope: &str) -> String {
    let trimmed = scope.trim();
    let mut url =
        Url::parse("https://forecast.weather.gov/zipcity.php").expect("static base url parses");
    url.query_pairs_mut().append_pair("inputstring", trimmed);
    url.to_string()
}

fn slugify_path_segment(raw: &str) -> Option<String> {
    let slug = raw
        .trim()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("-");
    (!slug.is_empty()).then_some(slug)
}

fn normalize_us_state_code(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let code = match normalized.as_str() {
        "al" | "alabama" => "al",
        "ak" | "alaska" => "ak",
        "az" | "arizona" => "az",
        "ar" | "arkansas" => "ar",
        "ca" | "california" => "ca",
        "co" | "colorado" => "co",
        "ct" | "connecticut" => "ct",
        "de" | "delaware" => "de",
        "dc" | "district of columbia" => "dc",
        "fl" | "florida" => "fl",
        "ga" | "georgia" => "ga",
        "hi" | "hawaii" => "hi",
        "id" | "idaho" => "id",
        "il" | "illinois" => "il",
        "in" | "indiana" => "in",
        "ia" | "iowa" => "ia",
        "ks" | "kansas" => "ks",
        "ky" | "kentucky" => "ky",
        "la" | "louisiana" => "la",
        "me" | "maine" => "me",
        "md" | "maryland" => "md",
        "ma" | "massachusetts" => "ma",
        "mi" | "michigan" => "mi",
        "mn" | "minnesota" => "mn",
        "ms" | "mississippi" => "ms",
        "mo" | "missouri" => "mo",
        "mt" | "montana" => "mt",
        "ne" | "nebraska" => "ne",
        "nv" | "nevada" => "nv",
        "nh" | "new hampshire" => "nh",
        "nj" | "new jersey" => "nj",
        "nm" | "new mexico" => "nm",
        "ny" | "new york" => "ny",
        "nc" | "north carolina" => "nc",
        "nd" | "north dakota" => "nd",
        "oh" | "ohio" => "oh",
        "ok" | "oklahoma" => "ok",
        "or" | "oregon" => "or",
        "pa" | "pennsylvania" => "pa",
        "ri" | "rhode island" => "ri",
        "sc" | "south carolina" => "sc",
        "sd" | "south dakota" => "sd",
        "tn" | "tennessee" => "tn",
        "tx" | "texas" => "tx",
        "ut" | "utah" => "ut",
        "vt" | "vermont" => "vt",
        "va" | "virginia" => "va",
        "wa" | "washington" => "wa",
        "wv" | "west virginia" => "wv",
        "wi" | "wisconsin" => "wi",
        "wy" | "wyoming" => "wy",
        _ => return None,
    };
    Some(code.to_string())
}

pub(crate) fn build_restaurantji_locality_root_url(scope: &str) -> Option<String> {
    let mut parts = scope
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty());
    let city = slugify_path_segment(parts.next()?)?;
    let state = normalize_us_state_code(parts.next()?)?;
    let mut url = Url::parse("https://www.restaurantji.com/").expect("static base url parses");
    url.set_path(&format!("/{state}/{city}/"));
    Some(url.to_string())
}

fn absolutize_ddg_href(href: &str) -> String {
    let trimmed = href.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if trimmed.starts_with("//") {
        return format!("https:{}", trimmed);
    }
    if trimmed.starts_with("/l/?") || trimmed.starts_with("/l/") {
        return format!("https://duckduckgo.com{}", trimmed);
    }
    trimmed.to_string()
}

fn decode_ddg_redirect(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !host.contains("duckduckgo.com") {
        return None;
    }
    if !parsed.path().starts_with("/l/") {
        return None;
    }

    let uddg = parsed
        .query_pairs()
        .find(|(k, _)| k == "uddg")
        .map(|(_, v)| v.to_string())?;
    if uddg.trim().is_empty() {
        return None;
    }

    // `query_pairs` returns a decoded value. Normalize by dropping fragments.
    let trimmed = uddg.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }

    if let Ok(mut dest) = Url::parse(trimmed) {
        dest.set_fragment(None);
        return Some(dest.to_string());
    }

    Some(trimmed.to_string())
}

pub(crate) fn normalize_search_href(href: &str) -> Option<String> {
    let abs = absolutize_ddg_href(href);
    if abs.is_empty() {
        return None;
    }
    if let Some(decoded) = decode_ddg_redirect(&abs) {
        return Some(decoded);
    }
    if abs.starts_with("http://") || abs.starts_with("https://") {
        return Some(abs);
    }
    None
}

fn absolutize_provider_href(provider_origin: &str, href: &str) -> String {
    let trimmed = href.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if trimmed.starts_with("//") {
        return format!("https:{}", trimmed);
    }
    if trimmed.starts_with('/') {
        return format!("{}{}", provider_origin, trimmed);
    }
    trimmed.to_string()
}

fn decode_google_redirect(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !host.contains("google.") {
        return None;
    }
    if parsed.path() != "/url" {
        return None;
    }

    let candidate = parsed
        .query_pairs()
        .find(|(k, _)| k == "q" || k == "url")
        .map(|(_, v)| v.to_string())?;
    let trimmed = candidate.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }
    if let Ok(mut dest) = Url::parse(trimmed) {
        dest.set_fragment(None);
        return Some(dest.to_string());
    }
    Some(trimmed.to_string())
}

fn decode_bing_redirect(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !host.ends_with("bing.com") {
        return None;
    }
    if parsed.path().starts_with("/news/apiclick.aspx") {
        let candidate = parsed
            .query_pairs()
            .find(|(k, _)| k == "url" || k == "u" || k == "ru")
            .map(|(_, v)| v.to_string())?;
        let trimmed = candidate.trim();
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            return None;
        }
        if let Ok(mut dest) = Url::parse(trimmed) {
            dest.set_fragment(None);
            return Some(dest.to_string());
        }
        return Some(trimmed.to_string());
    }
    if !parsed.path().starts_with("/ck/") {
        return None;
    }

    let raw = parsed
        .query_pairs()
        .find(|(k, _)| k == "u")
        .map(|(_, v)| v.to_string())?;
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.to_string());
    }

    let maybe_encoded = trimmed.strip_prefix("a1").unwrap_or(trimmed);
    if maybe_encoded.is_empty() {
        return None;
    }

    for candidate in [maybe_encoded, trimmed] {
        for engine in [
            &general_purpose::URL_SAFE_NO_PAD,
            &general_purpose::URL_SAFE,
            &general_purpose::STANDARD_NO_PAD,
            &general_purpose::STANDARD,
        ] {
            let Ok(bytes) = engine.decode(candidate) else {
                continue;
            };
            let Ok(decoded) = String::from_utf8(bytes) else {
                continue;
            };
            let decoded_trimmed = decoded.trim();
            if decoded_trimmed.starts_with("http://") || decoded_trimmed.starts_with("https://") {
                return Some(decoded_trimmed.to_string());
            }
        }
    }

    None
}

pub(crate) fn normalize_google_search_href(href: &str) -> Option<String> {
    let abs = absolutize_provider_href("https://www.google.com", href);
    if abs.is_empty() {
        return None;
    }
    if let Some(decoded) = decode_google_redirect(&abs) {
        return Some(decoded);
    }
    if abs.starts_with("http://") || abs.starts_with("https://") {
        return Some(abs);
    }
    None
}

pub(crate) fn normalize_bing_search_href(href: &str) -> Option<String> {
    let abs = absolutize_provider_href("https://www.bing.com", href);
    if abs.is_empty() {
        return None;
    }
    if let Some(decoded) = decode_bing_redirect(&abs) {
        return Some(decoded);
    }
    if abs.starts_with("http://") || abs.starts_with("https://") {
        return Some(abs);
    }
    None
}

pub(crate) fn normalize_brave_search_href(href: &str) -> Option<String> {
    let abs = absolutize_provider_href("https://search.brave.com", href);
    if abs.is_empty() {
        return None;
    }
    if abs.starts_with("http://") || abs.starts_with("https://") {
        return Some(abs);
    }
    None
}

pub(crate) fn is_search_engine_host(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    host.ends_with("duckduckgo.com")
        || host.ends_with("google.com")
        || host.ends_with("bing.com")
        || host.ends_with("search.brave.com")
}
