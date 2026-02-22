use crate::agentic::desktop::service::step::queue::query_requires_runtime_locality_scope;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::OnceCell;

const RUNTIME_LOCALITY_ENV_SEED_KEY: &str = "IOI_SESSION_LOCALITY";
const RUNTIME_LOCALITY_DISCOVERY_URLS: [&str; 3] = [
    "https://ipapi.co/json/",
    "https://ipwho.is/",
    "https://ipinfo.io/json",
];
const RUNTIME_LOCALITY_DISCOVERY_TIMEOUT_MS: u64 = 2_000;
const RUNTIME_LOCALITY_COMPONENT_MAX_CHARS: usize = 64;
const RUNTIME_LOCALITY_REGION_CODE_MAX_CHARS: usize = 4;
const RUNTIME_LOCALITY_ZONEINFO_MARKER: &str = "zoneinfo/";
const RUNTIME_LOCALITY_ZONEINFO_NOISE_ROOTS: [&str; 5] = ["etc", "gmt", "utc", "posix", "right"];
const TRUSTED_RUNTIME_LOCALITY_ENV_KEYS: [&str; 8] = [
    "IOI_SESSION_LOCALITY",
    "IOI_DEVICE_LOCALITY",
    "IOI_USER_LOCALITY",
    "IOI_LOCALITY",
    "SESSION_LOCALITY",
    "DEVICE_LOCALITY",
    "USER_LOCALITY",
    "LOCALITY",
];

static DEVICE_LOCALITY_SCOPE_CACHE: OnceLock<Option<String>> = OnceLock::new();
static DISCOVERED_RUNTIME_LOCALITY_SCOPE_CACHE: OnceCell<String> = OnceCell::const_new();

fn runtime_locality_env_present() -> bool {
    TRUSTED_RUNTIME_LOCALITY_ENV_KEYS.iter().any(|key| {
        std::env::var(key)
            .ok()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    })
}

fn compact_runtime_locality_whitespace(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sanitize_runtime_locality_component(raw: &str) -> Option<String> {
    let compact = compact_runtime_locality_whitespace(raw);
    let trimmed = compact.trim();
    if trimmed.is_empty() || trimmed.len() > RUNTIME_LOCALITY_COMPONENT_MAX_CHARS {
        return None;
    }
    if trimmed.chars().any(|ch| ch.is_control()) {
        return None;
    }
    Some(trimmed.to_string())
}

fn sanitize_runtime_locality_region_code(raw: &str) -> Option<String> {
    let compact = compact_runtime_locality_whitespace(raw);
    let trimmed = compact.trim();
    if trimmed.is_empty()
        || trimmed.len() > RUNTIME_LOCALITY_REGION_CODE_MAX_CHARS
        || !trimmed.chars().all(|ch| ch.is_ascii_alphabetic())
    {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

fn compose_runtime_locality_scope(
    city: Option<&str>,
    region_code: Option<&str>,
    region: Option<&str>,
) -> Option<String> {
    let city = city.and_then(sanitize_runtime_locality_component)?;
    if let Some(code) = region_code.and_then(sanitize_runtime_locality_region_code) {
        return Some(format!("{city}, {code}"));
    }
    if let Some(region_name) = region.and_then(sanitize_runtime_locality_component) {
        if !region_name.eq_ignore_ascii_case(&city) {
            return Some(format!("{city}, {region_name}"));
        }
    }
    Some(city)
}

fn runtime_locality_scope_from_ip_discovery_payload(payload: &serde_json::Value) -> Option<String> {
    let city = payload.get("city").and_then(|value| value.as_str());
    let region_code = payload
        .get("region_code")
        .or_else(|| payload.get("regionCode"))
        .and_then(|value| value.as_str());
    let region = payload.get("region").and_then(|value| value.as_str());
    compose_runtime_locality_scope(city, region_code, region)
}

async fn discover_runtime_locality_scope_from_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(RUNTIME_LOCALITY_DISCOVERY_TIMEOUT_MS))
        .build()
        .ok()?;
    for url in RUNTIME_LOCALITY_DISCOVERY_URLS {
        let response = match client.get(url).send().await {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let payload = match response.json::<serde_json::Value>().await {
            Ok(payload) => payload,
            Err(_) => continue,
        };
        if let Some(scope) = runtime_locality_scope_from_ip_discovery_payload(&payload) {
            return Some(scope);
        }
    }
    None
}

async fn cached_runtime_locality_scope() -> Option<String> {
    if let Some(cached) = DISCOVERED_RUNTIME_LOCALITY_SCOPE_CACHE.get() {
        return Some(cached.clone());
    }
    let discovered = discover_runtime_locality_scope_from_ip().await?;
    let _ = DISCOVERED_RUNTIME_LOCALITY_SCOPE_CACHE.set(discovered.clone());
    Some(discovered)
}

fn timezone_identifier_from_device() -> Option<String> {
    if let Ok(value) = std::env::var("TZ") {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    let link = std::fs::read_link("/etc/localtime").ok()?;
    let path = link.to_string_lossy();
    let marker_idx = path.rfind(RUNTIME_LOCALITY_ZONEINFO_MARKER)?;
    let identifier = path[(marker_idx + RUNTIME_LOCALITY_ZONEINFO_MARKER.len())..].trim();
    (!identifier.is_empty()).then(|| identifier.to_string())
}

fn locality_scope_from_timezone_identifier(identifier: &str) -> Option<String> {
    let normalized = identifier.trim().trim_matches('/');
    if normalized.is_empty() {
        return None;
    }
    let segments = normalized
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 2 {
        return None;
    }
    let root = segments
        .first()
        .map(|segment| segment.to_ascii_lowercase())
        .unwrap_or_default();
    if RUNTIME_LOCALITY_ZONEINFO_NOISE_ROOTS
        .iter()
        .any(|blocked| *blocked == root)
    {
        return None;
    }

    let city = segments
        .last()
        .copied()
        .unwrap_or_default()
        .replace('_', " ");
    let city = city.trim();
    if city.is_empty() {
        return None;
    }

    if segments.len() >= 3 {
        let region = segments[segments.len().saturating_sub(2)].replace('_', " ");
        let region = region.trim();
        if !region.is_empty() && !region.eq_ignore_ascii_case(city) {
            return Some(format!("{city}, {region}"));
        }
    }
    Some(city.to_string())
}

fn cached_device_locality_scope() -> Option<String> {
    DEVICE_LOCALITY_SCOPE_CACHE
        .get_or_init(|| {
            timezone_identifier_from_device()
                .as_deref()
                .and_then(locality_scope_from_timezone_identifier)
        })
        .clone()
}

pub(super) async fn maybe_seed_runtime_locality_context(goal: &str) {
    if cfg!(test) {
        return;
    }
    if !query_requires_runtime_locality_scope(goal) || runtime_locality_env_present() {
        return;
    }
    if let Some(scope) = cached_runtime_locality_scope()
        .await
        .or_else(cached_device_locality_scope)
    {
        std::env::set_var(RUNTIME_LOCALITY_ENV_SEED_KEY, scope);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compose_runtime_locality_scope, runtime_locality_scope_from_ip_discovery_payload,
        timezone_identifier_from_device,
    };
    use serde_json::json;

    #[test]
    fn runtime_locality_scope_from_ip_payload_prefers_region_code() {
        let payload = json!({
            "city": "Anderson",
            "region": "South Carolina",
            "region_code": "SC"
        });
        assert_eq!(
            runtime_locality_scope_from_ip_discovery_payload(&payload),
            Some("Anderson, SC".to_string())
        );
    }

    #[test]
    fn runtime_locality_scope_from_ip_payload_falls_back_to_region_name() {
        let payload = json!({
            "city": "Anderson",
            "region": "South Carolina"
        });
        assert_eq!(
            runtime_locality_scope_from_ip_discovery_payload(&payload),
            Some("Anderson, South Carolina".to_string())
        );
    }

    #[test]
    fn runtime_locality_scope_from_ip_payload_requires_city() {
        let payload = json!({
            "region": "South Carolina",
            "region_code": "SC"
        });
        assert_eq!(
            runtime_locality_scope_from_ip_discovery_payload(&payload),
            None
        );
    }

    #[test]
    fn compose_runtime_locality_scope_returns_city_when_region_matches_city() {
        assert_eq!(
            compose_runtime_locality_scope(Some("Anderson"), None, Some("Anderson")),
            Some("Anderson".to_string())
        );
    }

    #[test]
    fn timezone_identifier_from_device_prefers_tz_env_when_present() {
        let previous = std::env::var("TZ").ok();
        std::env::set_var("TZ", "America/New_York");
        assert_eq!(
            timezone_identifier_from_device(),
            Some("America/New_York".to_string())
        );
        if let Some(value) = previous {
            std::env::set_var("TZ", value);
        } else {
            std::env::remove_var("TZ");
        }
    }
}
