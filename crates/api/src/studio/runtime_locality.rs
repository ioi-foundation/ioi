use std::cell::RefCell;
use std::sync::OnceLock;

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
const RUNTIME_LOCALITY_COMPONENT_MAX_CHARS: usize = 64;
const RUNTIME_LOCALITY_ZONEINFO_MARKER: &str = "zoneinfo/";
const RUNTIME_LOCALITY_ZONEINFO_NOISE_ROOTS: [&str; 5] = ["etc", "gmt", "utc", "posix", "right"];
const RUNTIME_LOCALITY_PLACEHOLDER: &str = "near_me";

static DEVICE_LOCALITY_SCOPE_CACHE: OnceLock<Option<String>> = OnceLock::new();

thread_local! {
    static STUDIO_RUNTIME_LOCALITY_THREAD_OVERRIDE: RefCell<Option<Option<String>>> = const { RefCell::new(None) };
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

fn trusted_runtime_locality_scope_from_env() -> Option<String> {
    TRUSTED_RUNTIME_LOCALITY_ENV_KEYS.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|raw| sanitize_runtime_locality_component(&raw))
    })
}

fn studio_runtime_locality_scope_override() -> Option<Option<String>> {
    STUDIO_RUNTIME_LOCALITY_THREAD_OVERRIDE.with(|override_cell| override_cell.borrow().clone())
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

pub fn studio_runtime_locality_scope_hint() -> Option<String> {
    if let Some(override_value) = studio_runtime_locality_scope_override() {
        return override_value;
    }
    trusted_runtime_locality_scope_from_env().or_else(cached_device_locality_scope)
}

pub fn resolve_runtime_locality_placeholder(scope: &str) -> Option<String> {
    let trimmed = scope.trim();
    if trimmed.eq_ignore_ascii_case(RUNTIME_LOCALITY_PLACEHOLDER) {
        return studio_runtime_locality_scope_hint();
    }
    sanitize_runtime_locality_component(trimmed)
}

#[doc(hidden)]
pub fn with_studio_runtime_locality_scope_hint_override<T>(
    scope: Option<&str>,
    f: impl FnOnce() -> T,
) -> T {
    STUDIO_RUNTIME_LOCALITY_THREAD_OVERRIDE.with(|override_cell| {
        let previous = override_cell
            .borrow_mut()
            .replace(scope.and_then(sanitize_runtime_locality_component));
        let result = f();
        *override_cell.borrow_mut() = previous;
        result
    })
}

#[cfg(test)]
mod tests {
    use super::{
        locality_scope_from_timezone_identifier, resolve_runtime_locality_placeholder,
        with_studio_runtime_locality_scope_hint_override,
    };

    #[test]
    fn timezone_identifier_maps_to_scope() {
        assert_eq!(
            locality_scope_from_timezone_identifier("America/New_York"),
            Some("New York".to_string())
        );
    }

    #[test]
    fn resolve_placeholder_requires_runtime_scope() {
        with_studio_runtime_locality_scope_hint_override(Some("Williamsburg, Brooklyn"), || {
            assert_eq!(
                resolve_runtime_locality_placeholder("near_me"),
                Some("Williamsburg, Brooklyn".to_string())
            );
        });
    }
}
