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
