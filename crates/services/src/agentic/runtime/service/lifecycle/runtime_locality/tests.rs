use super::{
    compose_runtime_locality_scope, resolve_runtime_locality_seed,
    runtime_locality_ip_lookup_opted_in, runtime_locality_scope_from_ip_discovery_payload,
    timezone_identifier_from_device_with_tz,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

// W1 survey §7.8: the IP lookup sends the host's public IP to three third parties. With the
// default configuration it must never be reached; locality comes from local facts or is unknown.
#[test]
fn the_ip_lookup_is_off_unless_the_operator_opts_in() {
    for unset_or_no in [
        None,
        Some(""),
        Some("0"),
        Some("false"),
        Some("off"),
        Some("auto"),
    ] {
        assert!(
            !runtime_locality_ip_lookup_opted_in(unset_or_no),
            "{unset_or_no:?} must not opt in to the third-party lookup"
        );
    }
    for yes in [Some("1"), Some("true"), Some("YES"), Some(" on ")] {
        assert!(runtime_locality_ip_lookup_opted_in(yes), "{yes:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_default_configuration_never_reaches_the_network_lookup() {
    let lookups = AtomicUsize::new(0);
    let seed = resolve_runtime_locality_seed(
        runtime_locality_ip_lookup_opted_in(None),
        || async {
            lookups.fetch_add(1, Ordering::SeqCst);
            Some("Anderson, SC".to_string())
        },
        || Some("New York, America".to_string()),
    )
    .await;
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        0,
        "no outbound lookup by default"
    );
    assert_eq!(
        seed.as_deref(),
        Some("New York, America"),
        "local facts answer"
    );

    let unknown = resolve_runtime_locality_seed(
        false,
        || async {
            lookups.fetch_add(1, Ordering::SeqCst);
            Some("Anderson, SC".to_string())
        },
        || None,
    )
    .await;
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert_eq!(
        unknown, None,
        "with no local fact the locality stays unknown"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_operator_opt_in_reaches_the_lookup_and_falls_back_to_local_facts() {
    let lookups = AtomicUsize::new(0);
    let seed = resolve_runtime_locality_seed(
        true,
        || async {
            lookups.fetch_add(1, Ordering::SeqCst);
            None
        },
        || Some("Denver, America".to_string()),
    )
    .await;
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    assert_eq!(seed.as_deref(), Some("Denver, America"));
}

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
    assert_eq!(
        timezone_identifier_from_device_with_tz(Some("America/New_York".to_string())),
        Some("America/New_York".to_string())
    );
}
