use super::*;

fn sample_spec() -> WorkloadSpec {
    WorkloadSpec {
        runtime_target: RuntimeTarget::Network,
        net_mode: NetMode::AllowListed,
        capability_lease: Some(CapabilityLease {
            lease_id: [7u8; 32],
            issued_at_ms: 100,
            expires_at_ms: 1_000,
            mode: CapabilityLeaseMode::OneShot,
            capability_allowlist: vec!["net::fetch".to_string()],
            domain_allowlist: vec!["example.com".to_string()],
        }),
        ui_surface: None,
    }
}

#[test]
fn lease_check_fails_when_capability_lease_missing() {
    let spec = WorkloadSpec {
        runtime_target: RuntimeTarget::Network,
        net_mode: NetMode::AllowListed,
        capability_lease: None,
        ui_surface: None,
    };
    let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("example.com"), 500);
    assert!(!check.satisfied);
    assert_eq!(check.reason.as_deref(), Some("missing_capability_lease"));
}

#[test]
fn lease_check_fails_when_expired() {
    let spec = sample_spec();
    let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("example.com"), 1_001);
    assert!(!check.satisfied);
    assert_eq!(check.reason.as_deref(), Some("capability_lease_expired"));
}

#[test]
fn lease_check_fails_when_domain_out_of_scope() {
    let spec = sample_spec();
    let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("evil.com"), 500);
    assert!(!check.satisfied);
    assert_eq!(check.reason.as_deref(), Some("domain_out_of_scope"));
}

#[test]
fn lease_check_succeeds_for_allowlisted_domain() {
    let spec = sample_spec();
    let check = spec.evaluate_lease(&ActionTarget::NetFetch, Some("api.example.com"), 500);
    assert!(check.satisfied);
    assert!(check.reason.is_none());
}

#[test]
fn runtime_target_labels_include_absorbed_localai_capability_families() {
    assert_eq!(RuntimeTarget::Inference.as_label(), "inference");
    assert_eq!(RuntimeTarget::Media.as_label(), "media");
    assert_eq!(RuntimeTarget::ModelRegistry.as_label(), "model_registry");
}
