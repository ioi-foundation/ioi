use super::{
    locality_scope_from_timezone_identifier, resolve_runtime_locality_placeholder,
    with_runtime_locality_scope_hint_override,
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
    with_runtime_locality_scope_hint_override(Some("Williamsburg, Brooklyn"), || {
        assert_eq!(
            resolve_runtime_locality_placeholder("near_me"),
            Some("Williamsburg, Brooklyn".to_string())
        );
    });
}
