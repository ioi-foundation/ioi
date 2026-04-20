use super::*;

#[test]
fn normalize_role_handles_mixed_case_and_aliases() {
    assert_eq!(normalize_role("PushButton"), "button");
    assert_eq!(normalize_role("MenuItem"), "menuitem");
    assert_eq!(normalize_role("Description Value"), "description_value");
}

#[test]
fn normalize_attribute_key_compacts_placeholder_variants() {
    assert_eq!(normalize_attribute_key("placeholder-text"), "placeholder");
    assert_eq!(normalize_attribute_key("placeholderText"), "placeholder");
    assert_eq!(
        normalize_attribute_key("accessible-name"),
        "accessible_name"
    );
}

#[test]
fn stable_accessible_id_sanitizes_destination_and_path() {
    let id = stable_accessible_id(
        ":1.42",
        "/org/a11y/atspi/accessible/application/gnome-calculator/frame",
    );
    assert_eq!(
        id,
        "atspi__1_42_org_a11y_atspi_accessible_application_gnome_calculator_frame"
    );
}

#[test]
fn wrap_atspi_error_mentions_accessibility_bus_for_registry_failures() {
    let err = wrap_atspi_error(
        "connection open",
        "org.a11y.atspi.Registry was not provided",
    );
    assert!(err.to_string().contains("Linux accessibility bus"));
}
