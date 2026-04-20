use super::*;

#[test]
fn local_business_menu_surface_requirement_falls_back_to_query_contract() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";

    assert!(query_requires_local_business_menu_surface(
        query,
        None,
        Some("Anderson, SC"),
    ));
}

#[test]
fn local_business_menu_inventory_excerpt_prefers_structured_inventory_surface() {
    let excerpt = local_business_menu_inventory_excerpt(
        "Item inventory includes Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Related image gallery available with 6 images. Brothers Special Shrimp Pasta. Chef Salad.",
        240,
    )
    .expect("inventory excerpt");

    assert!(excerpt.contains("Item inventory includes"));
    assert!(excerpt.contains("Related image gallery available with 6 images."));
    assert!(!excerpt.contains("Chef Salad. Brothers"));
}

#[test]
fn local_business_menu_inventory_excerpt_synthesizes_inventory_from_line_list_surface() {
    let excerpt = local_business_menu_inventory_excerpt(
        "Bread Sticks\n\nHummus\n\nDolmas\n\nOrganic Old Fashioned Chef Salad\n\nOrganic Antipasto Salad\n\nOrganic Chicken Salad\n\nCentral Avenue - 150 E Shockley Ferry Rd\n\nDomino's Pizza - 121 E Shockley Ferry Rd",
        240,
    )
    .expect("inventory excerpt");

    assert!(excerpt.starts_with("Item inventory includes"));
    assert!(excerpt.contains("Bread Sticks"));
    assert!(excerpt.contains("Hummus"));
    assert!(excerpt.contains("Dolmas"));
    assert!(!excerpt.contains("Shockley Ferry Rd"));
    assert!(!excerpt.contains("Domino's Pizza"));
}

#[test]
fn menu_child_url_prefers_title_entity_over_trailing_surface_slug() {
    let source = PendingSearchReadSummary {
        url: "https://www.carminesnyc.com/locations/upper-west-side/menus/dinner"
            .to_string(),
        title: Some("Carmine's Upper West Side Dinner Menu".to_string()),
        excerpt: "Family-style Italian menu in New York, NY with spaghetti and meatballs."
            .to_string(),
    };

    let target =
        local_business_target_name_from_source(&source, Some("New York, NY")).expect("target");

    assert!(target.to_ascii_lowercase().contains("carmine"), "{target}");
    assert!(!target.eq_ignore_ascii_case("Dinner"), "{target}");
}
