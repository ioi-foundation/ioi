use super::*;

#[test]
fn canonical_source_title_for_query_uses_query_scoped_local_business_identity() {
    let source = PendingSearchReadSummary {
        url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d25369085-Reviews-Marcellino_Restaurant-New_York_City_New_York.html".to_string(),
        title: Some("Tripadvisor".to_string()),
        excerpt: "Marcellino Restaurant: com','cookie':'trip-cookie-payload-12345"
            .to_string(),
    };

    assert_eq!(
        canonical_source_title_for_query(
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
            &source,
        ),
        "Marcellino Restaurant"
    );
}
