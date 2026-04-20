use super::{WebRetrievalAffordance, WebSourceExpansionAffordance};

#[test]
fn retrieval_affordance_names_remain_structural_and_domain_agnostic() {
    let affordances = [
        WebRetrievalAffordance::QueryableIndex,
        WebRetrievalAffordance::OrderedCollection,
        WebRetrievalAffordance::LinkCollection,
        WebRetrievalAffordance::DetailDocument,
        WebRetrievalAffordance::StructuredRecord,
        WebRetrievalAffordance::TimestampedRecord,
        WebRetrievalAffordance::GeoScopedRecord,
        WebRetrievalAffordance::CanonicalLinkOut,
        WebRetrievalAffordance::BrowserRetrieval,
    ];
    let banned_tokens = [
        "news",
        "menu",
        "restaurant",
        "price",
        "weather",
        "bitcoin",
        "google",
        "bing",
        "coindesk",
        "restaurantji",
    ];

    for affordance in affordances {
        let serialized = serde_json::to_string(&affordance)
            .expect("affordance should serialize")
            .trim_matches('"')
            .to_string();
        assert!(
            banned_tokens
                .iter()
                .all(|token| !serialized.contains(token)),
            "affordance '{}' leaked a domain/provider token",
            serialized
        );
    }
}

#[test]
fn source_expansion_affordance_names_remain_structural_and_domain_agnostic() {
    let affordances = [
        WebSourceExpansionAffordance::JsonLdItemList,
        WebSourceExpansionAffordance::ChildLinkCollection,
    ];
    let banned_tokens = [
        "news",
        "menu",
        "restaurant",
        "price",
        "weather",
        "bitcoin",
        "google",
        "bing",
        "coindesk",
        "restaurantji",
    ];

    for affordance in affordances {
        let serialized = serde_json::to_string(&affordance)
            .expect("affordance should serialize")
            .trim_matches('"')
            .to_string();
        assert!(
            banned_tokens
                .iter()
                .all(|token| !serialized.contains(token)),
            "serialized affordance should remain structural: {serialized}"
        );
    }
}
