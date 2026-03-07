use super::*;
use crate::agentic::desktop::service::step::queue::support::{
    retrieval_contract_is_generic_headline_collection, retrieval_contract_min_sources,
    retrieval_contract_required_distinct_domain_floor,
};
use crate::agentic::desktop::service::step::queue::web_pipeline::resolved_query_contract_with_locality_hint;

include!("search/alignment.rs");

include!("search/discovery.rs");

include!("search/planning.rs");

#[cfg(test)]
mod tests {
    use super::{
        planning_bundle_after_surface_filter, pre_read_batch_urls,
        pre_read_candidate_inventory_target,
    };
    use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};

    #[test]
    fn pre_read_candidate_inventory_target_preserves_multisource_headroom() {
        assert_eq!(
            pre_read_candidate_inventory_target(None, "Tell me today's top news headlines.", 3, 3),
            5
        );
        assert_eq!(
            pre_read_candidate_inventory_target(None, "What's the current price of Bitcoin?", 2, 2),
            3
        );
        assert_eq!(
            pre_read_candidate_inventory_target(None, "What's 247 × 38?", 1, 1),
            1
        );
    }

    #[test]
    fn pre_read_batch_urls_limits_execution_batch_without_discarding_order() {
        let batch = pre_read_batch_urls(
            &[
                "https://example.com/one".to_string(),
                " ".to_string(),
                "https://example.com/two".to_string(),
                "https://example.com/three".to_string(),
            ],
            2,
        );
        assert_eq!(
            batch,
            vec![
                "https://example.com/one".to_string(),
                "https://example.com/two".to_string()
            ]
        );
    }

    #[test]
    fn planning_bundle_preserves_empty_surface_filter_result() {
        let entity_filtered_bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:bing:http".to_string(),
            query: Some("Find the three best-reviewed Italian restaurants near me.".to_string()),
            url: Some("https://example.com/search".to_string()),
            sources: vec![WebSource {
                source_id: "reddit".to_string(),
                rank: Some(1),
                url: "https://www.reddit.com/r/Italian/".to_string(),
                title: Some("Italian subreddit".to_string()),
                snippet: Some("Off-topic language discussion.".to_string()),
                domain: Some("www.reddit.com".to_string()),
            }],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: None,
        };
        let surface_filtered_bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:bing:http".to_string(),
            query: entity_filtered_bundle.query.clone(),
            url: entity_filtered_bundle.url.clone(),
            sources: vec![],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: None,
        };
        let mut verification_checks = Vec::new();

        let planning_bundle = planning_bundle_after_surface_filter(
            &entity_filtered_bundle,
            surface_filtered_bundle,
            &mut verification_checks,
        );

        assert!(planning_bundle.sources.is_empty());
        assert!(planning_bundle.documents.is_empty());
        assert!(verification_checks
            .iter()
            .any(|check| { check == "web_discovery_surface_filter_preserved_empty_bundle=true" }));
        assert!(verification_checks
            .iter()
            .all(|check| { check != "web_discovery_probe_fallback_to_pre_surface_bundle=true" }));
    }
}
