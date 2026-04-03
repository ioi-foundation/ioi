use super::*;
use crate::agentic::desktop::service::step::queue::support::{
    merge_url_sequence, pre_read_candidate_plan_with_contract,
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
        briefing_authority_link_expansion_required,
        briefing_authority_link_out_sources_from_html, briefing_authority_seed_admission,
        defer_search_planning_failure_while_recovery_actions_remain,
        deterministic_local_business_expansion_alignment_urls, effective_semantic_alignment_urls,
        planning_bundle_after_surface_filter, pre_read_batch_urls,
        pre_read_candidate_inventory_target,
    };
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use ioi_types::app::agentic::WebRetrievalContract;
    use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};
    use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
    use std::collections::{BTreeMap, VecDeque};

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [9u8; 32],
            goal: "find restaurants".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::default(),
            current_tier: ExecutionTier::default(),
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

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
    fn briefing_authority_link_expansion_required_when_count_meets_floor_but_selection_is_not_quality_ready(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let discovery_sources = vec![
            WebSource {
                source_id: "nist-news".to_string(),
                rank: Some(1),
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards".to_string(),
                ),
                snippet: Some(
                    "National Institute of Standards and Technology (.gov) | source_url=https://www.nist.gov".to_string(),
                ),
                domain: Some("www.nist.gov".to_string()),
            },
            WebSource {
                source_id: "nist-photonic".to_string(),
                rank: Some(2),
                url: "https://www.nist.gov/news-events/news/2026/03/nist-researchers-develop-photonic-chip-packaging-can-withstand-extreme".to_string(),
                title: Some(
                    "NIST Researchers Develop Photonic Chip Packaging That Can Withstand Extreme Environments"
                        .to_string(),
                ),
                snippet: Some(
                    "National Institute of Standards and Technology (.gov) | source_url=https://www.nist.gov".to_string(),
                ),
                domain: Some("www.nist.gov".to_string()),
            },
        ];

        assert!(briefing_authority_link_expansion_required(
            &retrieval_contract,
            query,
            &discovery_sources,
            2,
        ));
    }

    #[test]
    fn briefing_authority_link_expansion_skips_when_query_is_not_document_briefing() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let discovery_sources = vec![
            WebSource {
                source_id: "restaurant-a".to_string(),
                rank: Some(1),
                url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-/"
                    .to_string(),
                title: Some(
                    "Dolce Vita Italian Bistro, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                        .to_string(),
                ),
                snippet: Some(
                    "Italian bistro in Anderson, SC with pizza, pasta, calzones and dessert."
                        .to_string(),
                ),
                domain: Some("www.restaurantji.com".to_string()),
            },
            WebSource {
                source_id: "restaurant-b".to_string(),
                rank: Some(2),
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                    .to_string(),
                title: Some(
                    "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                        .to_string(),
                ),
                snippet: Some(
                    "Italian restaurant in Anderson, SC serving pizza, pasta and subs."
                        .to_string(),
                ),
                domain: Some("www.restaurantji.com".to_string()),
            },
        ];

        assert!(!briefing_authority_link_expansion_required(
            &retrieval_contract,
            query,
            &discovery_sources,
            2,
        ));
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

    #[test]
    fn briefing_authority_link_out_sources_surface_public_authority_links_from_external_article() {
        let html = r#"
            <html>
              <head><title>IBM overview of NIST standards</title></head>
              <body>
                <article>
                  <p>IBM summarizes the latest NIST post-quantum cryptography standards.</p>
                  <a href="https://csrc.nist.gov/pubs/fips/204/final">Federal Information Processing Standard (FIPS) 204</a>
                  <a href="https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards">NIST releases first 3 finalized post-quantum encryption standards</a>
                  <a href="https://www.facebook.com/share.php?u=https://www.ibm.com/think/insights/nist-pqc-standards">Share on Facebook</a>
                  <a href="/think/insights/another-ibm-article">Another IBM article</a>
                </article>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &crate::agentic::web::derive_web_retrieval_contract(
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                Some("Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."),
            )
            .expect("contract"),
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
            "https://www.ibm.com/think/insights/nist-pqc-standards",
            "https://www.ibm.com/think/insights/nist-pqc-standards",
            html,
            2,
            6,
        );
        let urls = sources
            .iter()
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>();

        assert!(
            urls.iter()
                .any(|url| url.contains("csrc.nist.gov/pubs/fips/204/final")),
            "expected CSRC authority link-out, got: {:?}",
            urls
        );
        assert!(
            urls.iter()
                .any(|url| url.contains("www.nist.gov/news-events/news/2024/08")),
            "expected NIST news authority link-out, got: {:?}",
            urls
        );
        assert!(
            !urls.iter().any(|url| url.contains("facebook.com")),
            "social share links should not be surfaced as authority expansion candidates: {:?}",
            urls
        );
        assert!(
            !urls.iter().any(|url| url.contains("another-ibm-article")),
            "same-host article links should not be treated as authority link-outs: {:?}",
            urls
        );
    }

    #[test]
    fn briefing_authority_link_expansion_keeps_same_host_deep_authority_documents() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let seed_url = "https://csrc.nist.gov/projects/post-quantum-cryptography";
        let html = r#"
            <html>
              <head>
                <title>Post-Quantum Cryptography | CSRC</title>
                <meta
                  name="description"
                  content="NIST project page for post-quantum cryptography standards and publications."
                />
              </head>
              <body>
                <a href="/pubs/fips/203/final">Post-Quantum Cryptography FIPS 203 Final</a>
                <a href="/projects">Projects</a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            seed_url,
            seed_url,
            html,
            2,
            8,
        );
        let urls = sources
            .iter()
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>();

        assert!(
            urls.iter()
                .any(|url| url == &"https://csrc.nist.gov/pubs/fips/203/final"),
            "expected same-host authority document, got: {:?}",
            urls
        );
        assert!(
            !urls.iter().any(|url| url == &"https://csrc.nist.gov/projects"),
            "shallow project navigation should not be surfaced as an authority expansion candidate: {:?}",
            urls
        );
    }

    #[test]
    fn briefing_authority_link_expansion_uses_page_context_for_minimal_same_host_titles() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let seed_url = "https://csrc.nist.gov/projects/post-quantum-cryptography";
        let html = r#"
            <html>
              <head>
                <title>Post-Quantum Cryptography | CSRC</title>
                <meta
                  name="description"
                  content="NIST project page for post-quantum cryptography standards and migration guidance."
                />
              </head>
              <body>
                <a href="/pubs/fips/203/final">Module-Lattice-Based<br />(ML-KEM)</a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            seed_url,
            seed_url,
            html,
            2,
            8,
        );
        let urls = sources
            .iter()
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>();

        assert!(
            urls.iter()
                .any(|url| url == &"https://csrc.nist.gov/pubs/fips/203/final"),
            "expected page context to preserve same-host authority document, got: {:?}",
            urls
        );
    }

    #[test]
    fn briefing_authority_link_expansion_ranks_publication_docs_ahead_of_navigation_links() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let seed_url = "https://csrc.nist.gov/projects/post-quantum-cryptography";
        let html = r#"
            <html>
              <head>
                <title>Post-Quantum Cryptography | CSRC</title>
                <meta
                  name="description"
                  content="PQC Standards and migration guidance for the latest NIST post-quantum cryptography standards."
                />
              </head>
              <body>
                <a href="/Groups/Computer-Security-Division/Cryptographic-Technology">Cryptographic Technology</a>
                <a href="/Projects/post-quantum-cryptography/publications">Publications</a>
                <a data-csrc-pub-link="true" href="/pubs/fips/203/final">Module-Lattice-Based Key-Encapsulation Mechanism Standard</a>
                <a data-csrc-pub-link="true" href="/pubs/fips/204/final">Module-Lattice-Based Digital Signature Standard</a>
                <a data-csrc-pub-link="true" href="/pubs/fips/205/final">Stateless Hash-Based Digital Signature Standard</a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            seed_url,
            seed_url,
            html,
            2,
            3,
        );
        let urls = sources
            .iter()
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>();

        assert_eq!(sources.len(), 3, "sources={sources:?}");
        assert!(
            urls.iter()
                .any(|url| url == &"https://csrc.nist.gov/pubs/fips/203/final"),
            "expected FIPS 203 to outrank navigation links, got: {:?}",
            urls
        );
        assert!(
            urls.iter()
                .any(|url| url == &"https://csrc.nist.gov/pubs/fips/204/final"),
            "expected FIPS 204 to outrank navigation links, got: {:?}",
            urls
        );
        assert!(
            urls.iter()
                .any(|url| url == &"https://csrc.nist.gov/pubs/fips/205/final"),
            "expected FIPS 205 to outrank navigation links, got: {:?}",
            urls
        );
        assert!(
            !urls.iter().any(|url| url.contains("/Groups/")),
            "generic navigation links should not crowd out publication docs when the limit is tight: {:?}",
            urls
        );
    }

    #[test]
    fn briefing_authority_link_expansion_preserves_domain_diversity_when_required() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let seed_url = "https://csrc.nist.gov/projects/post-quantum-cryptography";
        let html = r#"
            <html>
              <head>
                <title>Post-Quantum Cryptography | CSRC</title>
                <meta
                  name="description"
                  content="PQC Standards and migration guidance for the latest NIST post-quantum cryptography standards."
                />
              </head>
              <body>
                <a data-csrc-pub-link="true" href="/pubs/fips/203/final">Module-Lattice-Based Key-Encapsulation Mechanism Standard</a>
                <a data-csrc-pub-link="true" href="/pubs/fips/204/final">Module-Lattice-Based Digital Signature Standard</a>
                <a data-csrc-pub-link="true" href="/pubs/fips/205/final">Stateless Hash-Based Digital Signature Standard</a>
                <a href="https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards">NIST releases first 3 finalized post-quantum encryption standards</a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            seed_url,
            seed_url,
            html,
            2,
            2,
        );
        let urls = sources
            .iter()
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>();

        assert_eq!(sources.len(), 2, "sources={sources:?}");
        assert!(
            urls.iter()
                .any(|url| url.contains("csrc.nist.gov/pubs/fips/")),
            "expected one PQC publication from CSRC, got: {:?}",
            urls
        );
        assert!(
            urls.iter()
                .any(|url| url.contains("www.nist.gov/news-events/news/2024/08")),
            "expected one official NIST news source to preserve domain diversity, got: {:?}",
            urls
        );
    }

    #[test]
    fn briefing_authority_link_expansion_rejects_external_policy_links_grounded_only_by_page_context(
    ) {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let seed_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
        let html = r#"
            <html>
              <head>
                <title>IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC</title>
                <meta
                  name="description"
                  content="Current authoritative publication for the latest NIST post-quantum cryptography standards and migration status."
                />
              </head>
              <body>
                <a href="https://csrc.nist.gov/pubs/ir/8413/final">IR 8413 Final</a>
                <a href="https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards">NIST releases first 3 finalized post-quantum encryption standards</a>
                <a href="https://www.nist.gov/no-fear-act-policy">No Fear Act Policy</a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            seed_url,
            seed_url,
            html,
            2,
            4,
        );
        let urls = sources
            .iter()
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>();

        assert!(
            urls.iter()
                .any(|url| url == &"https://csrc.nist.gov/pubs/ir/8413/final"),
            "expected IR 8413 final authority document, got: {:?}",
            urls
        );
        assert!(
            urls.iter().any(|url| {
                url == &"https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            }),
            "expected official NIST news item with local query grounding, got: {:?}",
            urls
        );
        assert!(
            !urls
                .iter()
                .any(|url| url == &"https://www.nist.gov/no-fear-act-policy"),
            "page-context-only utility policy links should not survive authority expansion: {:?}",
            urls
        );
    }

    #[test]
    fn briefing_authority_link_expansion_keeps_external_support_snippet_clean_from_low_priority_seed(
    ) {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let seed_url =
            "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/";
        let html = r#"
            <html>
              <head>
                <title>Sponsored: Building organizational readiness for post-quantum cryptography</title>
                <meta
                  name="description"
                  content="Sponsored guidance on organizational readiness for post-quantum cryptography."
                />
              </head>
              <body>
                <a href="https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf">
                  State of PQC Readiness 2025
                </a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            seed_url,
            seed_url,
            html,
            2,
            4,
        );
        let support_source = sources
            .iter()
            .find(|source| {
                source.url
                    == "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
            })
            .expect("expected external support candidate");
        let snippet = support_source
            .snippet
            .as_deref()
            .expect("support snippet should be present");

        assert!(
            snippet.contains("State of PQC Readiness 2025"),
            "expected weak external title to remain in snippet: {snippet}"
        );
        assert!(
            snippet
                .to_ascii_lowercase()
                .contains("post-quantum cryptography"),
            "expected cleaned seed context to preserve query-grounding text: {snippet}"
        );
        assert!(
            !snippet.to_ascii_lowercase().contains("sponsored"),
            "external support snippet should stay clean of low-priority seed rhetoric: {snippet}"
        );
    }

    #[test]
    fn briefing_authority_link_expansion_keeps_same_host_query_grounded_project_seed() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let seed_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
        let html = r#"
            <html>
              <head>
                <title>IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC</title>
                <meta
                  name="description"
                  content="Current authoritative publication for the latest NIST post-quantum cryptography standards and migration status."
                />
              </head>
              <body>
                <a href="https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization">PQC Standardization Project</a>
                <a href="https://csrc.nist.gov/projects">Projects</a>
                <a href="https://csrc.nist.gov/pubs/ir/8413/final">IR 8413 Final</a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            seed_url,
            seed_url,
            html,
            2,
            4,
        );
        let urls = sources
            .iter()
            .map(|source| source.url.as_str())
            .collect::<Vec<_>>();

        assert!(
            urls.iter().any(|url| {
                url == &"https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
            }),
            "expected same-host PQC project seed for authoritative recovery, got: {:?}",
            urls
        );
        assert!(
            !urls
                .iter()
                .any(|url| url == &"https://csrc.nist.gov/projects"),
            "generic same-host navigation should still be rejected: {:?}",
            urls
        );
    }

    #[test]
    fn briefing_authority_seed_admission_accepts_authority_seed_without_snippet_grounding() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");

        let admission = briefing_authority_seed_admission(
            &retrieval_contract,
            query,
            2,
            "https://csrc.nist.gov/projects/post-quantum-cryptography",
            "Post-Quantum Cryptography | CSRC",
            "",
        );

        assert!(
            !admission.query_grounded,
            "empty discovery snippets should not count as grounded"
        );
        assert!(
            !admission.identifier_bearing,
            "project page should not need synthetic identifier hits to become fetchable"
        );
        assert!(
            admission.document_authority,
            "authority seed should still be recognized from URL/title/host signals"
        );
        assert!(
            admission.admitted(),
            "authority seed should be admitted for expansion even when the provider snippet is empty"
        );
    }

    #[test]
    fn briefing_authority_seed_admission_rejects_non_authority_seed() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");

        let admission = briefing_authority_seed_admission(
            &retrieval_contract,
            query,
            2,
            "https://example.com/company/blog",
            "Company blog",
            "",
        );

        assert!(!admission.query_grounded);
        assert!(!admission.identifier_bearing);
        assert!(!admission.document_authority);
        assert!(!admission.admitted());
    }

    #[test]
    fn briefing_authority_link_out_sources_skip_off_topic_public_authority_links() {
        let html = r#"
            <html>
              <head><title>IBM overview of the NIST Cybersecurity Framework</title></head>
              <body>
                <article>
                  <p>IBM discusses the NIST Cybersecurity Framework in detail.</p>
                  <a href="https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final">The NIST Cybersecurity Framework CSF 2.0</a>
                  <a href="https://www.nist.gov/cyberframework/framework-version-10">Framework Version 1.0</a>
                </article>
              </body>
            </html>
        "#;

        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
            Some("Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."),
        )
        .expect("contract");
        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2",
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2",
            html,
            2,
            6,
        );

        assert!(sources.is_empty(), "sources={sources:?}");
    }

    #[test]
    fn semantic_alignment_selection_urls_include_resolved_source_urls() {
        let urls = effective_semantic_alignment_urls(&[WebSource {
            source_id: "google-news-item".to_string(),
            rank: Some(1),
            url: "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
            title: Some("NIST releases first 3 finalized post-quantum encryption standards".to_string()),
            snippet: Some("NIST releases first 3 finalized post-quantum encryption standards | source_url=https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string()),
            domain: Some("news.google.com".to_string()),
        }]);

        assert!(urls
            .iter()
            .any(|url| url.contains("news.google.com/rss/articles/")));
        assert!(urls.iter().any(|url| {
            url.contains("nist-releases-first-3-finalized-post-quantum-encryption-standards")
        }));
    }

    #[test]
    fn search_planning_failure_is_nonterminal_while_other_web_recovery_actions_remain() {
        let query_contract =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let retrieval_contract: WebRetrievalContract =
            crate::agentic::web::derive_web_retrieval_contract(query_contract, None)
                .expect("retrieval contract");
        let mut agent_state = test_agent_state();
        agent_state.pending_search_completion =
            Some(crate::agentic::desktop::types::PendingSearchCompletion {
                query: "italian restaurants in Anderson, SC".to_string(),
                query_contract: query_contract.to_string(),
                retrieval_contract: Some(retrieval_contract),
                url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
                started_step: 1,
                started_at_ms: 1,
                deadline_ms: 60_000,
                candidate_urls: vec![],
                candidate_source_hints: vec![],
                attempted_urls: vec![],
                blocked_urls: vec![],
                successful_reads: vec![],
                min_sources: 3,
            });
        agent_state.execution_queue.push(ActionRequest {
            target: ActionTarget::WebRetrieve,
            params: serde_jcs::to_vec(&serde_json::json!({
                "query": "\"Brothers Italian Cuisine\" menus in Anderson, SC"
            }))
            .expect("params"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(agent_state.session_id),
                window_id: None,
            },
            nonce: 1,
        });
        let mut verification_checks = Vec::new();
        let mut success = false;
        let mut err = Some("ERROR_CLASS=SynthesisFailed placeholder".to_string());

        let deferred = defer_search_planning_failure_while_recovery_actions_remain(
            &mut agent_state,
            &mut verification_checks,
            &mut success,
            &mut err,
            "no semantically aligned discovery sources",
        );

        assert!(deferred);
        assert!(success);
        assert!(err.is_none());
        assert!(verification_checks
            .iter()
            .any(|check| { check == "web_pre_read_payload_error_nonterminal=true" }));
        assert!(verification_checks
            .iter()
            .any(|check| { check == "web_queued_web_recovery_actions_remaining=1" }));
    }

    #[test]
    fn deterministic_local_business_expansion_alignment_keeps_grounded_detail_pages() {
        let query_contract =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let expanded_sources = vec![
            WebSource {
                source_id: "brothers".to_string(),
                rank: Some(1),
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                    .to_string(),
                title: Some("Brothers Italian Cuisine".to_string()),
                snippet: Some(
                    "5.0 rating from 226 reviews | Italian restaurant in Anderson, SC.".to_string(),
                ),
                domain: Some("www.restaurantji.com".to_string()),
            },
            WebSource {
                source_id: "olive-garden".to_string(),
                rank: Some(2),
                url: "https://www.restaurantji.com/sc/anderson/olive-garden-italian-restaurant-/"
                    .to_string(),
                title: Some("Olive Garden Italian Restaurant".to_string()),
                snippet: Some(
                    "4.2 rating from 198 reviews | Pasta and Italian classics in Anderson, SC."
                        .to_string(),
                ),
                domain: Some("www.restaurantji.com".to_string()),
            },
            WebSource {
                source_id: "red-tomato".to_string(),
                rank: Some(3),
                url: "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/"
                    .to_string(),
                title: Some("Red Tomato and Wine Restaurant".to_string()),
                snippet: Some(
                    "4.6 rating from 312 reviews | Italian menu and wine in Anderson, SC."
                        .to_string(),
                ),
                domain: Some("www.restaurantji.com".to_string()),
            },
        ];

        let aligned_urls = deterministic_local_business_expansion_alignment_urls(
            query_contract,
            Some("Anderson, SC"),
            &expanded_sources,
            3,
        );

        assert_eq!(aligned_urls.len(), 3);
        assert!(aligned_urls
            .iter()
            .any(|url| url.contains("brothers-italian-cuisine")));
        assert!(aligned_urls
            .iter()
            .any(|url| url.contains("olive-garden-italian-restaurant")));
        assert!(aligned_urls
            .iter()
            .any(|url| url.contains("red-tomato-and-wine-restaurant")));
    }
}
