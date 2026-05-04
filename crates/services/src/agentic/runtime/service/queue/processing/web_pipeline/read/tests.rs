use super::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        None,
    )
    .expect("retrieval contract")
}

#[test]
fn gated_document_briefing_read_is_absorbed_as_blocked_candidate() {
    let gated_url = "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved";
    let fallback_url = "https://qramm.org/learn/nist-pqc-standards.html";
    let mut pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_briefing_contract()),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1,
        deadline_ms: 60_000,
        candidate_urls: vec![gated_url.to_string(), fallback_url.to_string()],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: gated_url.to_string(),
                title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                excerpt: "The Secretary of Commerce approved FIPS 203, FIPS 204 and FIPS 205."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: fallback_url.to_string(),
                title: Some(
                    "NIST Post-Quantum Cryptography Standards: Complete Guide to FIPS 203, 204, and 205"
                        .to_string(),
                ),
                excerpt:
                    "NIST released FIPS 203, FIPS 204 and FIPS 205 as production-ready standards."
                        .to_string(),
            },
        ],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                    .to_string(),
            ),
            excerpt:
                "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                    .to_string(),
        }],
        min_sources: 2,
    };
    let mut verification_checks = Vec::new();

    let absorbed = absorb_blocked_pending_web_read_candidate(
        &mut pending,
        gated_url,
        true,
        None,
        &mut verification_checks,
    );

    assert!(absorbed);
    assert!(pending.blocked_urls.iter().any(|url| url == gated_url));
    assert_eq!(
        crate::agentic::runtime::service::queue::support::next_pending_web_candidate(&pending)
            .as_deref(),
        Some(fallback_url)
    );
    assert!(verification_checks
        .iter()
        .any(|check| check == "web_gated_read_absorbed_as_blocked_candidate=true"));
}

#[test]
fn document_briefing_selected_source_alignment_uses_final_successful_reads() {
    let query_contract =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        "https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms".to_string(),
        "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
    ];
    let successful_reads = vec![
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt: "NIST IR 8413 Update 1 tracks the current post-quantum cryptography standardization process and references FIPS 203, FIPS 204, and FIPS 205.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "NIST documents the post-quantum cryptography standards process and the selected algorithms."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms".to_string(),
            title: Some("Post-Quantum Cryptography | CSRC".to_string()),
            excerpt: "The selected algorithms page links the NIST post-quantum cryptography project to FIPS 203, FIPS 204, and FIPS 205.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204, Module-Lattice-Based Digital Signature Standard | CSRC".to_string(),
            ),
            excerpt:
                "NIST finalized FIPS 204 as one of the first post-quantum cryptography standards."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
            title: Some(
                "FIPS 205, Stateless Hash-Based Digital Signature Standard | CSRC".to_string(),
            ),
            excerpt:
                "NIST finalized FIPS 205 as one of the first post-quantum cryptography standards."
                    .to_string(),
        },
    ];

    let mut aligned_urls = selected_source_alignment_urls_from_successful_reads(
        query_contract,
        Some(&nist_briefing_contract()),
        &selected_urls,
        &successful_reads,
    );
    let mut expected_urls = selected_urls.clone();
    aligned_urls.sort();
    expected_urls.sort();

    assert_eq!(aligned_urls, expected_urls);
}

#[test]
fn document_briefing_selected_source_alignment_accepts_grounded_external_pdf_support() {
    let query_contract =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
            .to_string(),
    ];
    let successful_reads = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 Update 1 tracks the current post-quantum cryptography standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("91% of organizations".to_string()),
            excerpt:
                "Industry readiness report for quantum-safe migration and deployment planning."
                    .to_string(),
        },
    ];

    let aligned_urls = selected_source_alignment_urls_from_successful_reads(
        query_contract,
        Some(&nist_briefing_contract()),
        &selected_urls,
        &successful_reads,
    );
    let support_urls = selected_source_support_artifact_urls_from_successful_reads(
        query_contract,
        Some(&nist_briefing_contract()),
        &selected_urls,
        &successful_reads,
    );
    let aligned_set = aligned_urls
        .iter()
        .map(|url| url.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let support_set = support_urls
        .iter()
        .map(|url| url.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();

    let floor_met = selected_urls.iter().all(|url| {
        let normalized = url.to_ascii_lowercase();
        aligned_set.contains(&normalized) || support_set.contains(&normalized)
    }) && !aligned_urls.is_empty();

    assert_eq!(support_urls, vec![selected_urls[1].clone()]);
    assert!(aligned_urls.contains(&selected_urls[0]));
    assert!(floor_met);
}

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [7u8; 32],
        goal: "find restaurants".to_string(),
        runtime_route_frame: None,
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
        mode: crate::agentic::runtime::types::AgentMode::default(),
        current_tier: crate::agentic::runtime::types::ExecutionTier::default(),
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

#[test]
fn local_business_menu_followup_read_is_queued_from_bundle_child_url() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract"),
        ),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1,
        deadline_ms: 60_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                .to_string(),
            title: Some(
                "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                .to_string(),
            title: Some(
                "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                    .to_string(),
        }],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: Some(query.to_string()),
        url: Some("https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/".to_string()),
        sources: vec![ioi_types::app::agentic::WebSource {
            source_id: "menu-1".to_string(),
            rank: Some(1),
            url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                .to_string(),
            title: Some("Menu".to_string()),
            snippet: Some(
                "View the menu, hours, phone number, address and map for Coach House Restaurant."
                    .to_string(),
            ),
            domain: Some("restaurantji.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: pending.retrieval_contract.clone(),
    };
    let mut verification_checks = Vec::new();
    let mut agent_state = test_agent_state();

    let queued = maybe_queue_local_business_menu_followup_reads(
        &mut agent_state,
        [7u8; 32],
        &mut pending,
        &bundle,
        "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/",
        &mut verification_checks,
    )
    .expect("menu followup queued");

    assert!(queued);
    assert!(pending.candidate_urls.iter().any(|url| {
        url == "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
    }));
    assert!(agent_state.execution_queue.iter().any(|request| {
        serde_json::from_slice::<serde_json::Value>(&request.params)
            .ok()
            .and_then(|value| {
                value
                    .get("url")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
            .as_deref()
            == Some("https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/")
    }));
    assert!(verification_checks
        .iter()
        .any(|check| check.contains("web_local_business_menu_followup_url_values=")));
}
