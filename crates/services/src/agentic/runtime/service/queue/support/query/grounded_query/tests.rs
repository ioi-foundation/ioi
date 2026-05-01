use super::*;

#[test]
fn grounded_search_query_does_not_inject_subject_specific_standard_identifiers() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();

    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &[],
        None,
    );

    assert!(!grounded.contains("\"FIPS 203\""), "query={grounded}");
    assert!(!grounded.contains("\"FIPS 204\""), "query={grounded}");
    assert!(!grounded.contains("\"FIPS 205\""), "query={grounded}");
    assert!(!grounded.contains("\"FIPS 206\""), "query={grounded}");
    assert!(!grounded.contains("\"HQC\""), "query={grounded}");
}

#[test]
fn grounded_search_query_strips_document_briefing_output_scaffolding() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();

    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &[],
        None,
    );
    let normalized = grounded.to_ascii_lowercase();

    assert!(
        normalized.contains("nist post quantum cryptography standards"),
        "query={grounded}"
    );
    assert!(!normalized.contains("local memory"), "query={grounded}");
    assert!(!normalized.contains("then return"), "query={grounded}");
    assert!(!normalized.contains("uncertainties"), "query={grounded}");
    assert!(!normalized.contains("next checks"), "query={grounded}");
}

#[test]
fn grounded_search_query_uses_local_business_discovery_basis_for_menu_comparison_queries() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");

    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        3,
        &[],
        Some("Anderson, SC"),
    );
    let normalized = grounded.to_ascii_lowercase();

    assert!(
        normalized.contains("italian restaurants in anderson")
            || normalized.contains("restaurants in anderson"),
        "query={grounded}"
    );
    assert!(!normalized.contains("compare"), "query={grounded}");
    assert!(!normalized.contains("menus"), "query={grounded}");
}

#[test]
fn grounded_probe_query_adds_public_authority_site_for_document_briefing_recovery() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.ibm.com/think/topics/nist".to_string(),
            title: Some("What is the NIST Cybersecurity Framework? | IBM".to_string()),
            excerpt: "IBM overview of NIST cybersecurity frameworks and standards.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
            excerpt: "IBM details NIST topics without an official NIST host.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        None,
    );

    let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        &grounded,
        None,
    )
    .expect("probe query should be generated");

    assert!(
        probe.to_ascii_lowercase().contains("site:nist.gov"),
        "probe={probe}"
    );
    assert!(
        probe.to_ascii_lowercase().contains("site:www.nist.gov"),
        "probe={probe}"
    );
}

#[test]
fn grounded_probe_query_does_not_blacklist_public_authority_recovery_host() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/Projects/post-quantum-cryptography/workshops-and-timeline".to_string(),
            title: Some("Post-Quantum Cryptography Workshops and Timeline | CSRC".to_string()),
            excerpt:
                "NIST post-quantum cryptography workshops and timeline for standards development."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf".to_string(),
            title: Some(
                "Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards - National Institute of Standards and Technology (.gov)"
                    .to_string(),
            ),
            excerpt:
                "Testing draft standards for migration to post-quantum cryptography."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some(
                "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string(),
            ),
            excerpt:
                "IBM overview of the NIST cybersecurity framework and related standards."
                    .to_string(),
        },
    ];
    let initial_query = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &[],
        None,
    );

    let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        &initial_query,
        None,
    )
    .expect("probe query should be generated");

    assert!(
        !probe.to_ascii_lowercase().contains("-site:nist.gov"),
        "probe={probe}"
    );
}

#[test]
fn grounded_probe_query_pivots_to_corroboration_after_authority_slot_is_satisfied() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                .to_string(),
            title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
            excerpt:
                "FIPS 203, FIPS 204, and FIPS 205 are approved post-quantum cryptography standards."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 documents the NIST post-quantum cryptography standardization process."
                    .to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        None,
    );

    let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        &grounded,
        None,
    )
    .expect("probe query should be generated");

    assert!(
        probe
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
        "probe={probe}"
    );
    assert!(
        !probe
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
        "probe={probe}"
    );
    assert!(
        !probe
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
        "probe={probe}"
    );
}

#[test]
fn grounded_probe_query_adds_identifier_terms_from_authority_backed_hints() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
        title: Some(
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                .to_string(),
        ),
        excerpt:
            "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as the first post-quantum standards."
                .to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        None,
    );

    let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        &grounded,
        None,
    )
    .expect("probe query should be generated");

    assert!(probe.contains("\"FIPS 203\""), "probe={probe}");
    assert!(probe.contains("\"FIPS 204\""), "probe={probe}");
    assert!(probe.contains("\"FIPS 205\""), "probe={probe}");
}

#[test]
fn grounded_probe_query_pivots_away_from_path_scoped_authority_site_once_authority_slot_is_satisfied(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let hints = vec![PendingSearchReadSummary {
        url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        title: Some(
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                .to_string(),
        ),
        excerpt:
            "NIST IR 8413 Update 1 references the finalized post-quantum cryptography standards."
                .to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        None,
    );

    let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        &grounded,
        None,
    )
    .expect("probe query should be generated");

    assert!(
        probe
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
        "probe={probe}"
    );
    assert!(
        !probe
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("site:csrc.nist.gov/pubs")),
        "probe={probe}"
    );
}

#[test]
fn grounded_probe_query_omits_legacy_excerpt_fips_reference_for_ir_publication() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let hints = vec![PendingSearchReadSummary {
        url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        title: Some(
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                .to_string(),
        ),
        excerpt:
            "IR 8413 Update 1 notes that the new public-key standards will augment Federal Information Processing Standard (FIPS) 186-4."
                .to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        None,
    );

    let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &hints,
        &grounded,
        None,
    )
    .expect("probe query should be generated");

    assert!(!probe.contains("\"FIPS 186\""), "probe={probe}");
    assert!(
        probe
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
        "probe={probe}"
    );
}

#[test]
fn grounded_search_query_bootstraps_public_authority_site_for_document_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");

    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        Some(&contract),
        2,
        &[],
        None,
    );

    assert!(
        grounded.to_ascii_lowercase().contains("site:nist.gov"),
        "grounded={grounded}"
    );
    assert!(
        grounded.to_ascii_lowercase().contains("site:www.nist.gov"),
        "grounded={grounded}"
    );
    assert!(
        !grounded
            .to_ascii_lowercase()
            .contains("\"nist post quantum cryptography\""),
        "grounded={grounded}"
    );
    assert!(
        !grounded.to_ascii_lowercase().contains("web utc timestamp"),
        "grounded={grounded}"
    );
    assert!(
        !grounded.to_ascii_lowercase().contains("utc timestamp"),
        "grounded={grounded}"
    );
}
