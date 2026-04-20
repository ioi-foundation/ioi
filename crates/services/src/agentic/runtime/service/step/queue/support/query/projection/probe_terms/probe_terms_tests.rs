use super::*;

#[test]
fn probe_host_exclusions_preserve_discovered_authority_hosts_for_identifier_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let projection = build_query_constraint_projection(query, 2, &[]);
    let candidate_hints = vec![
        PendingSearchReadSummary {
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            excerpt:
                "NIST finalized FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
                    .to_string(),
        },
    ];

    let terms = projection_probe_host_exclusion_terms(query, &projection, &candidate_hints);

    assert!(
        !terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
        "terms={terms:?}"
    );
}

#[test]
fn probe_host_exclusions_preserve_grounded_public_authority_hosts_for_document_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let projection = build_query_constraint_projection(query, 2, &[]);
    let candidate_hints = vec![
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

    let terms = projection_probe_host_exclusion_terms(query, &projection, &candidate_hints);

    assert!(
        !terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
        "terms={terms:?}"
    );
}

#[test]
fn document_briefing_probe_terms_add_public_authority_site_when_only_secondary_hints_exist() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let candidate_hints = vec![
        PendingSearchReadSummary {
            url: "https://www.ibm.com/think/topics/nist".to_string(),
            title: Some("What is the NIST Cybersecurity Framework? | IBM".to_string()),
            excerpt: "IBM overview of NIST cybersecurity frameworks and standards.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some(
                "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string(),
            ),
            excerpt: "IBM details NIST topics without an official NIST host.".to_string(),
        },
    ];

    let terms = query_probe_document_authority_site_terms(
        query,
        Some(&retrieval_contract),
        &candidate_hints,
    );

    assert!(
        terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
        "terms={terms:?}"
    );
    assert!(
        terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("site:www.nist.gov")),
        "terms={terms:?}"
    );
}

#[test]
fn document_briefing_probe_terms_skip_public_authority_site_when_authority_slot_is_satisfied() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let candidate_hints = vec![
        PendingSearchReadSummary {
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            excerpt:
                "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as the first post-quantum standards."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            title: Some(
                "NIST’s post-quantum cryptography standards are here - IBM Research"
                    .to_string(),
            ),
            excerpt:
                "IBM summarized FIPS 203, FIPS 204, and FIPS 205 after NIST released the standards."
                    .to_string(),
        },
    ];

    let terms = query_probe_document_authority_site_terms(
        query,
        Some(&retrieval_contract),
        &candidate_hints,
    );

    assert!(terms.is_empty(), "terms={terms:?}");
}

#[test]
fn document_briefing_probe_terms_keep_authority_site_expansion_when_floor_is_still_unmet() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let candidate_hints = vec![PendingSearchReadSummary {
        url: "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf".to_string(),
        title: Some(
            "Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards - National Institute of Standards and Technology (.gov)"
                .to_string(),
        ),
        excerpt:
            "Testing draft standards for migration to post-quantum cryptography without the finalized FIPS identifiers yet."
                .to_string(),
    }];

    let terms = query_probe_document_authority_site_terms(
        query,
        Some(&retrieval_contract),
        &candidate_hints,
    );

    assert!(
        terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
        "terms={terms:?}"
    );
    assert!(
        terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("site:www.nist.gov")),
        "terms={terms:?}"
    );
    assert!(
        terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("site:nccoe.nist.gov")),
        "terms={terms:?}"
    );
}

#[test]
fn document_briefing_probe_terms_skip_publication_path_scope_once_grounded_authority_is_present(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let candidate_hints = vec![PendingSearchReadSummary {
        url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        title: Some(
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                .to_string(),
        ),
        excerpt:
            "NIST IR 8413 summarizes the post-quantum cryptography standardization process."
                .to_string(),
    }];

    let terms = query_probe_document_authority_site_terms(
        query,
        Some(&retrieval_contract),
        &candidate_hints,
    );

    assert!(terms.is_empty(), "terms={terms:?}");
}

#[test]
fn document_briefing_probe_terms_skip_publication_path_scope_without_uppercase_authority_token_once_grounded_authority_is_present(
) {
    let query =
        "research the latest nist post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let candidate_hints = vec![PendingSearchReadSummary {
        url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        title: Some(
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                .to_string(),
        ),
        excerpt:
            "NIST IR 8413 summarizes the post-quantum cryptography standardization process."
                .to_string(),
    }];

    let terms = query_probe_document_authority_site_terms(
        query,
        Some(&retrieval_contract),
        &candidate_hints,
    );

    assert!(terms.is_empty(), "terms={terms:?}");
}

#[test]
fn document_briefing_probe_terms_exclude_grounded_authority_hosts_when_domain_diversity_is_unmet(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let candidate_hints = vec![
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

    let terms = query_probe_grounded_authority_host_exclusion_terms(
        query,
        Some(&retrieval_contract),
        &candidate_hints,
    );

    assert!(
        terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
        "terms={terms:?}"
    );
    assert!(
        !terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
        "terms={terms:?}"
    );
    assert!(
        !terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("-site:gov")),
        "terms={terms:?}"
    );
}
