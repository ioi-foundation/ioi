use super::*;

#[test]
fn prefer_excerpt_for_query_prefers_identifier_bearing_excerpt_over_longer_generic_excerpt() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let generic = "NIST maintains post-quantum cryptography resources and migration guidance for agencies planning the transition.";
    let identifiers = "The Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 standardize ML-KEM, ML-DSA, and SLH-DSA.";

    let preferred = prefer_excerpt_for_query(query, generic.to_string(), identifiers.to_string());

    assert_eq!(preferred, identifiers);
}

#[test]
fn prefer_excerpt_for_query_prefers_clean_hint_over_script_heavy_menu_excerpt() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let noisy = "3907 Clemson Blvd STE A, Anderson, SC 29621 return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)); document.querySelector('.commentPopup').style.display = 'none'";
    let clean = "View the menu, hours, phone number, address and map for Red Tomato and Wine Restaurant in Anderson, SC.";

    let preferred = prefer_excerpt_for_query(query, noisy.to_string(), clean.to_string());

    assert_eq!(preferred, clean);
}

#[test]
fn prefer_excerpt_for_query_prefers_current_metric_excerpt_for_latest_pricing() {
    let query = "What is the latest OpenAI API pricing?";
    let metric_excerpt = "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs";
    let generic_hint = "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers.";

    let preferred =
        prefer_excerpt_for_query(query, metric_excerpt.to_string(), generic_hint.to_string());

    assert_eq!(preferred, metric_excerpt);
}

#[test]
fn next_pending_web_candidate_prefers_discovered_official_authority_when_identifier_coverage_is_missing(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://www.securityweek.com/nist-announces-hqc-as-fifth-standardized-post-quantum-algorithm/".to_string(),
            "https://www.ibm.com/think/topics/nist".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            "https://www.nist.gov/pqc".to_string(),
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.securityweek.com/nist-announces-hqc-as-fifth-standardized-post-quantum-algorithm/".to_string(),
                title: Some(
                    "NIST Announces HQC as Fifth Standardized Post-Quantum Algorithm"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected HQC as a fifth post-quantum algorithm after prior standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ibm.com/think/topics/nist".to_string(),
                title: Some("NIST overview topic".to_string()),
                excerpt: "IBM overview of NIST topics.".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
        ],
        blocked_urls: Vec::new(),
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            title: Some(
                "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                    .to_string(),
            ),
            excerpt:
                "March 11, 2025 - NIST selected HQC after finalizing FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some("https://csrc.nist.gov/pubs/fips/203/final")
    );
}

#[test]
fn next_pending_web_candidate_keeps_distinct_domain_probe_alive_for_low_signal_unseen_hosts() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            "https://www.ibm.com/think/topics/nist".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some(
                    "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM"
                        .to_string(),
                ),
                excerpt: "IBM overview of the NIST cybersecurity framework.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ibm.com/think/topics/nist".to_string(),
                title: Some("What is the NIST Cybersecurity Framework? | IBM".to_string()),
                excerpt: "IBM overview of NIST topics.".to_string(),
            },
        ],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some(
                    "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM"
                        .to_string(),
                ),
                excerpt: "IBM overview of the NIST cybersecurity framework.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ibm.com/think/topics/nist".to_string(),
                title: Some("What is the NIST Cybersecurity Framework? | IBM".to_string()),
                excerpt: "IBM overview of NIST topics.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let candidate = next_pending_web_candidate(&pending)
        .expect("expected a bounded unseen-domain follow-up candidate");
    assert!(
        candidate.starts_with("https://www.nist.gov/")
            || candidate.starts_with("https://csrc.nist.gov/"),
        "expected an unseen NIST-domain candidate, got {candidate}"
    );
}

#[test]
fn next_pending_web_candidate_prefers_canonical_publication_detail_over_generic_policy_page() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf".to_string(),
            "https://www.nist.gov/nist-information-quality-standards".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                    .to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/nist-information-quality-standards".to_string(),
                title: Some(
                    "NIST Guidelines, Information Quality Standards and Administrative Mechanism | NIST"
                        .to_string(),
                ),
                excerpt:
                    "Part I: Background, Mission, Definitions and Scope for NIST information quality guidelines."
                        .to_string(),
            },
        ],
        attempted_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
        blocked_urls: Vec::new(),
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
        }],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some("https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf")
    );
}

#[test]
fn next_pending_web_candidate_prefers_sparse_authority_pdf_hint_over_verbose_policy_page() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf".to_string(),
            "https://www.nist.gov/nist-information-quality-standards".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.nist.gov/nist-information-quality-standards".to_string(),
            title: Some(
                "NIST Guidelines, Information Quality Standards and Administrative Mechanism | NIST"
                    .to_string(),
            ),
            excerpt:
                "Part I: Background, Mission, Definitions and Scope for NIST information quality guidelines."
                    .to_string(),
        }],
        attempted_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
        blocked_urls: Vec::new(),
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
        }],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some("https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf")
    );
}

#[test]
fn next_pending_web_candidate_prefers_query_grounded_support_over_sponsored_or_opinion_hints() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                title: Some(
                    "Sponsored: Building organizational readiness for post-quantum cryptography"
                        .to_string(),
                ),
                excerpt:
                    "Sponsored briefing on organizational readiness for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.washingtontechnology.com/opinion/2025/06/why-federal-agencies-must-act-now-post-quantum-cryptography/405738/".to_string(),
                title: Some(
                    "Opinion: Why federal agencies must act now on post-quantum cryptography"
                        .to_string(),
                ),
                excerpt:
                    "Opinion essay urging agencies to move faster on post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                excerpt:
                    "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
                        .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 is the status report on the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some(
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
        )
    );
}

#[test]
fn next_pending_web_candidate_prefers_distinct_official_support_over_same_domain_authority_tail() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                .to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                .to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                    .to_string(),
                title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                excerpt:
                    "CSRC announced approval of the post-quantum cryptography FIPS standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                    .to_string(),
                title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                excerpt:
                    "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST released the first three finalized post-quantum encryption standards and urged administrators to begin transitioning."
                        .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some(
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
        )
    );
}

#[test]
fn next_pending_web_candidate_prefers_same_domain_authoritative_support_surface_over_duplicate_authority_tail(
) {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                .to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                .to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                    .to_string(),
                title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                excerpt:
                    "CSRC announced approval of the post-quantum cryptography FIPS standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                    .to_string(),
                title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                excerpt:
                    "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some(
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
        )
    );
}

#[test]
fn next_pending_web_candidate_prefers_cleaned_external_support_context_over_same_host_authority_tail(
) {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
            "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                excerpt:
                    "State of PQC Readiness 2025 | linked from Building organizational readiness for post-quantum cryptography | guidance on organizational readiness for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
                title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                excerpt:
                    "CSRC announced approval of the post-quantum cryptography FIPS standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
                title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                excerpt:
                    "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some("FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard".to_string()),
                excerpt: "Finalized NIST FIPS 203 post-quantum cryptography standard.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some("FIPS 204, Module-Lattice-Based Digital Signature Standard".to_string()),
                excerpt: "Finalized NIST FIPS 204 post-quantum cryptography standard.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
                title: Some("FIPS 205, Stateless Hash-Based Digital Signature Standard".to_string()),
                excerpt: "Finalized NIST FIPS 205 post-quantum cryptography standard.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some(
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
        )
    );
}

#[test]
fn next_pending_web_candidate_prefers_distinct_domain_support_after_first_authority_read() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
            "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            "https://csrc.nist.gov/pubs/ir/8547/ipd".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                excerpt:
                    "State of PQC Readiness 2025 | linked from Building organizational readiness for post-quantum cryptography | guidance on organizational readiness for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
                title: Some("NIST releases first 3 finalized post-quantum encryption standards".to_string()),
                excerpt:
                    "NIST finalized the first post-quantum cryptography standards including FIPS 203, FIPS 204 and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
                title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                excerpt:
                    "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8547/ipd".to_string(),
                title: Some("IR 8547 Initial Public Draft".to_string()),
                excerpt:
                    "NIST IR 8547 covers transition guidance for post-quantum cryptography."
                        .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some(
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
        )
    );
}

#[test]
fn next_pending_web_candidate_prefers_sparse_distinct_domain_pdf_support_after_first_authority_read(
) {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
            excerpt:
                "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        min_sources: 2,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some(
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
        )
    );
}

#[test]
fn next_pending_web_candidate_stops_when_only_low_priority_residual_hints_remain() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract,
        url: String::new(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 0,
        candidate_urls: vec![],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                title: Some(
                    "Sponsored: Building organizational readiness for post-quantum cryptography"
                        .to_string(),
                ),
                excerpt:
                    "Sponsored briefing on organizational readiness for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.washingtontechnology.com/opinion/2025/06/why-federal-agencies-must-act-now-post-quantum-cryptography/405738/".to_string(),
                title: Some(
                    "Opinion: Why federal agencies must act now on post-quantum cryptography"
                        .to_string(),
                ),
                excerpt:
                    "Opinion essay urging agencies to move faster on post-quantum cryptography."
                        .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 is the status report on the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    assert_eq!(next_pending_web_candidate(&pending), None);
}

#[test]
fn next_pending_web_candidate_keeps_sparse_headline_article_probe_alive() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092"
                .to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
                ),
                excerpt:
                    "Daily school assembly roundup with thought of the day and headline digest."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://m.economictimes.com/news/new-updates/school-assembly-news-headlines-for-march-7-top-national-international-business-sports-update-and-thought-of-the-day/articleshow/129151758.cms".to_string(),
                title: Some(
                    "School Assembly News Headlines for March 7 Top National International Business Sports Update and Thought of the Day".to_string(),
                ),
                excerpt:
                    "School assembly roundup with top national and international updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://bestcolleges.indiatoday.in/news-detail/school-assembly-news-headlines-today-march-7-top-national-sports-and-world-news-curated-for-you-8335".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 7 Top National Sports and World News Curated for You".to_string(),
                ),
                excerpt:
                    "Curated school assembly headlines and thought of the day."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    assert_eq!(
        next_pending_web_candidate(&pending).as_deref(),
        Some("https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092")
    );
}
