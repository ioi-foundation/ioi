use super::*;
use ioi_types::app::agentic::WebSource;

#[test]
fn document_briefing_plan_preserves_authority_candidates_while_enforcing_domain_diversity() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let nist_hqc_url =
        "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
    let nist_2024_url =
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
    let terra_url =
        "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        2,
        vec![
            nist_hqc_url.to_string(),
            nist_2024_url.to_string(),
            terra_url.to_string(),
        ],
        vec![
            PendingSearchReadSummary {
                url: nist_hqc_url.to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt: "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: nist_2024_url.to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt: "The finalized standards include FIPS 203 and ML-KEM.".to_string(),
            },
            PendingSearchReadSummary {
                url: terra_url.to_string(),
                title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205.".to_string(),
            },
        ],
        None,
        false,
    );

    assert_eq!(plan.candidate_urls.len(), 3, "{:?}", plan.candidate_urls);
    assert!(plan
        .candidate_urls
        .iter()
        .any(|url| url.contains("://www.nist.gov/")));
    assert!(plan
        .candidate_urls
        .iter()
        .any(|url| url.eq_ignore_ascii_case(nist_2024_url)));
    assert!(plan
        .candidate_urls
        .iter()
        .any(|url| url.eq_ignore_ascii_case(terra_url)));
}

#[test]
fn document_briefing_plan_prioritizes_current_authority_documents() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let nist_hqc_url =
        "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
    let nist_2024_url =
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        2,
        vec![nist_2024_url.to_string(), nist_hqc_url.to_string()],
        vec![
            PendingSearchReadSummary {
                url: nist_2024_url.to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: nist_hqc_url.to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected HQC in 2025 after finalizing FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
        ],
        None,
        false,
    );

    assert_eq!(
        plan.candidate_urls.first().map(String::as_str),
        Some(nist_hqc_url)
    );
}

#[test]
fn document_briefing_plan_demotes_generic_authority_pages_without_query_grounding() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let nist_hqc_url =
        "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
    let nist_2024_url =
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
    let nist_cyber_url = "https://www.nist.gov/cybersecurity-and-privacy";
    let nist_webbook_url = "https://webbook.nist.gov/chemistry/";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        2,
        vec![
            nist_cyber_url.to_string(),
            nist_webbook_url.to_string(),
            nist_hqc_url.to_string(),
            nist_2024_url.to_string(),
        ],
        vec![
            PendingSearchReadSummary {
                url: nist_cyber_url.to_string(),
                title: Some("Cybersecurity and Privacy | NIST".to_string()),
                excerpt: "NIST advances standards, measurement science, and cybersecurity guidance."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: nist_webbook_url.to_string(),
                title: Some("NIST Chemistry WebBook".to_string()),
                excerpt: "Reference data and chemistry resources from NIST.".to_string(),
            },
            PendingSearchReadSummary {
                url: nist_hqc_url.to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected HQC after finalizing FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: nist_2024_url.to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
                        .to_string(),
            },
        ],
        None,
        false,
    );

    assert_eq!(
        plan.candidate_urls
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>(),
        vec![nist_hqc_url.to_string(), nist_2024_url.to_string()]
    );
}

#[test]
fn document_briefing_plan_does_not_append_static_authority_seed_urls() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let external_url =
        "https://www.securityweek.com/nist-announces-hqc-as-fifth-standardized-post-quantum-algorithm/";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        2,
        vec![external_url.to_string()],
        vec![PendingSearchReadSummary {
            url: external_url.to_string(),
            title: Some(
                "NIST Announces HQC as Fifth Standardized Post-Quantum Algorithm".to_string(),
            ),
            excerpt: "NIST selected HQC after releasing FIPS 203, FIPS 204, and FIPS 205."
                .to_string(),
        }],
        None,
        false,
    );

    assert_eq!(plan.candidate_urls, vec![external_url.to_string()]);
}

#[test]
fn document_briefing_plan_keeps_identifier_backed_nist_detail_candidates_from_pending_inventory(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let ir_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let news_url = "https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms";
    let fips_203_url = "https://csrc.nist.gov/pubs/fips/203/final";
    let fips_204_url = "https://csrc.nist.gov/pubs/fips/204/final";
    let fips_205_url = "https://csrc.nist.gov/pubs/fips/205/final";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        2,
        vec![
            ir_url.to_string(),
            news_url.to_string(),
            fips_203_url.to_string(),
            fips_204_url.to_string(),
            fips_205_url.to_string(),
        ],
        vec![
            PendingSearchReadSummary {
                url: ir_url.to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 describes the post-quantum cryptography standards track and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: news_url.to_string(),
                title: Some(
                    "NIST Announces First Four Quantum-Resistant Cryptographic Algorithms"
                        .to_string(),
                ),
                excerpt:
                    "NIST announced the algorithms that later became FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: fips_203_url.to_string(),
                title: Some(
                    "Federal Information Processing Standard (FIPS) 203".to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 203 as part of the post-quantum cryptography standards set."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: fips_204_url.to_string(),
                title: Some(
                    "Federal Information Processing Standard (FIPS) 204".to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 204 as part of the post-quantum cryptography standards set."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: fips_205_url.to_string(),
                title: Some(
                    "Federal Information Processing Standard (FIPS) 205".to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 205 as part of the post-quantum cryptography standards set."
                        .to_string(),
            },
        ],
        None,
        true,
    );

    assert!(plan.candidate_urls.len() >= 2, "{:?}", plan.candidate_urls);
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(ir_url)),
        "{:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(fips_203_url)),
        "{:?}",
        plan.candidate_urls
    );
}

#[test]
fn document_briefing_plan_prunes_off_subject_brand_matched_top_up_candidates() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let nccoe_pdf_url =
        "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf";
    let ibm_csf_url = "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        2,
        vec![nccoe_pdf_url.to_string(), ibm_csf_url.to_string()],
        vec![
            PendingSearchReadSummary {
                url: nccoe_pdf_url.to_string(),
                title: Some(
                    "Migration to Post-Quantum Cryptography Quantum Readiness: Testing Draft Standards"
                        .to_string(),
                ),
                excerpt:
                    "NCCoE draft guidance covers migration to post-quantum cryptography for federal systems."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: ibm_csf_url.to_string(),
                title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
                excerpt:
                    "IBM explains the NIST Cybersecurity Framework 2.0 and broader cyber risk management."
                        .to_string(),
            },
        ],
        None,
        false,
    );

    assert_eq!(plan.candidate_urls, vec![nccoe_pdf_url.to_string()]);
    assert!(plan.requires_constraint_search_probe);
}

#[test]
fn document_briefing_plan_keeps_two_authority_candidates_from_nist_pqc_bundle() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let csrc_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let press_release_url =
        "https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms";
    let pdf_url = "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf";
    let bundle = ioi_types::app::agentic::WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "web.pipeline.test".to_string(),
        query: Some(query.to_string()),
        url: None,
        sources: vec![
            ioi_types::app::agentic::WebSource {
                source_id: "csrc".to_string(),
                rank: Some(1),
                url: csrc_url.to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                snippet: Some(
                    "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            ioi_types::app::agentic::WebSource {
                source_id: "pdf".to_string(),
                rank: Some(2),
                url: pdf_url.to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST IR 8413 Update 1 summarizes the post-quantum cryptography standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                ),
                domain: Some("nvlpubs.nist.gov".to_string()),
            },
            ioi_types::app::agentic::WebSource {
                source_id: "press-release".to_string(),
                rank: Some(3),
                url: press_release_url.to_string(),
                title: Some(
                    "NIST Announces First Four Quantum-Resistant Cryptographic Algorithms"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST announced the first selected algorithms in its post-quantum cryptography standardization effort."
                        .to_string(),
                ),
                domain: Some("www.nist.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: retrieval_contract.clone(),
    };

    let plan =
        pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
            retrieval_contract.as_ref(),
            query,
            2,
            &bundle,
            None,
            true,
        );

    assert!(plan.candidate_urls.len() >= 2, "{:?}", plan.candidate_urls);
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(csrc_url)),
        "{:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(pdf_url)),
        "{:?}",
        plan.candidate_urls
    );
}

#[test]
fn document_briefing_plan_preserves_distinct_official_news_support_from_run_shaped_bundle() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let csrc_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let csrc_project_url =
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization";
    let csrc_news_url =
        "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved";
    let nist_news_url =
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
    let bundle = ioi_types::app::agentic::WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "web.pipeline.test".to_string(),
        query: Some(query.to_string()),
        url: None,
        sources: vec![
            ioi_types::app::agentic::WebSource {
                source_id: "csrc-ir".to_string(),
                rank: Some(1),
                url: csrc_url.to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                snippet: Some(
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            ioi_types::app::agentic::WebSource {
                source_id: "csrc-project".to_string(),
                rank: Some(2),
                url: csrc_project_url.to_string(),
                title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                snippet: Some(
                    "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            ioi_types::app::agentic::WebSource {
                source_id: "csrc-news".to_string(),
                rank: Some(3),
                url: csrc_news_url.to_string(),
                title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                snippet: Some(
                    "CSRC announced approval of the post-quantum cryptography FIPS standards."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            ioi_types::app::agentic::WebSource {
                source_id: "nist-news".to_string(),
                rank: Some(4),
                url: nist_news_url.to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST released the first three finalized post-quantum encryption standards and urged administrators to begin transitioning."
                        .to_string(),
                ),
                domain: Some("www.nist.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: retrieval_contract.clone(),
    };

    let plan =
        pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
            retrieval_contract.as_ref(),
            query,
            2,
            &bundle,
            None,
            true,
        );

    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(csrc_url)),
        "{:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(nist_news_url)),
        "{:?}",
        plan.candidate_urls
    );
}

#[test]
fn document_briefing_plan_keeps_grounded_external_publication_artifact_from_run_shaped_bundle()
{
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let csrc_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let csrc_project_url =
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization";
    let tcg_pdf_url =
        "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf";
    let bundle = ioi_types::app::agentic::WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "web.pipeline.test".to_string(),
        query: Some(query.to_string()),
        url: None,
        sources: vec![
            ioi_types::app::agentic::WebSource {
                source_id: "csrc-ir".to_string(),
                rank: Some(1),
                url: csrc_url.to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                snippet: Some(
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            ioi_types::app::agentic::WebSource {
                source_id: "csrc-project".to_string(),
                rank: Some(2),
                url: csrc_project_url.to_string(),
                title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                snippet: Some(
                    "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            ioi_types::app::agentic::WebSource {
                source_id: "tcg-pqc-readiness".to_string(),
                rank: Some(3),
                url: tcg_pdf_url.to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                snippet: Some(
                    "State of PQC Readiness 2025 | linked from Building organizational readiness for post-quantum cryptography | guidance on organizational readiness for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("trustedcomputinggroup.org".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: retrieval_contract.clone(),
    };

    let plan =
        pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
            retrieval_contract.as_ref(),
            query,
            2,
            &bundle,
            None,
            true,
        );

    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(csrc_url)),
        "{:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(tcg_pdf_url)),
        "{:?}",
        plan.candidate_urls
    );
}

#[test]
fn document_briefing_plan_keeps_probe_required_for_same_host_authority_only_inventory() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let candidate_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
            .to_string(),
    ];
    let candidate_source_hints = vec![
        PendingSearchReadSummary {
            url: candidate_urls[0].clone(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: candidate_urls[1].clone(),
            title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
            excerpt:
                "CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                    .to_string(),
        },
    ];

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        2,
        candidate_urls.clone(),
        candidate_source_hints,
        None,
        false,
    );

    assert!(plan.candidate_urls.len() <= 2, "{:?}", plan.candidate_urls);
    assert!(plan.requires_constraint_search_probe);
}

#[test]
fn single_snapshot_pricing_plan_prioritizes_official_authority_surface() {
    let query = "What is the latest OpenAI API pricing?";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let official_url = "https://openai.com/api/pricing/";
    let third_party_url =
        "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        1,
        vec![third_party_url.to_string(), official_url.to_string()],
        vec![
            PendingSearchReadSummary {
                url: official_url.to_string(),
                title: Some("OpenAI API Pricing | OpenAI".to_string()),
                excerpt: "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: third_party_url.to_string(),
                title: Some(
                    "OpenAI API Pricing & Services - A Comprehensive Guide".to_string(),
                ),
                excerpt: "April 24, 2025 - OpenAI o4-mini: A cost-efficient alternative to the o3 model. Price: Input: $1.10 per 1M tokens."
                    .to_string(),
            },
        ],
        None,
        false,
    );

    assert_eq!(plan.candidate_urls.first().map(String::as_str), Some(official_url));
}

#[test]
fn single_snapshot_current_role_plan_prioritizes_identity_grounded_role_holder_surface() {
    let query = "Who is the current Secretary-General of the UN?";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
    let faq_url = "https://ask.un.org/faq/14625";
    let biography_url = "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres";
    let role_definition_url =
        "https://en.wikipedia.org/wiki/Secretary-General_of_the_United_Nations";

    let plan = pre_read_candidate_plan_with_contract(
        retrieval_contract.as_ref(),
        query,
        1,
        vec![
            role_definition_url.to_string(),
            biography_url.to_string(),
            faq_url.to_string(),
        ],
        vec![
            PendingSearchReadSummary {
                url: faq_url.to_string(),
                title: Some(
                    "Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                        .to_string(),
                ),
                excerpt:
                    "António Guterres is the current Secretary-General of the United Nations."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: biography_url.to_string(),
                title: Some("António Guterres - Wikipedia".to_string()),
                excerpt:
                    "Guterres was elected secretary-general in October 2016, succeeding Ban Ki-moon at the beginning of the following year."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: role_definition_url.to_string(),
                title: Some("Secretary-General of the United Nations - Wikipedia".to_string()),
                excerpt:
                    "The secretary-general of the United Nations is the Head of the United Nations Secretariat."
                        .to_string(),
            },
        ],
        None,
        false,
    );

    assert_eq!(plan.candidate_urls.first().map(String::as_str), Some(faq_url));
    assert!(
        !plan.candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(role_definition_url)),
        "{:?}",
        plan.candidate_urls
    );
}

#[test]
fn headline_plan_keeps_distinct_article_domains_from_constrained_inventory() {
    let query = "Tell me today's top news headlines.";
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:google-news-rss".to_string(),
        query: Some(query.to_string()),
        url: Some("https://news.google.com/rss/search?q=top+headlines".to_string()),
        sources: vec![
            WebSource {
                source_id: "fox-main".to_string(),
                rank: Some(1),
                url: "https://www.foxnews.com/us/example-breaking-story".to_string(),
                title: Some("Emergency response declared after major storm".to_string()),
                snippet: Some(
                    "Officials declared an emergency response Wednesday morning."
                        .to_string(),
                ),
                domain: Some("foxnews.com".to_string()),
            },
            WebSource {
                source_id: "fox-politics".to_string(),
                rank: Some(2),
                url: "https://www.foxnews.com/politics/example-policy-shift".to_string(),
                title: Some("Senate leaders announce policy framework".to_string()),
                snippet: Some(
                    "Leaders announced a bipartisan framework in Washington."
                        .to_string(),
                ),
                domain: Some("foxnews.com".to_string()),
            },
            WebSource {
                source_id: "reuters".to_string(),
                rank: Some(3),
                url: "https://www.reuters.com/world/europe/example-story/".to_string(),
                title: Some("European ministers agree on emergency aid package".to_string()),
                snippet: Some(
                    "Ministers agreed to an aid package after overnight talks."
                        .to_string(),
                ),
                domain: Some("reuters.com".to_string()),
            },
            WebSource {
                source_id: "ap".to_string(),
                rank: Some(4),
                url: "https://apnews.com/article/example-story".to_string(),
                title: Some("Federal agency expands investigation into outage".to_string()),
                snippet: Some(
                    "Agency officials expanded an investigation late Tuesday.".to_string(),
                ),
                domain: Some("apnews.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };
    assert!(retrieval_contract_is_generic_headline_collection(None, query));

    let (candidate_urls, candidate_source_hints) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(query, 3, &bundle, None);
    let diagnostics = candidate_source_hints
        .iter()
        .map(|hint| {
            (
                hint.url.clone(),
                headline_source_is_low_quality(
                    &hint.url,
                    hint.title.as_deref().unwrap_or_default(),
                    &hint.excerpt,
                ),
                retrieval_affordances_with_locality_hint(
                    query,
                    3,
                    &candidate_source_hints,
                    None,
                    &hint.url,
                    hint.title.as_deref().unwrap_or_default(),
                    &hint.excerpt,
                ),
                is_search_hub_url(&hint.url),
            )
        })
        .collect::<Vec<_>>();
    let plan = pre_read_candidate_plan_with_contract(
        None,
        query,
        3,
        candidate_urls,
        candidate_source_hints,
        None,
        false,
    );

    assert_eq!(plan.candidate_urls.len(), 3, "{plan:?} diagnostics={diagnostics:?}");
}
