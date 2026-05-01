use super::*;

#[test]
fn briefing_subject_guard_rejects_off_topic_authority_neighbor_article() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let good = WebSource {
        source_id: "nist-csrc".to_string(),
        rank: Some(1),
        url: "https://csrc.nist.gov/projects/post-quantum-cryptography".to_string(),
        title: Some("Post-Quantum Cryptography | CSRC".to_string()),
        snippet: Some(
            "NIST project page for post-quantum cryptography standards and publications."
                .to_string(),
        ),
        domain: Some("csrc.nist.gov".to_string()),
    };
    let bad = WebSource {
        source_id: "ibm-es".to_string(),
        rank: Some(2),
        url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
            .to_string(),
        title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
        snippet: Some(
            "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos.".to_string(),
        ),
        domain: Some("www.ibm.com".to_string()),
    };

    assert!(
        semantically_aligned_discovery_source_passes_briefing_subject_guard(
            &retrieval_contract,
            query,
            &good,
        )
    );
    assert!(
        !semantically_aligned_discovery_source_passes_briefing_subject_guard(
            &retrieval_contract,
            query,
            &bad,
        )
    );
}

#[test]
fn briefing_subject_guard_keeps_direct_fips_publication_pages() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let source = WebSource {
        source_id: "nist-fips-203".to_string(),
        rank: Some(1),
        url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
        title: Some("FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard".to_string()),
        snippet: Some(
            "NIST finalized FIPS 203 as a post-quantum cryptography standard."
                .to_string(),
        ),
        domain: Some("csrc.nist.gov".to_string()),
    };

    assert!(
        semantically_aligned_discovery_source_passes_briefing_subject_guard(
            &retrieval_contract,
            query,
            &source,
        )
    );
}

#[test]
fn semantically_aligned_discovery_sources_prioritize_primary_authority_before_generic_clusters()
{
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let ranked = rank_semantically_aligned_discovery_sources(
        &retrieval_contract,
        query,
        vec![
            WebSource {
                source_id: "ibm-br".to_string(),
                rank: Some(1),
                url: "https://www.ibm.com/br-pt/think/topics/nist".to_string(),
                title: Some("O que e o NIST Cybersecurity Framework? - IBM".to_string()),
                snippet: Some("IBM overview of NIST cybersecurity topics.".to_string()),
                domain: Some("www.ibm.com".to_string()),
            },
            WebSource {
                source_id: "ibm-es".to_string(),
                rank: Some(2),
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some(
                    "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string(),
                ),
                snippet: Some("IBM details NIST topics without the finalized standards.".to_string()),
                domain: Some("www.ibm.com".to_string()),
            },
            WebSource {
                source_id: "washington-post".to_string(),
                rank: Some(3),
                url: "https://www.washingtonpost.com/politics/2026/03/31/judge-trump-white-house-ballroom/"
                    .to_string(),
                title: Some("Judge allows White House ballroom plan".to_string()),
                snippet: Some("Unrelated politics coverage.".to_string()),
                domain: Some("www.washingtonpost.com".to_string()),
            },
            WebSource {
                source_id: "nist-csrc".to_string(),
                rank: Some(11),
                url: "https://csrc.nist.gov/Projects/post-quantum-cryptography/workshops-and-timeline"
                    .to_string(),
                title: Some("Post-Quantum Cryptography Workshops and Timeline".to_string()),
                snippet: Some("NIST timeline for post-quantum cryptography standards and workshops.".to_string()),
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: "nist-news".to_string(),
                rank: Some(12),
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
                title: Some(
                    "NIST releases first 3 finalized post-quantum encryption standards"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("www.nist.gov".to_string()),
            },
        ],
    );

    let top_urls = ranked
        .iter()
        .take(2)
        .map(|source| source.url.as_str())
        .collect::<Vec<_>>();
    assert!(
        top_urls
            .iter()
            .any(|url| url.contains("nist.gov") || url.contains("csrc.nist.gov")),
        "top_urls={top_urls:?}"
    );
    assert!(
        !top_urls
            .iter()
            .any(|url| url.contains("washingtonpost.com")),
        "top_urls={top_urls:?}"
    );
}
