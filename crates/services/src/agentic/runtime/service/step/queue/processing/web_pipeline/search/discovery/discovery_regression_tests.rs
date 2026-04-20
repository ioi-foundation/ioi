use super::*;

#[test]
fn authority_link_expansion_prefers_official_publication_artifact_over_stale_news() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
    let html = r#"
        <html>
          <body>
            <a href="https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms">
              NIST Announces First Four Quantum-Resistant Cryptographic Algorithms
            </a>
            <a href="https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf">
              Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process
            </a>
          </body>
        </html>
    "#;

    let sources = briefing_authority_link_out_sources_from_html(
        &retrieval_contract,
        query,
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
        html,
        2,
        2,
    );

    assert_eq!(sources.len(), 2, "{sources:?}");
    assert_eq!(
        sources[0].url,
        "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
    );
}

#[test]
fn authority_link_expansion_filters_generic_same_host_authority_pages_for_semantic_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
    let html = r#"
        <html>
          <head>
            <title>Cybersecurity and privacy | NIST</title>
            <meta
              name="description"
              content="NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources."
            />
          </head>
          <body>
            <a href="/about-nist">About NIST</a>
            <a href="/about-nist/work-nist">Work at NIST</a>
            <a href="/publications/search/topic/248731">Publications</a>
            <a href="/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards">
              NIST Releases First 3 Finalized Post-Quantum Encryption Standards
            </a>
          </body>
        </html>
    "#;

    let sources = briefing_authority_link_out_sources_from_html(
        &retrieval_contract,
        query,
        "https://www.nist.gov/cybersecurity-and-privacy",
        "https://www.nist.gov/cybersecurity-and-privacy",
        html,
        2,
        4,
    );
    let urls = sources.iter().map(|source| source.url.as_str()).collect::<Vec<_>>();

    assert!(
        urls.iter().any(|url| url.eq_ignore_ascii_case(
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
        )),
        "{urls:?}"
    );
    assert!(
        urls.iter()
            .all(|url| !url.eq_ignore_ascii_case("https://www.nist.gov/about-nist")),
        "{urls:?}"
    );
    assert!(
        urls.iter().all(|url| !url.eq_ignore_ascii_case(
            "https://www.nist.gov/about-nist/work-nist"
        )),
        "{urls:?}"
    );
}
