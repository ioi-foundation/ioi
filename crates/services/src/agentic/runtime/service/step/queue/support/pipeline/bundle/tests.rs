use super::*;
use ioi_types::app::agentic::WebSource;

#[test]
fn candidate_source_hints_resolve_wrapper_source_url_metadata() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:google-news-rss".to_string(),
        query: Some("today top news headlines".to_string()),
        url: Some("https://news.google.com/rss/search?q=today+top+news+headlines".to_string()),
        sources: vec![WebSource {
            source_id: "google-item-1".to_string(),
            rank: Some(1),
            url: "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
            title: Some("Sample Story".to_string()),
            snippet: Some(
                "Reuters | source_url=https://www.reuters.com/world/europe/example-story-2026-03-01/"
                    .to_string(),
            ),
            domain: Some("reuters.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let hints = candidate_source_hints_from_bundle_ranked(&bundle);
    assert_eq!(hints.len(), 1);
    assert_eq!(
        hints[0].url,
        "https://www.reuters.com/world/europe/example-story-2026-03-01/"
    );
}

#[test]
fn constrained_inventory_preserves_primary_authority_sources_for_document_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing-search-rss".to_string(),
        query: Some(query.to_string()),
        url: Some(
            "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards&format=rss"
                .to_string(),
        ),
        sources: vec![
            WebSource {
                source_id: "secondary-cyberscoop".to_string(),
                rank: Some(1),
                url: "https://cyberscoop.com/why-federal-it-leaders-must-act-now-to-deliver-nists-post-quantum-cryptography-transition-op-ed/".to_string(),
                title: Some(
                    "Why federal IT leaders must act now to deliver NIST's post-quantum cryptography transition".to_string(),
                ),
                snippet: Some(
                    "CyberScoop analysis of NIST post-quantum cryptography transition guidance."
                        .to_string(),
                ),
                domain: Some("cyberscoop.com".to_string()),
            },
            WebSource {
                source_id: "official-nist-pqc".to_string(),
                rank: Some(2),
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                snippet: Some(
                    "December 8, 2025 - These Federal Information Processing Standards (FIPS) are mandatory for federal systems and adopted around the world."
                        .to_string(),
                ),
                domain: Some("nist.gov".to_string()),
            },
            WebSource {
                source_id: "secondary-cybersecuritydive".to_string(),
                rank: Some(3),
                url: "https://www.cybersecuritydive.com/news/nist-post-quantum-cryptography-guidance-mapping/760638/".to_string(),
                title: Some(
                    "NIST expands post-quantum cryptography guidance mapping".to_string(),
                ),
                snippet: Some(
                    "Cybersecurity Dive covers NIST post-quantum cryptography transition guidance."
                        .to_string(),
                ),
                domain: Some("cybersecuritydive.com".to_string()),
            },
            WebSource {
                source_id: "official-nist-news".to_string(),
                rank: Some(4),
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST releases first 3 finalized post-quantum encryption standards"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("nist.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: Some(retrieval_contract),
    };

    let (urls, _) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(query, 2, &bundle, None);

    let pqc_idx = urls
        .iter()
        .position(|url| url == "https://www.nist.gov/pqc")
        .expect("nist pqc page retained");
    let news_idx = urls
        .iter()
        .position(|url| {
            url
                == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
        })
        .expect("nist news page retained");
    let cyberscoop_idx = urls
        .iter()
        .position(|url| {
            url
                == "https://cyberscoop.com/why-federal-it-leaders-must-act-now-to-deliver-nists-post-quantum-cryptography-transition-op-ed/"
        })
        .expect("secondary source retained");

    assert!(pqc_idx < cyberscoop_idx);
    assert!(news_idx < cyberscoop_idx);
}

#[test]
fn constrained_inventory_prioritizes_current_authority_identifier_expansion_sources() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing-search-rss".to_string(),
        query: Some(query.to_string()),
        url: Some(
            "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards&format=rss"
                .to_string(),
        ),
        sources: vec![
            WebSource {
                source_id: "official-nist-2024".to_string(),
                rank: Some(1),
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST releases first 3 finalized post-quantum encryption standards"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("nist.gov".to_string()),
            },
            WebSource {
                source_id: "official-nist-2025".to_string(),
                rank: Some(2),
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST selected HQC after finalizing FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                ),
                domain: Some("nist.gov".to_string()),
            },
            WebSource {
                source_id: "secondary".to_string(),
                rank: Some(3),
                url: "https://example.com/analysis/nist-pqc".to_string(),
                title: Some("Independent analysis of NIST PQC".to_string()),
                snippet: Some(
                    "Independent analysis summarizes FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                ),
                domain: Some("example.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: Some(retrieval_contract),
    };

    let (urls, _) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(query, 2, &bundle, None);

    assert_eq!(
        urls.first().map(String::as_str),
        Some(
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
        )
    );
}

#[test]
fn constrained_inventory_prioritizes_official_pricing_authority_surface() {
    let query = "What is the latest OpenAI API pricing?";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let official_url = "https://openai.com/api/pricing/";
    let third_party_url =
        "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services";
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:brave:http".to_string(),
        query: Some(query.to_string()),
        url: Some("https://search.brave.com/search?q=openai+api+pricing".to_string()),
        sources: vec![
            WebSource {
                source_id: "official-openai-pricing".to_string(),
                rank: Some(1),
                url: official_url.to_string(),
                title: Some("OpenAI API Pricing | OpenAI".to_string()),
                snippet: Some(
                    "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers."
                        .to_string(),
                ),
                domain: Some("openai.com".to_string()),
            },
            WebSource {
                source_id: "third-party-pricing".to_string(),
                rank: Some(2),
                url: third_party_url.to_string(),
                title: Some(
                    "OpenAI API Pricing & Services - A Comprehensive Guide".to_string(),
                ),
                snippet: Some(
                    "April 24, 2025 - OpenAI o4-mini: A cost-efficient alternative to the o3 model. Price: Input: $1.10 per 1M tokens."
                        .to_string(),
                ),
                domain: Some("www.arsturn.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: Some(retrieval_contract),
    };

    let (urls, _) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(query, 1, &bundle, None);

    assert_eq!(urls.first().map(String::as_str), Some(official_url));
}

#[test]
fn constrained_inventory_prioritizes_current_role_holder_surface_over_biography() {
    let query = "Who is the current Secretary General of the UN?";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let faq_url = "https://ask.un.org/faq/14625";
    let biography_url = "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres";
    let role_definition_url =
        "https://en.wikipedia.org/wiki/Secretary-General_of_the_United_Nations";
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:search:aggregate:test".to_string(),
        query: Some("who secretary general".to_string()),
        url: Some("https://search.brave.com/search?q=who+secretary+general".to_string()),
        sources: vec![
            WebSource {
                source_id: "ask-un".to_string(),
                rank: Some(1),
                url: faq_url.to_string(),
                title: Some(
                    "UN Ask DAG ask.un.org › faq › 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                        .to_string(),
                ),
                snippet: Some(
                    "António Guterres is the current Secretary-General of the United Nations."
                        .to_string(),
                ),
                domain: Some("ask.un.org".to_string()),
            },
            WebSource {
                source_id: "un-role-definition".to_string(),
                rank: Some(4),
                url: role_definition_url.to_string(),
                title: Some(
                    "Wikipedia en.wikipedia.org › wiki › Secretary-General_of_the_United_Nations Secretary-General of the United Nations - Wikipedia"
                        .to_string(),
                ),
                snippet: Some(
                    "The secretary-general of the United Nations is the Head of the United Nations Secretariat."
                        .to_string(),
                ),
                domain: Some("en.wikipedia.org".to_string()),
            },
            WebSource {
                source_id: "guterres-biography".to_string(),
                rank: Some(6),
                url: biography_url.to_string(),
                title: Some(
                    "Wikipedia en.wikipedia.org › wiki › António_Guterres António Guterres - Wikipedia"
                        .to_string(),
                ),
                snippet: Some(
                    "17 hours ago - Guterres was elected secretary-general in October 2016, succeeding Ban Ki-moon at the beginning of the following year and becoming the first European to hold this office since Kurt Waldheim in 1981."
                        .to_string(),
                ),
                domain: Some("en.wikipedia.org".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: Some(retrieval_contract),
    };

    let (urls, _) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(query, 1, &bundle, None);

    assert_eq!(urls.first().map(String::as_str), Some(faq_url), "{urls:?}");
    assert!(
        !urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(role_definition_url)),
        "{urls:?}"
    );
}

#[test]
fn constrained_inventory_preserves_distinct_headline_article_domains() {
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
                    "Officials declared an emergency response Wednesday morning.".to_string(),
                ),
                domain: Some("foxnews.com".to_string()),
            },
            WebSource {
                source_id: "fox-politics".to_string(),
                rank: Some(2),
                url: "https://www.foxnews.com/politics/example-policy-shift".to_string(),
                title: Some("Senate leaders announce policy framework".to_string()),
                snippet: Some(
                    "Leaders announced a bipartisan framework in Washington.".to_string(),
                ),
                domain: Some("foxnews.com".to_string()),
            },
            WebSource {
                source_id: "reuters".to_string(),
                rank: Some(3),
                url: "https://www.reuters.com/world/europe/example-story/".to_string(),
                title: Some("European ministers agree on emergency aid package".to_string()),
                snippet: Some(
                    "Ministers agreed to an aid package after overnight talks.".to_string(),
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

    let (urls, hints) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(query, 3, &bundle, None);

    let distinct_domains = urls
        .iter()
        .filter_map(|url| source_host(url))
        .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(hints.len(), 4, "{hints:?}");
    assert_eq!(distinct_domains.len(), 3, "{urls:?}");
}
