use super::*;
use ioi_types::app::agentic::{WebDocument, WebEvidenceBundle, WebQuoteSpan, WebSource};

#[test]
fn headline_read_success_url_rejects_root_homepages() {
    assert!(!headline_read_success_url_allowed(
        "https://www.cbsnews.com/"
    ));
    assert!(!headline_read_success_url_allowed(
        "https://www.nbcnews.com/"
    ));
}

#[test]
fn headline_read_success_url_accepts_deep_article_urls() {
    assert!(headline_read_success_url_allowed(
        "https://www.reuters.com/world/europe/example-story-2026-03-01/"
    ));
    assert!(headline_read_success_url_allowed(
        "https://news.google.com/rss/articles/CBMiY2h0dHBzOi8vd3d3LmFwbmV3cy5jb20vYXJ0aWNsZS9leGFtcGxlLXN0b3J5LTIwMjYtMDMtMDFSAQA"
    ));
}

#[test]
fn push_pending_web_success_blocks_security_checkpoint_interstitials() {
    let mut pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                None,
            )
            .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![
            "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans"
                .to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans"
                .to_string(),
            title: Some(
                "NIST's post-quantum cryptography standards: our plans".to_string(),
            ),
            excerpt:
                "HashiCorp outlines the newly finalized NIST post-quantum standards and migration planning."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 3,
    };

    push_pending_web_success(
        &mut pending,
        "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans",
        Some("Vercel Security Checkpoint".to_string()),
        "Please complete the security check to continue.".to_string(),
    );

    assert!(pending.successful_reads.is_empty());
    assert_eq!(
        pending.blocked_urls,
        vec![
            "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans"
                .to_string()
        ]
    );
}

#[test]
fn push_pending_web_success_upgrades_duplicate_url_with_identifier_bearing_excerpt() {
    let requested_url = "https://www.nist.gov/pqc";
    let mut pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                None,
            )
            .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            excerpt: "NIST maintains migration guidance for post-quantum cryptography.".to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 3,
    };

    push_pending_web_success(
        &mut pending,
        requested_url,
        Some("Post-quantum cryptography | NIST".to_string()),
        "NIST maintains post-quantum cryptography migration guidance for agencies.".to_string(),
    );
    push_pending_web_success(
        &mut pending,
        requested_url,
        Some("Post-quantum cryptography | NIST".to_string()),
        "The Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 standardize ML-KEM, ML-DSA, and SLH-DSA."
            .to_string(),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0].excerpt.contains("FIPS 203")
            && pending.successful_reads[0].excerpt.contains("FIPS 204")
            && pending.successful_reads[0].excerpt.contains("FIPS 205"),
        "expected upgraded identifier-bearing excerpt, got: {:?}",
        pending.successful_reads[0]
    );
}

#[test]
fn push_pending_web_success_prefers_hint_identifier_excerpt_for_document_briefing_queries() {
    let requested_url =
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
    let mut pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                None,
            )
            .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            excerpt:
                "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as the first post-quantum standards."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };

    push_pending_web_success(
        &mut pending,
        requested_url,
        Some("NIST Releases First 3 Finalized Post-Quantum Encryption Standards".to_string()),
        "NIST released the first finalized post-quantum encryption standards.".to_string(),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0].excerpt.contains("FIPS 203")
            && pending.successful_reads[0].excerpt.contains("FIPS 204")
            && pending.successful_reads[0].excerpt.contains("FIPS 205"),
        "expected hint-backed identifier coverage to be preserved, got: {:?}",
        pending.successful_reads[0]
    );
}

#[test]
fn push_pending_web_success_prefers_metric_excerpt_for_current_pricing_queries() {
    let requested_url = "https://openai.com/api/pricing/";
    let mut pending = PendingSearchCompletion {
        query: "What is the latest OpenAI API pricing?".to_string(),
        query_contract: "What is the latest OpenAI API pricing?".to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(
                "What is the latest OpenAI API pricing?",
                None,
            )
            .expect("retrieval contract"),
        ),
        url: "https://search.brave.com/search?q=openai+api+pricing".to_string(),
        started_step: 1,
        started_at_ms: 1_776_229_080_000,
        deadline_ms: 1_776_229_200_000,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("OpenAI API Pricing | OpenAI".to_string()),
            excerpt: "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers.".to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 1,
    };

    push_pending_web_success(
        &mut pending,
        requested_url,
        Some("OpenAI API Pricing | OpenAI".to_string()),
        "Our frontier models are designed to spend more time thinking before producing a response, making them ideal for complex, multi-step problems.\n\nPricing above reflects standard processing rates for context lengths under 270K.\n\nNow: 1 GB for $0.03 / 64GB for $1.92 per container Starting March 31, 2026: 1 GB for $0.03 / 64GB for $1.92 per 20-minute session pass.\n\nAudio: $32.00 for inputs $0.40 for cached inputs $64.00 for outputs Text: $4.00 for inputs $0.40 for cached inputs $16.00 for outputs Image: $5.00 for inputs $0.50 for cached inputs\n\nState-of-the-art image generation model.\n\nImage: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs".to_string(),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    let excerpt = pending.successful_reads[0].excerpt.as_str();
    assert!(
        excerpt.contains("$32.00") || excerpt.contains("$8.00"),
        "expected stored excerpt to preserve pricing metrics, got: {excerpt}"
    );
    assert!(
        contains_current_condition_metric_signal(excerpt),
        "expected stored excerpt to preserve current metric grounding, got: {excerpt}"
    );
    assert!(
        !excerpt.contains("1 GB for $0.03") && !excerpt.contains("per container"),
        "expected stored excerpt to avoid unrelated container pricing, got: {excerpt}"
    );
}

#[test]
fn append_pending_web_success_from_bundle_prefers_query_aligned_quote_span_for_latest_openai_pricing(
) {
    let requested_url = "https://openai.com/api/pricing/";
    let query = "What is the latest OpenAI API pricing?";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://search.brave.com/search?q=openai+api+pricing".to_string(),
        started_step: 1,
        started_at_ms: 1_776_229_080_000,
        deadline_ms: 1_776_229_200_000,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("OpenAI API Pricing | OpenAI".to_string()),
            excerpt: "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools."
                .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 1,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_776_229_081_000,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "openai-pricing".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some("OpenAI API Pricing | OpenAI".to_string()),
            snippet: Some(
                "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools."
                    .to_string(),
            ),
            domain: Some("openai.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "openai-pricing".to_string(),
            url: requested_url.to_string(),
            title: Some("OpenAI API Pricing | OpenAI".to_string()),
            content_text: concat!(
                "Our frontier models are designed to spend more time thinking before producing a response, ",
                "making them ideal for complex, multi-step problems.\n\n",
                "Our cheapest GPT-5.4-class model for simple high-volume tasks.\n\n",
                "Pricing above reflects standard processing rates for context lengths under 270K.\n\n",
                "Now: 1 GB for $0.03 / 64GB for $1.92 per container. ",
                "Starting March 31, 2026: 1 GB for $0.03 / 64GB for $1.92 per 20-minute session pass.\n\n",
                "State-of-the-art image generation model.\n\n",
                "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs ",
                "Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs"
            )
            .to_string(),
            content_hash: "openai-pricing-doc".to_string(),
            quote_spans: vec![
                WebQuoteSpan {
                    start_byte: 0,
                    end_byte: 128,
                    quote: "Our frontier models are designed to spend more time thinking before producing a response, making them ideal for complex, multi-step problems.".to_string(),
                },
                WebQuoteSpan {
                    start_byte: 220,
                    end_byte: 370,
                    quote: "Now: 1 GB for $0.03 / 64GB for $1.92 per container. Starting March 31, 2026: 1 GB for $0.03 / 64GB for $1.92 per 20-minute session pass.".to_string(),
                },
                WebQuoteSpan {
                    start_byte: 420,
                    end_byte: 568,
                    quote: "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs".to_string(),
                },
            ],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    let excerpt = pending.successful_reads[0].excerpt.as_str();
    assert!(
        excerpt.contains("Image: $8.00")
            && excerpt.contains("Text: $5.00")
            && excerpt.contains("$32.00"),
        "expected pricing quote-span excerpt, got: {excerpt}"
    );
    assert!(
        !excerpt.contains("1 GB for $0.03") && !excerpt.contains("per container"),
        "expected unrelated storage/session quote to be rejected, got: {excerpt}"
    );
}

#[test]
fn append_pending_web_success_from_bundle_blocks_security_checkpoint_documents() {
    let requested_url =
        "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans";
    let mut pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                None,
            )
            .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("NIST's post-quantum cryptography standards: our plans".to_string()),
            excerpt:
                "HashiCorp outlines the newly finalized NIST post-quantum standards and migration planning."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "hashicorp".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some(
                "HashiCorp hashicorp.com › en › blog › nist-s-post-quantum-cryptography-standards-our-plans NIST’s post-quantum cryptography standards: Our plans"
                    .to_string(),
            ),
            snippet: Some(String::new()),
            domain: Some("hashicorp.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "hashicorp".to_string(),
            url: requested_url.to_string(),
            title: Some("Vercel Security Checkpoint".to_string()),
            content_text: "Please complete the security check to continue.".to_string(),
            content_hash: "hashicorp-checkpoint".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(pending.successful_reads.is_empty());
    assert_eq!(pending.blocked_urls, vec![requested_url.to_string()]);
}

#[test]
fn append_pending_web_success_from_bundle_prefers_identifier_bearing_excerpt_for_briefing_queries()
{
    let requested_url = "https://www.nist.gov/pqc";
    let mut pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                None,
            )
            .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "nist-pqc".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            snippet: Some(
                "Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 are now available."
                    .to_string(),
            ),
            domain: Some("nist.gov".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "nist-pqc".to_string(),
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            content_text: "NIST maintains resources for post-quantum cryptography migration. The Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 standardize ML-KEM, ML-DSA, and SLH-DSA for federal systems. Agencies should prepare transition plans.".to_string(),
            content_hash: "nist-pqc-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0].excerpt.contains("FIPS 203")
            && pending.successful_reads[0].excerpt.contains("FIPS 204")
            && pending.successful_reads[0].excerpt.contains("FIPS 205"),
        "expected identifier-bearing excerpt, got: {:?}",
        pending.successful_reads[0]
    );
}

#[test]
fn append_pending_web_success_from_bundle_synthesizes_identifier_backed_nist_authority_candidates()
{
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "nist-ir-8413".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            snippet: Some(
                "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "nist-ir-8413".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            content_text: "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205 as the finalized post-quantum cryptography standards."
                .to_string(),
            content_hash: "nist-ir-8413-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    for expected_url in [
        "https://csrc.nist.gov/pubs/fips/203/final",
        "https://csrc.nist.gov/pubs/fips/204/final",
        "https://csrc.nist.gov/pubs/fips/205/final",
    ] {
        assert!(
            pending.candidate_urls.iter().any(|url| url == expected_url),
            "expected candidate URL inventory to include {expected_url:?}, got: {:?}",
            pending.candidate_urls
        );
        assert!(
            pending
                .candidate_source_hints
                .iter()
                .any(|hint| hint.url == expected_url),
            "expected candidate hint inventory to include {expected_url:?}, got: {:?}",
            pending.candidate_source_hints
        );
    }
    assert_eq!(
        crate::agentic::runtime::service::queue::support::next_pending_web_candidate(&pending)
            .as_deref(),
        Some("https://csrc.nist.gov/pubs/fips/203/final")
    );
}

#[test]
fn append_pending_web_success_from_bundle_synthesizes_identifier_backed_nist_authority_candidates_from_document_surface(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt: "NIST IR 8413 Update 1 summarizes the standardization process.".to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "nist-ir-8413".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            snippet: Some(
                "NIST IR 8413 Update 1 summarizes the standardization process."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "nist-ir-8413".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            content_text: "NIST IR 8413 Update 1 references FIPS 203, FIPS 204, and FIPS 205 as the finalized post-quantum cryptography standards."
                .to_string(),
            content_hash: "nist-ir-8413-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    for expected_url in [
        "https://csrc.nist.gov/pubs/fips/203/final",
        "https://csrc.nist.gov/pubs/fips/204/final",
        "https://csrc.nist.gov/pubs/fips/205/final",
    ] {
        assert!(
            pending.candidate_urls.iter().any(|url| url == expected_url),
            "expected candidate URL inventory to include {expected_url:?}, got: {:?}",
            pending.candidate_urls
        );
    }
}

#[test]
fn append_pending_web_success_from_bundle_preserves_supplemental_authority_links_as_candidates() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt: "NIST IR 8413 Update 1 summarizes the standardization process.".to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![
            WebSource {
                source_id: "nist-ir-8413".to_string(),
                rank: Some(1),
                url: requested_url.to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST IR 8413 Update 1 summarizes the standardization process."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: "fips203".to_string(),
                rank: Some(2),
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some("FIPS 203".to_string()),
                snippet: Some(
                    "Federal Information Processing Standard for ML-KEM.".to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "nist-ir-8413".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            content_text: "This report summarizes NIST's post-quantum cryptography standardization process."
                .to_string(),
            content_hash: "nist-ir-8413-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending
            .candidate_urls
            .iter()
            .any(|url| url == "https://csrc.nist.gov/pubs/fips/203/final"),
        "expected supplemental authority link in candidate urls: {:?}",
        pending.candidate_urls
    );
    assert!(
        pending
            .candidate_source_hints
            .iter()
            .any(|hint| hint.url == "https://csrc.nist.gov/pubs/fips/203/final"),
        "expected supplemental authority link in candidate hints: {:?}",
        pending.candidate_source_hints
    );
}

#[test]
fn append_pending_web_success_from_bundle_uses_supporting_source_snippets_to_ground_document_success(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url =
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Post-Quantum Cryptography | CSRC".to_string()),
            excerpt:
                "Current authoritative project page for the latest NIST post-quantum cryptography standards."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![
            WebSource {
                source_id: "pqc-project".to_string(),
                rank: None,
                url: requested_url.to_string(),
                title: Some("Post-Quantum Cryptography | CSRC".to_string()),
                snippet: None,
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: "call-for-proposals".to_string(),
                rank: Some(1),
                url: format!("{requested_url}/call-for-proposals"),
                title: Some("Call for Proposals".to_string()),
                snippet: Some(
                    "Post-Quantum Cryptography | CSRC | FIPS 203, FIPS 204, and FIPS 205 were published August 13, 2024."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "pqc-project".to_string(),
            url: requested_url.to_string(),
            title: Some("Post-Quantum Cryptography | CSRC".to_string()),
            content_text:
                "NIST's project page tracks the ongoing post-quantum cryptography effort."
                    .to_string(),
            content_hash: "pqc-project-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(
        pending.successful_reads.len(),
        1,
        "{:?}",
        pending.successful_reads
    );
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0].excerpt.contains("FIPS 203")
            && pending.successful_reads[0].excerpt.contains("FIPS 204")
            && pending.successful_reads[0].excerpt.contains("FIPS 205"),
        "expected success excerpt to inherit grounding from supporting bundle sources: {:?}",
        pending.successful_reads
    );
}

#[test]
fn append_pending_web_success_from_sources_only_bundle_preserves_project_child_hints() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url =
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Post-Quantum Cryptography | CSRC".to_string()),
            excerpt:
                "Current authoritative project page for the latest NIST post-quantum cryptography standards."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![
            WebSource {
                source_id: "pqc-project".to_string(),
                rank: None,
                url: requested_url.to_string(),
                title: Some("Post-Quantum Cryptography | CSRC".to_string()),
                snippet: None,
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: "call-for-proposals".to_string(),
                rank: Some(1),
                url: format!("{requested_url}/call-for-proposals"),
                title: Some("Call for Proposals".to_string()),
                snippet: Some(
                    "Post-Quantum Cryptography | CSRC | FIPS 203, FIPS 204, and FIPS 205 were published August 13, 2024."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: "submission-requirements".to_string(),
                rank: Some(2),
                url: format!("{requested_url}/submission-requirements"),
                title: Some("Submission Requirements".to_string()),
                snippet: Some(
                    "Post-Quantum Cryptography | CSRC | FIPS 203, FIPS 204, and FIPS 205 remain the current baseline."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending
            .successful_reads
            .iter()
            .any(|read| read.url == requested_url),
        "expected sources-only bundle to record the primary project page: {:?}",
        pending.successful_reads
    );
    assert!(
        pending.candidate_source_hints.iter().any(|hint| {
            hint.url == format!("{requested_url}/call-for-proposals")
                && hint.excerpt.contains("FIPS 203")
                && hint.excerpt.contains("FIPS 204")
                && hint.excerpt.contains("FIPS 205")
        }),
        "expected sources-only bundle to preserve child hints for recovery: {:?}",
        pending.candidate_source_hints
    );
}

#[test]
fn append_pending_web_success_from_sources_only_bundle_preserves_child_hints_when_primary_source_is_rejected(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url = "https://csrc.nist.gov/publications/fips";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards".to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Federal Information Processing Standards Publications".to_string()),
            excerpt: "Publication index".to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![
            WebSource {
                source_id: "nist-fips-hub".to_string(),
                rank: None,
                url: requested_url.to_string(),
                title: Some("Federal Information Processing Standards Publications".to_string()),
                snippet: Some("Publication index".to_string()),
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: "call-for-proposals".to_string(),
                rank: Some(1),
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some("FIPS 203".to_string()),
                snippet: Some(
                    "Module-Lattice-Based Key-Encapsulation Mechanism Standard.".to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: "submission-requirements".to_string(),
                rank: Some(2),
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some("FIPS 204".to_string()),
                snippet: Some("Module-Lattice-Based Digital Signature Standard.".to_string()),
                domain: Some("csrc.nist.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "expected the publication hub to remain out of successful reads: {:?}",
        pending.successful_reads
    );
    assert!(
        pending.candidate_source_hints.iter().any(|hint| {
            hint.url == "https://csrc.nist.gov/pubs/fips/203/final"
                && hint.excerpt.contains("Key-Encapsulation")
        }),
        "expected authority hints to survive even when the primary source is rejected: {:?}",
        pending.candidate_source_hints
    );
    assert!(
        pending.candidate_source_hints.iter().any(|hint| {
            hint.url == "https://csrc.nist.gov/pubs/fips/204/final"
                && hint.excerpt.contains("Digital Signature")
        }),
        "expected secondary authority hints to remain available for follow-up reads: {:?}",
        pending.candidate_source_hints
    );
}

#[test]
fn append_pending_web_success_from_bundle_does_not_synthesize_identifier_backed_nist_authority_candidates_from_non_nist_hosts(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url = "https://www.ibm.com/think/insights/post-quantum-cryptography-transition";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography transition guidance".to_string()),
            excerpt:
                "IBM summarizes FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography transition planning."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "ibm-brief".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography transition guidance".to_string()),
            snippet: Some(
                "IBM summarizes FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography transition planning."
                    .to_string(),
            ),
            domain: Some("www.ibm.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "ibm-brief".to_string(),
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography transition guidance".to_string()),
            content_text:
                "IBM summarizes FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography transition planning."
                    .to_string(),
            content_hash: "ibm-brief-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending
            .candidate_urls
            .iter()
            .all(|url| !url.starts_with("https://csrc.nist.gov/pubs/fips/")),
        "did not expect synthesized NIST authority candidates from non-NIST host: {:?}",
        pending.candidate_urls
    );
}

#[test]
fn append_pending_web_success_from_bundle_does_not_synthesize_legacy_fips_followups_from_ir_snippet(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url = "https://csrc.nist.gov/pubs/ir/8413/upd1/final";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms to augment Federal Information Processing Standard (FIPS) 186-4, Digital Signature Standard."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "nist-ir-8413".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms to augment Federal Information Processing Standard (FIPS) 186-4, Digital Signature Standard."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        }],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending
            .candidate_urls
            .iter()
            .all(|url| { !url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/fips/186/final") }),
        "did not expect legacy FIPS 186 follow-up candidate: {:?}",
        pending.candidate_urls
    );
}

#[test]
fn append_pending_web_success_from_bundle_keeps_official_pdf_when_challenge_terms_only_appear_late()
{
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url =
        "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Migration to Post-Quantum Cryptography | NCCoE".to_string(),
            ),
            excerpt:
                "NCCoE draft report for NIST SP 1800-38C covering migration to post-quantum cryptography interoperability and performance testing."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http:pdf".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "nist-pqc-pdf".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: None,
            snippet: Some(
                "NCCoE draft report for NIST SP 1800-38C covering migration to post-quantum cryptography interoperability and performance testing."
                    .to_string(),
            ),
            domain: Some("www.nccoe.nist.gov".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "nist-pqc-pdf".to_string(),
            url: requested_url.to_string(),
            title: None,
            content_text: concat!(
                "NIST SPECIAL PUBLICATION 1800-38C Migration to Post-Quantum Cryptography ",
                "Quantum Readiness: Testing Draft Standards. Volume C: Quantum-Resistant ",
                "Cryptography Technology Interoperability and Performance Report. ",
                "National Institute of Standards and Technology. ",
                "Appendix example browser message for test data only: access denied due to captcha."
            )
            .to_string(),
            content_hash: "nist-pqc-pdf-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.blocked_urls, Vec::<String>::new());
    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .contains("NIST SPECIAL PUBLICATION 1800-38C"),
        "expected the official PDF surface to be preserved, got: {:?}",
        pending.successful_reads[0]
    );
}

#[test]
fn append_pending_web_success_from_bundle_preserves_inventory_excerpt_for_menu_comparisons() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let requested_url = "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract"),
        ),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Menu".to_string()),
            excerpt: "Italian restaurant in Anderson, SC serving pasta, calzones, and sandwiches."
                .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "brothers-menu".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some("Menu".to_string()),
            snippet: Some(String::new()),
            domain: Some("restaurantji.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "brothers-menu".to_string(),
            url: requested_url.to_string(),
            title: Some("Menu".to_string()),
            content_text: "Item inventory includes Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Related image gallery available with 6 images. Brothers Special Shrimp Pasta. Chef Salad.".to_string(),
            content_hash: "brothers-menu-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .contains("Item inventory includes"),
        "expected structured inventory excerpt to survive read success, got: {:?}",
        pending.successful_reads[0]
    );
}

#[test]
fn append_pending_web_success_from_bundle_synthesizes_inventory_excerpt_from_line_list_menu_surface(
) {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let requested_url =
        "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract"),
        ),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Menu".to_string()),
            excerpt:
                "Italian restaurant in Anderson, SC serving pizza, pasta, and Mediterranean starters."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 1_773_117_248_754,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "red-tomato-menu".to_string(),
            rank: Some(1),
            url: requested_url.to_string(),
            title: Some("Menu".to_string()),
            snippet: Some(String::new()),
            domain: Some("restaurantji.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "red-tomato-menu".to_string(),
            url: requested_url.to_string(),
            title: Some("Menu".to_string()),
            content_text: "Bread Sticks\n\nHummus\n\nDolmas\n\nOrganic Old Fashioned Chef Salad\n\nOrganic Antipasto Salad\n\nOrganic Chicken Salad\n\nCentral Avenue - 150 E Shockley Ferry Rd\n\nDomino's Pizza - 121 E Shockley Ferry Rd".to_string(),
            content_hash: "red-tomato-menu-doc".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .contains("Item inventory includes Bread Sticks, Hummus, Dolmas"),
        "expected synthesized inventory excerpt, got: {:?}",
        pending.successful_reads[0]
    );
    assert!(
        !pending.successful_reads[0]
            .excerpt
            .contains("Shockley Ferry Rd"),
        "expected address-like tail lines to be excluded, got: {:?}",
        pending.successful_reads[0]
    );
}

#[test]
fn push_pending_web_success_preserves_inventory_excerpt_when_hint_is_more_generic() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let requested_url = "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract"),
        ),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Menu for Coach House Restaurant, Anderson, SC - Restaurantji".to_string()),
            excerpt:
                "Coach House Restaurant in Anderson, SC offers a menu, reviews, photos, hours, and address."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 3,
    };

    push_pending_web_success(
        &mut pending,
        requested_url,
        Some("Menu for Coach House Restaurant, Anderson, SC - Restaurantji".to_string()),
        "Item inventory includes Served with Sauteed Onions and Brown Gravy, Tuesday Dinner Special Chopped Steak, Broccoli Stuffed Chicken Breast, Country Fried Steak Sandwich, and Assorted Home Made Cakes."
            .to_string(),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .contains("Item inventory includes"),
        "expected structured inventory excerpt to survive generic hint replacement, got: {:?}",
        pending.successful_reads[0]
    );
}

#[test]
fn push_pending_web_success_rejects_non_authority_non_identifier_briefing_source() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let requested_url = "https://www.ibm.com/think/insights/post-quantum-cryptography-transition";
    let mut pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, None)
                .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography transition guidance".to_string()),
            excerpt:
                "March 2026 - IBM explains recent NIST post-quantum cryptography transition planning for enterprises."
                    .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };

    push_pending_web_success(
        &mut pending,
        requested_url,
        Some("Post-quantum cryptography transition guidance".to_string()),
        "March 2026 - IBM explains recent NIST post-quantum cryptography transition planning for enterprises."
            .to_string(),
    );

    assert!(
        pending.successful_reads.is_empty(),
        "unexpected retained sources: {:?}",
        pending.successful_reads
    );
}

#[test]
fn append_pending_web_success_fallback_backfills_hint_for_terminal_completion_notes() {
    let requested_url = "https://www.nist.gov/pqc";
    let mut pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                None,
            )
            .expect("retrieval contract"),
        ),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 2,
    };

    append_pending_web_success_fallback(
        &mut pending,
        requested_url,
        Some("Completed. Final response emitted via chat__reply."),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert_eq!(
        pending.successful_reads[0].title.as_deref(),
        Some("Post-quantum cryptography | NIST")
    );
    assert!(
        pending.successful_reads[0]
            .excerpt
            .contains("Federal Information Processing Standards"),
        "expected hint excerpt to be retained for fallback evidence: {:?}",
        pending.successful_reads[0]
    );
}
