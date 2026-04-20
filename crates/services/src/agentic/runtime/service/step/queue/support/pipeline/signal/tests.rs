use super::*;

#[test]
fn source_terminal_error_signal_detects_not_found_page() {
    assert!(source_has_terminal_error_signal(
        "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc",
        "404 Not Found | Eater NY",
        "Sorry, the page you were looking for could not be found."
    ));
}

#[test]
fn source_terminal_error_signal_detects_rate_limited_shell() {
    assert!(source_has_terminal_error_signal(
        "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/",
        "429 Too Many Requests",
        "429 Too Many Requests"
    ));
}

#[test]
fn source_terminal_error_signal_ignores_valid_article_surface() {
    assert!(!source_has_terminal_error_signal(
        "https://www.theinfatuation.com/new-york/guides/best-italian-restaurants-nyc",
        "The Best Italian Restaurants In NYC",
        "A guide to standout Roman pasta, antipasti and house-made focaccia in New York."
    ));
}

#[test]
fn source_human_challenge_signal_detects_security_checkpoint_interstitial() {
    assert!(source_has_human_challenge_signal(
        "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans",
        "Vercel Security Checkpoint",
        "Please complete the security check to continue."
    ));
}

#[test]
fn source_human_challenge_signal_ignores_late_body_markers_in_official_document() {
    assert!(!source_has_human_challenge_signal(
        "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf",
        "Migration to Post-Quantum Cryptography | NCCoE",
        "NIST SPECIAL PUBLICATION 1800-38C Migration to Post-Quantum Cryptography Quantum Readiness: Testing Draft Standards. Volume C: Quantum-Resistant Cryptography Technology Interoperability and Performance Report. National Institute of Standards and Technology. Appendix example browser message for test data only: access denied due to captcha."
    ));
}

#[test]
fn headline_actionable_inventory_excludes_low_priority_roundups() {
    let sources = vec![
        PendingSearchReadSummary {
            url: "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            excerpt: "Daily roundup for school assembly with thought of the day and national headlines."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092".to_string(),
            title: Some(
                "High School Teacher Reveals The 1 Classroom Rule She No Longer Enforces After 25 Years".to_string(),
            ),
            excerpt: "Courtney Schermerhorn, a high school U.S. history teacher in Texas, says some classroom rules stop serving students after years of experience.".to_string(),
        },
    ];

    let (actionable_sources, actionable_domains) = headline_actionable_source_inventory(&sources);

    assert_eq!(actionable_sources, 1);
    assert_eq!(actionable_domains, 1);
    assert!(headline_source_is_actionable(&sources[1]));
    assert!(!headline_source_is_actionable(&sources[0]));
}

#[test]
fn headline_source_is_actionable_when_title_carries_the_claim() {
    let source = PendingSearchReadSummary {
        url: "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
        title: Some(
            "Trump tariffs: Customs and Border Protection tells judge it can't comply with refund order - CNBC".to_string(),
        ),
        excerpt: "CNBC | source_url=https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
    };

    assert!(
        headline_source_is_actionable(&source),
        "claim-bearing article titles should count as actionable headline evidence"
    );
}

#[test]
fn headline_actionable_inventory_counts_specific_articles_with_sparse_snippets() {
    let sources = vec![
        PendingSearchReadSummary {
            url: "https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7".to_string(),
            title: Some(
                "Sri Lanka takes custody of an Iranian vessel off its coast after US sank an Iranian warship - AP News"
                    .to_string(),
            ),
            excerpt:
                "AP News | source_url=https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7"
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384".to_string(),
            title: Some(
                "Mar 6: WAFCON Postponed, Uganda Evacuates 43 Students From Iran"
                    .to_string(),
            ),
            excerpt:
                "OkayAfrica | source_url=https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
            title: Some(
                "Trump tariffs: Customs and Border Protection tells judge it can't comply with refund order - CNBC".to_string(),
            ),
            excerpt:
                "CNBC | source_url=https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html"
                    .to_string(),
        },
    ];

    let (actionable_sources, actionable_domains) = headline_actionable_source_inventory(&sources);

    assert_eq!(actionable_sources, 3);
    assert_eq!(actionable_domains, 3);
}

#[test]
fn headline_source_is_not_actionable_for_multi_story_roundup_surface() {
    let source = PendingSearchReadSummary {
        url: "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
        title: Some(
            "Morning Sprint: March 6 morning's top news and weather headlines - Channel 3000"
                .to_string(),
        ),
        excerpt: "Morning roundup video covering the day's top news and weather headlines."
            .to_string(),
    };

    assert!(
        !headline_source_is_actionable(&source),
        "multi-story roundup surfaces should not count as actionable headline stories"
    );
}

#[test]
fn prioritized_query_grounding_excerpt_prefers_required_standard_identifier_segment() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let selected = prioritized_query_grounding_excerpt(
        query,
        3,
        "https://www.nist.gov/pqc",
        "Post-quantum cryptography | NIST",
        "NIST maintains post-quantum cryptography transition guidance for agencies. The Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 standardize ML-KEM, ML-DSA, and SLH-DSA for federal use. Agencies should inventory systems and plan migration timelines.",
        220,
    );

    assert!(
        selected.contains("FIPS 203")
            && selected.contains("FIPS 204")
            && selected.contains("FIPS 205"),
        "expected identifier-bearing segment, got: {selected:?}"
    );
}

#[test]
fn prioritized_query_grounding_excerpt_combines_identifier_segments_when_needed() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let selected = prioritized_query_grounding_excerpt(
        query,
        3,
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST",
        "NIST finalized the first post-quantum encryption standards. Federal Information Processing Standard (FIPS) 203 specifies ML-KEM. The two digital signature standards are FIPS 204 and FIPS 205 for ML-DSA and SLH-DSA. Agencies should begin transition planning.",
        220,
    );

    assert!(
        selected.contains("FIPS 203")
            && selected.contains("FIPS 204")
            && selected.contains("FIPS 205"),
        "expected combined identifier-bearing excerpt, got: {selected:?}"
    );
}

#[test]
fn observed_briefing_standard_identifier_labels_do_not_expand_query_specific_fips_sets() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let labels = observed_briefing_standard_identifier_labels(
        query,
        "NIST released FIPS 203, 204, and 205 as finalized post-quantum cryptography standards.",
    );

    assert!(labels.is_empty(), "labels={labels:?}");
}

#[test]
fn preferred_briefing_identifier_alias_ignores_trailing_match_when_raw_tokens_are_shorter() {
    assert_eq!(
        preferred_briefing_identifier_alias("FIPS 204", "PQC ML-DSA FIPS 204 ML-KEM"),
        None
    );
}

#[test]
fn observed_briefing_standard_identifier_labels_capture_ir_publication_numbers() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let labels = observed_briefing_standard_identifier_labels(
        query,
        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC",
    );

    assert_eq!(labels, vec!["IR 8413".to_string()]);
}

#[test]
fn source_briefing_standard_identifier_labels_prefer_primary_publication_id_over_excerpt_reference()
{
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let labels = source_briefing_standard_identifier_labels(
        query,
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC",
        "IR 8413 documents NIST's third-round status report and notes that new public-key standards will augment Federal Information Processing Standard (FIPS) 186-4.",
    );

    assert_eq!(labels, BTreeSet::from(["IR 8413".to_string()]));
}

#[test]
fn source_briefing_standard_identifier_labels_ignore_year_path_component_for_ir_publications() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let labels = source_briefing_standard_identifier_labels(
        query,
        "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf",
        "NIST IR 8413 Update 1 (PDF)",
        "NIST IR 8413 Update 1 summarizes the post-quantum cryptography standardization process.",
    );

    assert_eq!(labels, BTreeSet::from(["IR 8413".to_string()]));
}

#[test]
fn source_document_authority_family_key_collapses_ir_update_variants() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let title =
        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC";
    let excerpt =
        "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process.";

    let original = source_document_authority_family_key(
        query,
        "https://csrc.nist.gov/pubs/ir/8413/final",
        title,
        excerpt,
    );
    let update = source_document_authority_family_key(
        query,
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
        title,
        excerpt,
    );

    assert_eq!(original, update);
}

#[test]
fn source_document_authority_family_key_collapses_ir_update_variants_despite_excerpt_identifier_drift(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let title =
        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC";

    let original = source_document_authority_family_key(
        query,
        "https://csrc.nist.gov/pubs/ir/8413/final",
        title,
        "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process.",
    );
    let update = source_document_authority_family_key(
        query,
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
        title,
        "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205.",
    );

    assert_eq!(original, update);
}

#[test]
fn source_document_authority_family_key_distinguishes_distinct_fips_publications() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let fips_203 = source_document_authority_family_key(
        query,
        "https://csrc.nist.gov/pubs/fips/203/final",
        "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard",
        "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM.",
    );
    let fips_204 = source_document_authority_family_key(
        query,
        "https://csrc.nist.gov/pubs/fips/204/final",
        "FIPS 204 Module-Lattice-Based Digital Signature Standard",
        "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA.",
    );

    assert_ne!(fips_203, fips_204);
}

#[test]
fn source_document_authority_accepts_official_archive_news_with_query_grounding() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let url =
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
    let title = "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST";
    let excerpt = "August 13, 2024 - The finalized standards are FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography.";

    assert!(
        source_has_document_authority(query, url, title, excerpt),
        "official archive story should retain document authority despite archive-year surface"
    );
    assert!(source_document_authority_score(query, url, title, excerpt) > 0);
}

#[test]
fn source_document_authority_rejects_generic_public_authority_surface_without_query_grounding() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let url = "https://www.nist.gov/cybersecurity-and-privacy";
    let title = "Cybersecurity and Privacy | NIST";
    let excerpt = "NIST advances measurement science, standards, and technology for cybersecurity and privacy.";

    assert!(!source_has_document_authority(query, url, title, excerpt));
    assert_eq!(
        source_document_authority_score(query, url, title, excerpt),
        0
    );
}

#[test]
fn source_document_authority_accepts_generic_authority_pages_when_discovery_signals_align() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let url = "https://www.nist.gov/pqc";
    let title = "Post-quantum cryptography | NIST";
    let excerpt =
        "NIST is advancing post-quantum cryptography standardization and transition guidance.";

    assert!(source_has_document_authority(query, url, title, excerpt));
    assert!(source_document_authority_score(query, url, title, excerpt) > 0);
}

#[test]
fn grounded_primary_authority_accepts_on_subject_official_standards_pages() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";

    assert!(source_has_grounded_primary_authority(
        query,
        "https://www.nist.gov/pqc",
        "Post-quantum cryptography | NIST",
        "NIST is advancing post-quantum cryptography standardization and transition guidance."
    ));
    assert!(source_has_grounded_primary_authority(
        query,
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST",
        "August 13, 2024 - The finalized standards are FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
    ));
}

#[test]
fn grounded_primary_authority_rejects_generic_official_authority_neighbors() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";

    assert!(!source_has_grounded_primary_authority(
        query,
        "https://www.nist.gov/cybersecurity-and-privacy",
        "Cybersecurity and Privacy | NIST",
        "NIST advances measurement science, standards, and technology for cybersecurity and privacy."
    ));
}

#[test]
fn primary_authority_accepts_live_openai_pricing_surface_with_title_only() {
    let query = "What is the latest OpenAI API pricing?";
    let url = "https://openai.com/api/pricing/";
    let title = "OpenAI API Pricing | OpenAI";

    assert!(
        source_has_document_authority(query, url, title, ""),
        "official branded pricing page should retain document authority from host/title grounding"
    );
    assert!(
        source_counts_as_primary_authority(query, url, title, ""),
        "host-anchored current pricing query should count the official branded pricing page as primary authority"
    );
}

#[test]
fn primary_authority_accepts_live_openai_pricing_surface_with_search_snippet() {
    let query = "What is the latest OpenAI API pricing?";
    let url = "https://openai.com/api/pricing/";
    let title = "OpenAI API Pricing | OpenAI";
    let excerpt = "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers.";

    assert!(source_has_document_authority(query, url, title, excerpt));
    assert!(source_counts_as_primary_authority(
        query, url, title, excerpt
    ));
}

#[test]
fn host_anchored_primary_authority_snapshot_alignment_accepts_official_pricing_rate_card() {
    let query = "What is the latest OpenAI API pricing?";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let url = "https://openai.com/api/pricing/";
    let title = "OpenAI API Pricing | OpenAI";
    let excerpt = "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs";

    assert!(query_requires_host_anchored_primary_authority(query));
    assert!(retrieval_contract_requires_primary_authority_source(
        Some(&retrieval_contract),
        query,
    ));
    assert!(source_counts_as_primary_authority(
        query, url, title, excerpt
    ));
    assert!(
        candidate_time_sensitive_resolvable_payload(url, title, excerpt),
        "title+excerpt should qualify as a resolvable current pricing payload"
    );
    assert!(
        source_has_host_anchored_primary_authority_snapshot_alignment(
            Some(&retrieval_contract),
            query,
            1,
            url,
            title,
            excerpt,
        )
    );
}

#[test]
fn prioritized_query_grounding_excerpt_prefers_metric_surface_for_current_pricing_pages() {
    let query = "What is the latest OpenAI API pricing?";
    let url = "https://openai.com/api/pricing/";
    let title = "OpenAI API Pricing | OpenAI";
    let content = "Our frontier models are designed to spend more time thinking before producing a response, making them ideal for complex, multi-step problems.\n\nPricing above reflects standard processing rates for context lengths under 270K.\n\nNow: 1 GB for $0.03 / 64GB for $1.92 per container Starting March 31, 2026: 1 GB for $0.03 / 64GB for $1.92 per 20-minute session pass.\n\nAudio: $32.00 for inputs $0.40 for cached inputs $64.00 for outputs Text: $4.00 for inputs $0.40 for cached inputs $16.00 for outputs Image: $5.00 for inputs $0.50 for cached inputs\n\nState-of-the-art image generation model.\n\nImage: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");

    let selected = prioritized_query_grounding_excerpt_with_contract(
        Some(&retrieval_contract),
        query,
        1,
        url,
        title,
        content,
        240,
    );

    assert!(
        selected.contains("$32.00") || selected.contains("$8.00"),
        "selected={selected}"
    );
    assert!(
        contains_current_condition_metric_signal(&selected),
        "selected={selected}"
    );
    assert!(
        !selected.starts_with("Our frontier models are designed"),
        "selected={selected}"
    );
    assert!(
        !selected.contains("1 GB for $0.03") && !selected.contains("per container"),
        "selected={selected}"
    );
}

#[test]
fn document_briefing_authority_alignment_accepts_empty_snippet_identifier_pages() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let url = "https://csrc.nist.gov/pubs/ir/8413/final";
    let title =
        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC";
    let excerpt = "";

    assert!(source_has_public_authority_host(url));
    assert!(source_has_briefing_standard_identifier_signal(
        query, url, title, excerpt
    ));
    assert!(query_prefers_document_briefing_layout(query));
    assert!(analyze_query_facets(query).grounded_external_required);
    assert!(
        query_native_anchor_tokens(query)
            .intersection(&source_anchor_tokens(url, title, excerpt))
            .count()
            >= 2
    );

    assert!(
        source_has_document_briefing_authority_alignment_with_contract(
            Some(&contract),
            query,
            2,
            url,
            title,
            excerpt,
        )
    );
}

#[test]
fn prioritized_query_grounding_excerpt_anchors_long_segment_at_identifier_surface() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let selected = prioritized_query_grounding_excerpt(
        query,
        3,
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST",
        "Official websites use .gov and secure HTTPS connections for official government information and services. This page explains the update. NIST released FIPS 203, 204, and 205 as the first finalized post-quantum encryption standards for federal use and transition planning.",
        120,
    );

    assert!(
        selected.contains("FIPS 203") && selected.contains("204") && selected.contains("205"),
        "expected identifier-anchored excerpt, got: {selected:?}"
    );
    assert!(
        !selected.starts_with("Official websites use"),
        "expected identifier-focused excerpt, got: {selected:?}"
    );
}

#[test]
fn prioritized_query_grounding_excerpt_preserves_menu_inventory_for_menu_comparisons() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let selected = prioritized_query_grounding_excerpt_with_contract(
        Some(&retrieval_contract),
        query,
        3,
        "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/",
        "Menu",
        "Item inventory includes Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Related image gallery available with 6 images. Brothers Special Shrimp Pasta. Chef Salad.",
        240,
    );

    assert!(selected.contains("Item inventory includes"));
    assert!(selected.contains("Related image gallery available with 6 images."));
}
