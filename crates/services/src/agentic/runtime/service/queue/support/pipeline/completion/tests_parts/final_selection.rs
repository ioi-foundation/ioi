#[test]
fn final_summary_selection_accepts_model_authored_sourced_answer() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt:
                    "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt:
                    "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://newsroom.ibm.com/2024-08-13-ibm-developed-algorithms-announced-as-worlds-first-post-quantum-cryptography-standards".to_string(),
                title: Some(
                    "IBM-Developed Algorithms Announced as NIST's First Published Post-Quantum Cryptography Standards"
                        .to_string(),
                ),
                excerpt:
                    "IBM-developed algorithms announced as NIST's first published post-quantum cryptography standards."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };
    let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.".to_string();
    let model_summary = "NIST's current post-quantum cryptography standards are centered on FIPS 203, FIPS 204, and FIPS 205, with NIST and IBM sources describing them as the first finalized post-quantum standards for federal and broader adoption. IBM's supporting coverage says its algorithms were included in the first published standards.\n\nSources:\n- [Post-quantum cryptography | NIST](https://www.nist.gov/pqc)\n- [NIST’s post-quantum cryptography standards are here - IBM Research](https://research.ibm.com/blog/nist-pqc-standards)\n- [IBM-Developed Algorithms Announced as NIST's First Published Post-Quantum Cryptography Standards](https://newsroom.ibm.com/2024-08-13-ibm-developed-algorithms-announced-as-worlds-first-post-quantum-cryptography-standards)".to_string();
    let selection = select_final_web_summary_from_candidates(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        vec![
            FinalWebSummaryCandidate {
                provider: "legacy_template_candidate",
                summary: bad_summary,
            },
            FinalWebSummaryCandidate {
                provider: "model_direct_sourced_answer",
                summary: model_summary.clone(),
            },
        ],
    )
    .expect("summary selection");

    assert_eq!(selection.provider, "model_direct_sourced_answer");
    assert!(selection.contract_ready);
    assert_eq!(selection.summary, model_summary);
    assert_eq!(selection.evaluations.len(), 2);
    assert!(!selection.evaluations[0].contract_ready);
    assert_eq!(
        selection.evaluations[0].provider,
        "legacy_template_candidate"
    );
    assert_eq!(
        selection.evaluations[0]
            .facts
            .answer_rendered_layout_profile,
        "source_collection"
    );
    assert!(selection.evaluations[1].contract_ready);
    assert_eq!(
        selection.evaluations[1].provider,
        "model_direct_sourced_answer"
    );
}

#[test]
fn final_summary_selection_preserves_non_ready_model_candidate_for_gate() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
            title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
            excerpt: "Filecoin live USD quote from CoinGecko simple price API: price $0.954 USD."
                .to_string(),
        }],
        min_sources: 2,
    };
    let model_answer =
        "Filecoin looks more stable, but this answer does not cite both requested assets."
            .to_string();
    let selection = select_final_web_summary_from_candidates(
        &pending,
        WebPipelineCompletionReason::DeadlineReached,
        vec![FinalWebSummaryCandidate {
            provider: "model_direct_sourced_answer",
            summary: model_answer.clone(),
        }],
    )
    .expect("model candidate should reach the CEC gate even when not ready");

    assert_eq!(selection.provider, "model_direct_sourced_answer");
    assert_eq!(selection.summary, model_answer);
    assert!(!selection.contract_ready);
    assert_eq!(selection.evaluations.len(), 1);
    assert!(!selection.evaluations[0].contract_ready);
}

#[test]
fn final_summary_selection_prefers_latest_non_ready_model_retry() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
            title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
            excerpt: "Filecoin live USD quote from CoinGecko simple price API: price $0.954 USD."
                .to_string(),
        }],
        min_sources: 2,
    };

    let latest_retry =
        "Latest model retry: still missing Akash quote evidence, but closer to the requested comparison."
            .to_string();
    let first_attempt = "First model attempt: Filecoin only.".to_string();
    let selection = select_final_web_summary_from_candidates(
        &pending,
        WebPipelineCompletionReason::DeadlineReached,
        vec![
            FinalWebSummaryCandidate {
                provider: "model_direct_sourced_answer",
                summary: latest_retry.clone(),
            },
            FinalWebSummaryCandidate {
                provider: "model_direct_sourced_answer",
                summary: first_attempt,
            },
        ],
    )
    .expect("latest model retry should be preserved at the CEC boundary");

    assert_eq!(selection.summary, latest_retry);
    assert!(!selection.contract_ready);
    assert_eq!(selection.evaluations.len(), 2);
}

#[test]
fn comparison_sourced_answer_allows_natural_comparison_section() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network live USD quote from CoinGecko simple price API: price $0.806303 USD. Market cap: $235.94M. 24h trading volume: $6.65M."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin live USD quote from CoinGecko simple price API: price $0.954 USD. Market cap: $654.12M. 24h trading volume: $124.96M."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m"
                    .to_string(),
                title: Some("Filecoin Vs Akash Network Comparison".to_string()),
                excerpt:
                    "A comparison page discussing Filecoin and Akash forecasts, sentiment, and risk."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on live quote evidence, Akash has the higher-beta compute thesis while Filecoin is the larger, more established storage network. This is not financial advice.\n\n## Key Comparison Summary\n- Akash: about $0.806, market cap about $235.94M, and 24h trading volume about $6.65M.\n- Filecoin: about $0.954, market cap about $654.12M, and 24h trading volume about $124.96M.\n- Akash: smaller cap, decentralized compute exposure, higher volatility.\n- Filecoin: larger storage network, more mature ecosystem, lower growth torque.\n\nSources:\n- [Akash Network live USD price quote - CoinGecko](https://www.coingecko.com/en/coins/akash-network)\n- [Filecoin live USD price quote - CoinGecko](https://www.coingecko.com/en/coins/filecoin)\n- [Filecoin Vs Akash Network Comparison](https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m)";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(facts.answer_rendered_layout_profile, "sourced_answer");
    assert!(facts.comparison_required);
    assert!(facts.comparison_ready);
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn comparison_model_answer_accepts_natural_market_metrics_without_visible_urls() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_304_870_000,
        deadline_ms: 1_780_304_930_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.754621 USD. Market cap: $220.31M. 24h trading volume: $4.87M. 24h price change: -2.92%."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.921671 USD. Market cap: $725.31M. 24h trading volume: $84.64M. 24h price change: -4.07%."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = r#"Based on current market data and project fundamentals, here is a comparison of Akash Network (AKT) and Filecoin (FIL) to help you assess which might be a better investment right now.

### Current Market Metrics
As of the latest quote observations, the two tokens show the following metrics:

*   **Akash Network (AKT)**
    *   **Price:** ~$0.75
    *   **Market Cap:** ~$220.31M
    *   **24h Trading Volume:** ~$4.87M
    *   **24h Price Change:** -2.92%
    *   **Source:** CoinGecko

*   **Filecoin (FIL)**
    *   **Price:** ~$0.92
    *   **Market Cap:** ~$725.31M
    *   **24h Trading Volume:** ~$84.64M
    *   **24h Price Change:** -4.07%
    *   **Source:** CoinGecko

### Fundamental Comparison

| Feature | Akash Network (AKT) | Filecoin (FIL) |
| :--- | :--- | :--- |
| **Primary Use Case** | **Decentralized Cloud Computing.** Focuses on compute power for applications. | **Decentralized Storage.** Focuses on storing data files securely and cheaply. |
| **Risk Profile** | **Higher Risk / Higher Growth Potential.** Smaller market cap implies more volatility but potential for outsized gains if compute adoption accelerates. | **Lower Risk / Steady Growth.** Larger market cap and liquidity suggest stability, though less explosive upside. |

Right now, **Filecoin** appears to be the safer, more established investment due to its superior liquidity and larger market cap. However, **Akash** offers a higher-risk, higher-reward profile if you are bullish on decentralized compute.

*Disclaimer: This is not financial advice. Cryptocurrency investments are volatile and carry significant risk.*"#;

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(facts.answer_rendered_layout_profile, "other");
    assert!(facts.market_quote_grounding_required);
    assert!(facts.market_quote_grounding_floor_met);
    assert!(facts.rendered_summary_semantic_floor_met);
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn source_finding_sourced_answer_accepts_relevant_citable_sources() {
    let query = "Find current sources for today's top local AI model runtime issue.";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/local-ai-runtime".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://localai.io/basics/troubleshooting/".to_string(),
                title: Some("Troubleshooting - LocalAI".to_string()),
                excerpt:
                    "Troubleshooting guide covering common issues when using LocalAI runtimes."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://localai.io/advanced/vram-management/index.html".to_string(),
                title: Some("VRAM and Memory Management - LocalAI".to_string()),
                excerpt: "LocalAI describes model loading failures when systems run out of VRAM."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Two useful starting points are LocalAI's troubleshooting guide and its VRAM-management documentation.\n\nSources:\n- [Troubleshooting - LocalAI](https://localai.io/basics/troubleshooting/): useful for common runtime failure categories.\n- [VRAM and Memory Management - LocalAI](https://localai.io/advanced/vram-management/index.html): useful for model-load and GPU memory failure diagnosis.";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(facts.answer_rendered_layout_profile, "sourced_answer");
    assert_eq!(facts.evidence_selected_source_compatible, 2);
    assert!(facts.evidence_citation_read_backing_floor_met);
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn final_summary_selection_rejects_non_ready_fallback_summaries() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                        .to_string(),
                ),
                excerpt: "The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms while HQC serves as a backup."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                        .to_string(),
                ),
                excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };
    let better_summary = "# NIST post-quantum cryptography standards\n\nSummary: As of 2026-03-10, retrieved authoritative sources identify the currently published standards as FIPS 204 and FIPS 205. According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST, the other finished standards are FIPS 204 and FIPS 205 while HQC serves as a backup. According to Diving Into NIST’s New Post-Quantum Standards, the finalized standards set includes FIPS 203, FIPS 204, and FIPS 205.\n\nEvidence:\n- According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST, the other finished standards are FIPS 204 and FIPS 205 while HQC serves as a backup.\n- According to Diving Into NIST’s New Post-Quantum Standards, the finalized standards set includes FIPS 203, FIPS 204, and FIPS 205.\n\nCitations:\n- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST | https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption | 2026-03-10T12:19:24Z | retrieved_utc\n- Diving Into NIST’s New Post-Quantum Standards | https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/ | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: medium"
        .to_string();
    let worse_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nCitations:\n- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST | https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption | 2026-03-10T12:19:24Z | retrieved_utc"
        .to_string();

    let selection = select_final_web_summary_from_candidates(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        vec![
            FinalWebSummaryCandidate {
                provider: "legacy_template_candidate",
                summary: better_summary.clone(),
            },
            FinalWebSummaryCandidate {
                provider: "legacy_fallback_candidate",
                summary: worse_summary,
            },
        ],
    );
    assert!(
        selection.is_none(),
        "non-ready deterministic or template fallback summaries must not be selected"
    );
}
