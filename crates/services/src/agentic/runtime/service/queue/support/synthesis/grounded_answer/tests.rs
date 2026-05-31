use super::*;

#[test]
fn product_metadata_lines_are_stripped_from_model_answers() {
    let answer = "Akash has the clearer compute thesis, but both assets remain speculative.\n\nSources:\n- [Example](https://example.com)\n\nRun date (UTC): 2026-05-29 Run timestamp (UTC): 2026-05-29T20:12:57Z Overall confidence: low";

    let stripped = strip_product_metadata_lines(answer);

    assert!(stripped.contains("Akash has the clearer compute thesis"));
    assert!(stripped.contains("Sources:"));
    assert!(!stripped.contains("Run date (UTC):"));
    assert!(!stripped.contains("Run timestamp (UTC):"));
    assert!(!stripped.contains("Overall confidence:"));
}

#[test]
fn direct_investment_synthesis_requires_quote_grade_sources_for_all_compared_assets() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: Vec::new(),
        candidate_source_hints: Vec::new(),
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt:
                    "Akash Network live USD quote from CoinGecko simple price API: price $0.806303 USD."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m"
                    .to_string(),
                title: Some("Filecoin Vs Akash Network Comparison".to_string()),
                excerpt:
                    "A comparison page that discusses Filecoin and Akash sentiment, forecasts, and investment risk."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    assert!(
        direct_source_context_from_pending(&pending).is_none(),
        "direct synthesis must not answer a current investment comparison from one live quote plus secondary comparison pages"
    );
}

#[test]
fn direct_investment_synthesis_uses_quote_grade_sources_when_floor_is_met() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: Vec::new(),
        candidate_source_hints: Vec::new(),
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
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
                excerpt: "A comparison page with forecasts and sentiment.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let context = direct_source_context_from_pending(&pending).expect("quote context");
    assert!(context.contains("coingecko.com/en/coins/akash-network"));
    assert!(context.contains("coingecko.com/en/coins/filecoin"));
    assert!(context.contains("Use explicit values from this source"));
    assert!(
        context.contains("walletinvestor.com"),
        "investment comparison synthesis keeps comparison context instead of feeding the model only quote pages"
    );
    assert!(
        context.contains("never expand bare numbers into market caps or prices"),
        "comparison-context notes must warn the model away from hallucinated quote units"
    );
}

#[test]
fn direct_investment_guidance_prevents_ambiguous_comparison_metrics() {
    let guidance =
        direct_synthesis_behavior_guidance("Which is a better investment, Filecoin or Akash?");

    assert!(guidance.contains("source note for that same asset explicitly states"));
    assert!(guidance.contains("Use other sources for qualitative thesis"));
    assert!(guidance.contains("expand bare comparison values"));
}

#[test]
fn direct_source_finding_guidance_keeps_answer_model_authored_without_template_heading() {
    let guidance = direct_synthesis_behavior_guidance(
        "Find current sources for today's top local AI model runtime issue.",
    );

    assert!(guidance.contains("Sources:"));
    assert!(guidance.contains("temporal qualifier"));
    assert!(guidance.contains("Do not use `Sources checked`"));
}

#[test]
fn direct_source_finding_context_can_use_discovered_source_hints() {
    let query = "Find current sources for today's top local AI model runtime issue.";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://www.bing.com/search?q=local+AI+model+runtime+issue".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: Vec::new(),
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://localai.io/basics/troubleshooting/".to_string(),
            title: Some("Troubleshooting - LocalAI".to_string()),
            excerpt: "Troubleshooting guide covering common issues when using LocalAI runtimes."
                .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 1,
    };

    let context = direct_source_context_from_pending(&pending).expect("source context");

    assert!(context.contains("LocalAI"));
    assert!(context.contains("Troubleshooting guide"));
    assert!(context.contains("https://localai.io/basics/troubleshooting/"));
}

#[test]
fn direct_source_finding_answer_must_preserve_current_qualifier() {
    let query = "Find current sources for today's top local AI model runtime issue.";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://www.bing.com/search?q=local+AI+model+runtime+issue".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: Vec::new(),
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://localai.io/basics/troubleshooting/".to_string(),
            title: Some("Troubleshooting - LocalAI".to_string()),
            excerpt: "Troubleshooting guide covering common issues when using LocalAI runtimes."
                .to_string(),
        }],
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources: 1,
    };
    let vague_answer = "These sources cover local AI runtime troubleshooting.\n\nSources:\n- [LocalAI Troubleshooting](https://localai.io/basics/troubleshooting/)";
    let current_answer = "These current sources cover local AI runtime troubleshooting.\n\nSources:\n- [LocalAI Troubleshooting](https://localai.io/basics/troubleshooting/)";

    assert!(visible_direct_answer_from_raw(vague_answer, &pending).is_none());
    assert!(visible_direct_answer_from_raw(current_answer, &pending).is_some());
}

#[test]
fn visible_direct_answer_attaches_source_affordance_without_rewriting_answer() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: Vec::new(),
        candidate_source_hints: Vec::new(),
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
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
                excerpt: "A comparison page with forecasts and sentiment.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let answer = "Based on the live quotes and comparison context, Akash has the clearer upside if you want a higher-beta compute thesis, while Filecoin is the more established storage network. This is not financial advice.";

    let normalized = visible_direct_answer_from_raw(answer, &pending).expect("visible answer");

    assert!(normalized.starts_with("Based on the live quotes"));
    assert!(normalized.contains("Sources:"));
    assert!(normalized.contains("https://www.coingecko.com/en/coins/akash-network"));
    assert!(normalized.contains("https://www.coingecko.com/en/coins/filecoin"));
    assert!(!normalized.contains("Story 1"));
    assert!(!normalized.contains("Run date (UTC):"));
}

#[test]
fn direct_investment_answer_rejects_unsupported_market_cap_numbers() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://search.example/akt-fil".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: Vec::new(),
        candidate_source_hints: Vec::new(),
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.791261 USD. Market cap: $229.88M. 24h trading volume: $5.82M. 24h price change: -2.51%."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.9748 USD. Market cap: $662.41M. 24h trading volume: $113.98M. 24h price change: -1.12%."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m"
                    .to_string(),
                title: Some("Filecoin Vs Akash Network Comparison".to_string()),
                excerpt: "Currency from Currency To Compare Price (USD) FIL 0.000000028 AKT 0.000000019 Market Cap (USD) FIL 16 AKT 5."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };
    let unsupported = "Based on live quote evidence, Akash is smaller and higher beta. This is not financial advice.\n\n| Metric | Akash | Filecoin |\n| --- | --- | --- |\n| Market Cap | $5 Billion | $16 Billion |\n\nSources:\n- [Akash Network live USD price quote - CoinGecko](https://www.coingecko.com/en/coins/akash-network)\n- [Filecoin live USD price quote - CoinGecko](https://www.coingecko.com/en/coins/filecoin)\n- [Filecoin Vs Akash Network Comparison](https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m)";
    let supported = "Based on live quote evidence, Akash is smaller and higher beta. This is not financial advice.\n\n| Metric | Akash | Filecoin |\n| --- | --- | --- |\n| Market Cap | $229.88M | $662.41M |\n\nSources:\n- [Akash Network live USD price quote - CoinGecko](https://www.coingecko.com/en/coins/akash-network)\n- [Filecoin live USD price quote - CoinGecko](https://www.coingecko.com/en/coins/filecoin)\n- [Filecoin Vs Akash Network Comparison](https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m)";

    assert!(visible_direct_answer_from_raw(unsupported, &pending).is_none());
    assert!(visible_direct_answer_from_raw(supported, &pending).is_some());
}

#[test]
fn section_kind_resolution_prefers_exact_evidence_key_over_summary_aliases() {
    assert_eq!(
        section_kind_from_key("key_evidence"),
        Some(ReportSectionKind::Evidence)
    );
    assert_eq!(
        section_kind_from_key("what_happened"),
        Some(ReportSectionKind::Summary)
    );
}
