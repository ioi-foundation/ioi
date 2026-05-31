#[test]
fn rendered_summary_rejects_current_investment_answer_without_quote_grounding() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://cryptonium.cloud/articles/depin-decentralized-compute-wars-filecoin-akash-infrastructure-race-ai-web3".to_string(),
                title: Some("DePIN Compute Wars: Filecoin vs. Akash for AI & Web3".to_string()),
                excerpt: "A current comparison of Filecoin and Akash in decentralized compute infrastructure, including AI and Web3 demand, network risks, and adoption uncertainty.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m".to_string(),
                title: Some("Filecoin Vs Akash Network Comparison".to_string()),
                excerpt: "A six-month Filecoin and Akash Network comparison that includes current market price, sentiment, and investment risk indicators.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "I would not make a confident investment call from these sources alone. Akash looks more directly exposed to decentralized compute demand, while Filecoin has a broader storage/network thesis; both remain high-risk crypto assets and neither source set is enough for a full portfolio decision. This is not financial advice.\n\nKey points:\n- Akash has a clearer AI/decentralized compute narrative, but that also makes it more exposed to execution and adoption risk.\n- Filecoin is the more established storage network, but the retrieved comparison material does not prove stronger near-term upside.\n\nSources:\n- [DePIN Compute Wars: Filecoin vs. Akash for AI & Web3](https://cryptonium.cloud/articles/depin-decentralized-compute-wars-filecoin-akash-infrastructure-race-ai-web3)\n- [Filecoin Vs Akash Network Comparison](https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m)";
    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(facts.answer_rendered_layout_profile, "sourced_answer");
    assert!(facts.market_quote_grounding_required);
    assert!(!facts.market_quote_grounding_floor_met);
    assert!(
        !final_web_completion_contract_ready(&facts),
        "current investment comparisons need live quote grounding, not only secondary comparison pages"
    );
}

#[test]
fn rendered_summary_accepts_current_investment_answer_with_quote_grounding() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
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
                title: Some("Akash Network Price: AKT Live Price Chart".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.81 USD. Market cap: $235.94M. 24h trading volume: $6.65M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin Price: FIL Live Price Chart".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $2.34 USD. Market cap: $1.61B. 24h trading volume: $124.96M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://cryptonium.cloud/articles/depin-decentralized-compute-wars-filecoin-akash-infrastructure-race-ai-web3".to_string(),
                title: Some("DePIN Compute Wars: Filecoin vs. Akash for AI & Web3".to_string()),
                excerpt: "A comparison of Filecoin and Akash in decentralized compute and storage infrastructure, including AI demand, adoption uncertainty, and network risks.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on live quote pages and the comparison source, Akash has the clearer decentralized-compute growth thesis, while Filecoin is the more established decentralized-storage network. Akash is around $0.81 with about $236M market cap and $6.65M 24h volume; Filecoin is around $2.34 with about $1.61B market cap and $124.96M 24h volume. Both remain volatile crypto assets, so this is not financial advice.\n\nSources:\n- [Akash Network Price: AKT Live Price Chart](https://www.coingecko.com/en/coins/akash-network)\n- [Filecoin Price: FIL Live Price Chart](https://www.coingecko.com/en/coins/filecoin)\n- [DePIN Compute Wars: Filecoin vs. Akash for AI & Web3](https://cryptonium.cloud/articles/depin-decentralized-compute-wars-filecoin-akash-infrastructure-race-ai-web3)";
    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(facts.answer_rendered_layout_profile, "sourced_answer");
    assert!(facts.market_quote_grounding_required);
    assert!(facts.market_quote_grounding_floor_met);
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn model_authored_natural_answer_accepts_sources_from_typed_evidence() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
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
                title: Some("Akash Network Price: AKT Live Price Chart".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.78 USD. Market cap: $231M. 24h trading volume: $6.65M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin Price: FIL Live Price Chart".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.98 USD. Market cap: $770M. 24h trading volume: $124.96M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://cryptonium.cloud/articles/depin-decentralized-compute-wars-filecoin-akash-infrastructure-race-ai-web3".to_string(),
                title: Some("DePIN Compute Wars: Filecoin vs. Akash for AI & Web3".to_string()),
                excerpt: "A comparison of Filecoin and Akash in decentralized compute and storage infrastructure, including AI demand, adoption uncertainty, and network risks.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on the current quote evidence and project context, Filecoin is the larger and more established storage network, while Akash is the higher-beta decentralized compute play. Filecoin is trading around $0.98 with roughly $770M market cap and $124.96M 24h volume, while Akash is around $0.78 with roughly $231M market cap and $6.65M 24h volume. If you want lower relative volatility, Filecoin is the more conservative choice; if you want more upside tied to decentralized cloud and AI compute demand, Akash has the stronger growth setup. This is not financial advice.";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(facts.answer_rendered_layout_profile, "other");
    assert!(facts.market_quote_grounding_required);
    assert!(facts.market_quote_grounding_floor_met);
    assert!(facts.comparison_ready);
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn model_authored_natural_answer_accepts_two_quote_sources_without_source_clusters() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
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
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.792457 USD. Market cap: $232.40M. 24h trading volume: $6.09M. 24h price change: -1.09%.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.970942 USD. Market cap: $764.19M. 24h trading volume: $90.18M. 24h price change: -1.03%.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on the current quote evidence, Filecoin is the larger and more liquid decentralized-storage play, while Akash is the smaller decentralized-compute play with more upside torque and more volatility. Filecoin is around $0.97 with about $764M market cap and $90M 24h volume; Akash is around $0.79 with about $232M market cap and $6M 24h volume. Akash looks like the higher-risk growth bet, while Filecoin looks more conservative. This is not financial advice.";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(facts.answer_rendered_layout_profile, "other");
    assert!(facts.market_quote_grounding_required);
    assert!(facts.market_quote_grounding_floor_met);
    assert!(
        !facts.comparison_ready,
        "two typed quote reads should not need a deterministic story-slot layout"
    );
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn model_authored_market_answer_rejects_nominal_price_axis_and_missing_market_caps() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
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
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.787387 USD. Market cap: $230.57M. 24h trading volume: $4.80M. 24h price change: -1.38%.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.972233 USD. Market cap: $767.37M. 24h trading volume: $88.87M. 24h price change: -1.87%.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on the gathered evidence, Filecoin is trading at a higher nominal price per token than Akash. The lower price point for Akash may be attractive, but neither is objectively better from price alone.";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert!(facts.market_quote_grounding_required);
    assert!(facts.market_quote_grounding_floor_met);
    assert!(!facts.rendered_summary_semantic_floor_met);
    assert!(!final_web_completion_contract_ready(&facts));
}

#[test]
fn model_authored_market_answer_rejects_generic_fundamentals_without_typed_quote_metrics() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
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
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.784457 USD. Market cap: $229.60M. 24h trading volume: $4.65M. 24h price change: -2.45%.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.974784 USD. Market cap: $767.93M. 24h trading volume: $83.97M. 24h price change: -2.65%.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on the current market data and project fundamentals, Filecoin is a mature decentralized storage network with massive market cap and high liquidity. Akash is a decentralized cloud marketplace with higher growth potential and higher volatility. Choose Filecoin for stability and Akash for upside. This is not financial advice.";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert!(facts.market_quote_grounding_required);
    assert!(facts.market_quote_grounding_floor_met);
    assert!(!facts.rendered_summary_semantic_floor_met);
    assert!(!final_web_completion_contract_ready(&facts));
}

#[test]
fn current_investment_answer_uses_quote_grade_sources_plus_comparison_context() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
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
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.806303 USD. Market cap: $235.94M. 24h trading volume: $6.65M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.954 USD. Market cap: $654.12M. 24h trading volume: $124.96M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m".to_string(),
                title: Some("Filecoin Vs Akash Network Comparison".to_string()),
                excerpt: "A six-month comparison that mentions Filecoin and Akash Network prices, sentiment, and investment risk indicators.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on live quote sources and a comparison source, Akash has a higher-risk compute growth thesis while Filecoin is the more established storage network. Akash is around $0.81 with about $236M market cap and $6.65M 24h volume; Filecoin is around $0.95 with about $654M market cap and $124.96M 24h volume. This is not financial advice.\n\nSources:\n- [Akash Network live USD price quote](https://www.coingecko.com/en/coins/akash-network)\n- [Filecoin live USD price quote](https://www.coingecko.com/en/coins/filecoin)\n- [Filecoin Vs Akash Network Comparison](https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m)";
    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert_eq!(
        facts.selected_source_urls,
        vec![
            "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m".to_string(),
            "https://www.coingecko.com/en/coins/akash-network".to_string(),
            "https://www.coingecko.com/en/coins/filecoin".to_string(),
        ]
    );
    assert!(facts.market_quote_grounding_floor_met);
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn current_investment_market_quotes_terminalize_without_queued_structured_metric_candidate() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![
            "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m"
                .to_string(),
            "https://coinmarketcap.com/cmc-ai/filecoin/price-prediction/".to_string(),
            "https://api.coingecko.com/api/v3/simple/price?ids=filecoin&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true&precision=full".to_string(),
            "https://coinmarketcap.com/alexandria/article/what-is-decentralized-storage-a-deep-dive-by-filecoin".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://api.coingecko.com/api/v3/simple/price?ids=akash-network&vs_currencies=usd"
                .to_string(),
            "https://coinmarketcap.com/currencies/filecoin/".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.808010 USD. Market cap: $235.11M. 24h trading volume: $6.65M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://coinmarketcap.com/currencies/filecoin/".to_string(),
                title: Some(
                    "Filecoin price today, FIL to USD live price, marketcap and chart"
                        .to_string(),
                ),
                excerpt: "The live Filecoin price today is $0.9597 USD with a 24-hour trading volume of $123,595,098.67 USD. We update our FIL to USD price in real-time.".to_string(),
            },
        ],
        min_sources: 2,
    };

    assert_eq!(
        market_quote_structured_metric_source_count_for_sources(&pending.successful_reads, query),
        1
    );
    assert_eq!(
        web_pipeline_completion_reason(&pending, 1_780_081_560_000),
        Some(WebPipelineCompletionReason::MinSourcesReached)
    );
    assert_eq!(next_pending_web_candidate(&pending), None);
}

#[test]
fn current_investment_market_quotes_terminalize_after_decentralized_cloud_context() {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![
            "https://coinmarketcap.com/alexandria/article/what-is-decentralized-storage-a-deep-dive-by-filecoin".to_string(),
            "https://coinmarketcap.com/rankings/exchanges/derivatives/".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://cryptonium.cloud/articles/depin-decentralized-compute-wars-filecoin-akash-infrastructure-race-ai-web3".to_string(),
                title: Some("DePIN Compute Wars: Filecoin vs. Akash for AI & Web3".to_string()),
                excerpt: "A comparison of Filecoin and Akash in decentralized compute infrastructure, AI demand, adoption uncertainty, and network risks.".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://api.coingecko.com/api/v3/simple/price?ids=akash-network&vs_currencies=usd"
                .to_string(),
            "https://api.coingecko.com/api/v3/simple/price?ids=filecoin&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true&precision=full".to_string(),
            "https://stealthcloud.ai/cloud-paradigms/decentralized-cloud-computing/"
                .to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.795713 USD. Market cap: $232.56M. 24h trading volume: $7.11M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.9738 USD. Market cap: $667.12M. 24h trading volume: $116.91M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://stealthcloud.ai/cloud-paradigms/decentralized-cloud-computing/".to_string(),
                title: Some("Decentralized Cloud Computing: Filecoin, Akash, and the".to_string()),
                excerpt: "A critical analysis of decentralized cloud computing platforms including Filecoin, Akash Network, Arweave, and Flux, examining technical architectures, economic models, privacy properties, performance, reliability, and operational complexity.".to_string(),
            },
        ],
        min_sources: 2,
    };

    assert_eq!(
        market_quote_grounding_source_count_for_sources(&pending.successful_reads, query),
        2
    );
    assert_eq!(
        market_quote_comparison_context_source_count_for_sources(&pending.successful_reads, query),
        1
    );
    assert!(source_cluster_completion_contract_ready(&pending, 3));
    assert_eq!(
        web_pipeline_completion_reason(&pending, 1_780_081_570_000),
        Some(WebPipelineCompletionReason::MinSourcesReached)
    );
    assert_eq!(next_pending_web_candidate(&pending), None);
}

#[test]
fn current_investment_market_quotes_terminalize_after_quote_grade_asset_coverage_without_structured_metric_floor(
) {
    let query = "Which is a better investment right now, Akash or Filecoin?";
    let filecoin_api = "https://api.coingecko.com/api/v3/simple/price?ids=filecoin&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true&precision=full";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(query, None).ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
        started_step: 1,
        started_at_ms: 1_780_081_552_000,
        deadline_ms: 1_780_081_612_000,
        candidate_urls: vec![
            filecoin_api.to_string(),
            "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://api.coingecko.com/api/v3/simple/price?ids=akash-network&vs_currencies=usd&include_market_cap=true&include_24hr_vol=true&include_24hr_change=true&precision=full".to_string(),
            "https://coinmarketcap.com/currencies/filecoin/".to_string(),
            "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.795713 USD. Market cap: $232.56M. 24h trading volume: $7.11M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://coinmarketcap.com/currencies/filecoin/".to_string(),
                title: Some("Filecoin price today, FIL to USD live price, marketcap and chart | CoinMarketCap".to_string()),
                excerpt: "The live Filecoin price today is $0.9738 USD with a 24-hour trading volume of $116,908,021.44 USD. We update our FIL to USD price in real-time.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://walletinvestor.com/compare/filecoin-vs-akash-network/interval/6m".to_string(),
                title: Some("Filecoin Vs Akash Network Comparison".to_string()),
                excerpt: "Currency from Currency To Compare Price (USD) FIL 0.000000028 AKT 0.000000019 Market Cap (USD) FIL 16 AKT 5.".to_string(),
            },
        ],
        min_sources: 2,
    };

    assert_eq!(
        market_quote_structured_metric_source_count_for_sources(&pending.successful_reads, query),
        1
    );
    assert_eq!(
        web_pipeline_completion_reason(&pending, 1_780_081_570_000),
        Some(WebPipelineCompletionReason::MinSourcesReached)
    );
    assert_eq!(next_pending_web_candidate(&pending), None);
}

#[test]
fn current_investment_answer_rejects_rendered_summary_that_drops_quote_grade_asset() {
    let pending = PendingSearchCompletion {
        query: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        retrieval_contract: crate::agentic::web::derive_web_retrieval_contract(
            "Which is a better investment right now, Akash or Filecoin?",
            None,
        )
        .ok(),
        url: "https://www.bing.com/search?q=akash+filecoin+investment".to_string(),
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
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.806303 USD. Market cap: $235.94M.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://coinmarketcap.com/currencies/filecoin/".to_string(),
                title: Some("Filecoin price today, FIL to USD live price, marketcap and chart".to_string()),
                excerpt: "The live Filecoin price today is $0.954 USD with a 24-hour trading volume of $124,962,347.39 USD.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://coinmarketcap.com/cmc-ai/filecoin/price-prediction/".to_string(),
                title: Some("Filecoin price prediction".to_string()),
                excerpt: "A forecast article about Filecoin price scenarios.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let rendered_summary = "Based on the retrieved source notes, the live price of Filecoin (FIL) is approximately $0.954 USD. The provided information does not contain a current price or specific investment analysis for Akash, so I cannot make a definitive comparison. This is not financial advice.\n\nSources:\n- [Filecoin price today, FIL to USD live price, marketcap and chart](https://coinmarketcap.com/currencies/filecoin/)\n- [Filecoin price prediction](https://coinmarketcap.com/cmc-ai/filecoin/price-prediction/)";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        rendered_summary,
    );

    assert!(facts.market_quote_grounding_required);
    assert_eq!(facts.market_quote_grounding_source_count, 1);
    assert!(!facts.market_quote_grounding_floor_met);
    assert!(!facts.evidence_citation_read_backing_floor_met);
    assert!(
        !final_web_completion_contract_ready(&facts),
        "the rendered answer must cite quote-grade sources for both compared assets"
    );
}

