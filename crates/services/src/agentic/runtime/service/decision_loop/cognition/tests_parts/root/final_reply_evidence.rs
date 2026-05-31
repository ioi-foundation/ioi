#[test]
fn direct_chat_reply_sanitizer_removes_think_blocks() {
    let cleaned = super::sanitize_direct_chat_reply_output(
        "<think>I should not show this.</think>\nHere is the final answer.",
    );

    assert_eq!(cleaned, "Here is the final answer.");
}

#[test]
fn final_reply_incomplete_reason_flags_cut_off_markdown() {
    assert_eq!(
        super::final_reply_incomplete_reason(
            "### Current Market Data\n* **Filecoin:** price details\n* **Trading"
        ),
        Some("unclosed_markdown_bold")
    );
    assert_eq!(
        super::final_reply_incomplete_reason("Here is a complete answer with **bold** text."),
        None
    );
}

#[test]
fn final_reply_html_document_contract_detects_source_document_requests() {
    assert!(super::final_reply_goal_requests_html_document(
        "Create a website that explains post-quantum computers."
    ));
    assert!(super::final_reply_goal_requests_html_document(
        "Output an HTML file about photonic quantum computing."
    ));
    assert!(!super::final_reply_goal_requests_html_document(
        "Explain post-quantum cryptography in two paragraphs."
    ));

    assert_eq!(
        super::final_reply_html_document_reason(
            ".hero { color: red; }<body>Missing the opening document.",
            "Create a website that explains post-quantum computers."
        ),
        Some("missing_html_document_start")
    );
    assert_eq!(
        super::final_reply_html_document_reason(
            "<!DOCTYPE html><html><head></head><body><h1>Done</h1></body></html>",
            "Create a website that explains post-quantum computers."
        ),
        None
    );
}

#[test]
fn final_reply_repair_messages_focus_on_evidence_context_without_invalid_draft() {
    let messages = serde_json::json!([
        { "role": "system", "content": "FINAL RESPONSE MODE" },
        { "role": "user", "content": "Original request and gathered evidence" }
    ]);

    let retry = super::final_reply_repair_messages(
        &messages,
        "Partial answer with **Trading",
        "unclosed_markdown_bold",
        1,
        "Which is a better investment right now, Akash or Filecoin?",
        "Typed market quote evidence from tool results:\n- asset: Akash Network; price: $0.78; Market cap: $230M; 24h trading volume: $4M; 24h price change: 1%",
    );
    let retry_messages = retry.as_array().expect("retry array");

    assert_eq!(retry_messages.len(), 2);
    assert_eq!(retry_messages[0]["role"], "system");
    assert!(retry_messages[1]["content"]
        .as_str()
        .unwrap()
        .contains("invalid draft is intentionally omitted"));
    assert!(!retry_messages[1]["content"]
        .as_str()
        .unwrap()
        .contains("Partial answer"));
    assert!(retry_messages[1]["content"]
        .as_str()
        .unwrap()
        .contains("Typed market quote evidence"));
    assert!(retry_messages[0]["content"]
        .as_str()
        .unwrap()
        .contains("24h trading volume"));
}

#[test]
fn final_reply_evidence_context_prefers_successful_relevant_tool_output() {
    let history = vec![
        chat_message(
            "tool",
            "Tool Output (file__read):\nline one\n### Stage 3: Retrieval\nNext step: Stage 4 repo-aware read/search.\n",
            1,
        ),
        chat_message(
            "tool",
            "Tool Output (file__read): ERROR_CLASS=NoEffectAfterAction skipped replay",
            2,
        ),
    ];

    let context = super::final_reply_evidence_context(
        &history,
        "What does progress look like per .internal/plans/example.md?",
        "fallback",
    );

    assert!(context.contains("Stage 3"), "{context}");
    assert!(context.contains("Stage 4"), "{context}");
    assert!(!context.contains("NoEffectAfterAction"), "{context}");
}

#[test]
fn final_reply_evidence_context_normalizes_web_tool_results_for_model_handoff() {
    let history = vec![chat_message(
        "tool",
        r#"Tool Output (web__read):
{
  "schema_version": 1,
  "tool": "web__read",
  "backend": "edge:read:http:coingecko-simple-price",
  "url": "https://api.coingecko.com/api/v3/simple/price?ids=akash-network",
  "sources": [
    {
      "url": "https://www.coingecko.com/en/coins/akash-network",
      "title": "Akash Network live USD price quote - CoinGecko",
      "snippet": "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.787649 USD.\n\nMarket cap: $230.06M.\n\n24h trading volume: $5.04M.\n\n24h price change: -2.40%."
    }
  ],
  "documents": [
    {
      "url": "https://www.coingecko.com/en/coins/akash-network",
      "title": "Akash Network",
      "content_text": "Akash Network price $0.787649 USD with market cap $230.06M."
    }
  ]
}"#,
        1,
    )];

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment right now, Akash or Filecoin?",
        "fallback",
    );

    assert!(
        context.contains("Typed market quote evidence from tool results"),
        "{context}"
    );
    assert!(context.contains("price $0.787649 USD"), "{context}");
    assert!(context.contains("Market cap: $230.06M"), "{context}");
    assert!(
        context.contains("https://www.coingecko.com/en/coins/akash-network"),
        "{context}"
    );
    assert!(!context.contains("schema_version"), "{context}");
}

#[test]
fn final_reply_evidence_context_unwraps_nested_agent_action_web_output() {
    let web_payload = serde_json::json!({
        "schema_version": 1,
        "tool": "web__read",
        "backend": "edge:read:http:coingecko-simple-price",
        "url": "https://api.coingecko.com/api/v3/simple/price?ids=akash-network",
        "sources": [
            {
                "url": "https://www.coingecko.com/en/coins/akash-network",
                "title": "Akash Network live USD price quote - CoinGecko",
                "snippet": "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.781608 USD. Market cap: $228.38M. 24h price change: -2.52%."
            }
        ],
        "documents": [
            {
                "url": "https://www.coingecko.com/en/coins/akash-network",
                "title": "Akash Network",
                "content_text": "Akash Network price $0.781608 USD with market cap $228.38M."
            }
        ]
    });
    let nested = serde_json::json!({
        "AgentActionResult": {
            "agent_status": "Running",
            "error_class": null,
            "output": web_payload.to_string(),
            "step_index": 2,
            "tool_name": "web__read"
        }
    })
    .to_string();
    let history = vec![chat_message("tool", &nested, 1)];

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment right now, Akash or Filecoin?",
        "fallback",
    );

    assert!(
        context.contains("Typed market quote evidence from tool results"),
        "{context}"
    );
    assert!(context.contains("price $0.781608 USD"), "{context}");
    assert!(context.contains("Market cap: $228.38M"), "{context}");
    assert!(
        context.contains("https://www.coingecko.com/en/coins/akash-network"),
        "{context}"
    );
    assert!(!context.contains("AgentActionResult"), "{context}");
}

#[test]
fn final_reply_evidence_context_preserves_multiple_web_result_notes_and_skips_ready_placeholder() {
    let mut history = Vec::new();
    for idx in 0..5 {
        history.push(chat_message(
            "tool",
            &format!(
                r#"Tool Output (web__read):
{{
  "schema_version": 1,
  "tool": "web__read",
  "url": "https://example.com/source-{idx}",
  "sources": [
    {{
      "url": "https://example.com/source-{idx}",
      "title": "Source {idx} live quote",
      "snippet": "Source {idx} reports price ${idx}.00 USD and market cap ${idx}00M for Akash or Filecoin."
    }}
  ]
}}"#
            ),
            idx as u64,
        ));
    }
    history.push(chat_message(
        "tool",
        "Web evidence is ready for a model-authored final answer.",
        99,
    ));

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment right now, Akash or Filecoin?",
        "fallback",
    );

    assert!(
        context.contains("https://example.com/source-0"),
        "{context}"
    );
    assert!(
        context.contains("https://example.com/source-4"),
        "{context}"
    );
    assert!(
        !context.contains("model-authored final answer"),
        "{context}"
    );
}

#[test]
fn final_reply_evidence_context_keeps_older_web_evidence_beyond_recent_prompt_window() {
    let akash = r#"Tool Output (web__read):
{
  "schema_version": 1,
  "tool": "web__read",
  "url": "https://api.coingecko.com/api/v3/simple/price?ids=akash-network",
  "sources": [
    {
      "title": "Akash Network live USD price quote - CoinGecko",
      "url": "https://www.coingecko.com/en/coins/akash-network",
      "snippet": "Akash Network live USD quote: price $0.783 USD. Market cap: $228.65M. 24h price change: -2.75%."
    }
  ]
}"#;
    let mut history = vec![chat_message("tool", akash, 1)];
    for index in 0..8 {
        history.push(chat_message(
            "tool",
            &format!("Tool Output (file__read): filler evidence {index}"),
            index + 2,
        ));
    }

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment, Filecoin or Akash Network?",
        "fallback",
    );

    assert!(
        context.contains("Akash Network live USD price quote"),
        "{context}"
    );
    assert!(context.contains("$0.783"), "{context}");
}

#[test]
fn final_reply_evidence_context_ranks_quote_evidence_above_later_weak_web_reads() {
    let quote = r#"Tool Output (web__read):
{
  "schema_version": 1,
  "tool": "web__read",
  "backend": "edge:read:http:coingecko-simple-price",
  "url": "https://api.coingecko.com/api/v3/simple/price?ids=akash-network",
  "sources": [
    {
      "title": "Akash Network live USD price quote - CoinGecko",
      "url": "https://www.coingecko.com/en/coins/akash-network",
      "snippet": "Akash Network live USD quote: price $0.783 USD. Market cap: $229.15M. 24h trading volume: $4.95M."
    }
  ]
}"#;
    let mut history = vec![chat_message("tool", quote, 1)];
    for index in 0..14 {
        history.push(chat_message(
            "tool",
            &format!(
                r#"Tool Output (web__read):
{{
  "schema_version": 1,
  "tool": "web__read",
  "url": "https://crypto.example.com/weak-{index}",
  "sources": [
    {{
      "title": "General crypto page {index}",
      "url": "https://crypto.example.com/weak-{index}",
      "snippet": "General market page with no specific Akash or Filecoin quote."
    }}
  ]
}}"#
            ),
            (index + 2) as u64,
        ));
    }

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment right now, Akash or Filecoin?",
        "fallback",
    );

    assert!(
        context.contains("Akash Network live USD price quote"),
        "{context}"
    );
    assert!(context.contains("price: $0.783"), "{context}");
    assert!(context.contains("Market cap: $229.15M"), "{context}");
    assert!(!context.contains("General crypto page"), "{context}");
    assert!(!context.contains("weak-"), "{context}");
}

#[test]
fn final_reply_evidence_context_preserves_comparison_quote_matrix_for_model_handoff() {
    let akash = r#"Tool Output (web__read):
{
  "schema_version": 1,
  "tool": "web__read",
  "backend": "edge:read:http:coingecko-simple-price",
  "url": "https://api.coingecko.com/api/v3/simple/price?ids=akash-network",
  "sources": [
    {
      "title": "Akash Network live USD price quote - CoinGecko",
      "url": "https://www.coingecko.com/en/coins/akash-network",
      "snippet": "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.783364 USD.\n\nMarket cap: $228.32M.\n\n24h trading volume: $4.88M.\n\n24h price change: -2.80%."
    }
  ]
}"#;
    let filecoin = r#"Tool Output (web__read):
{
  "schema_version": 1,
  "tool": "web__read",
  "backend": "edge:read:http:coingecko-simple-price",
  "url": "https://api.coingecko.com/api/v3/simple/price?ids=filecoin",
  "sources": [
    {
      "title": "Filecoin live USD price quote - CoinGecko",
      "url": "https://www.coingecko.com/en/coins/filecoin",
      "snippet": "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.969088 USD.\n\nMarket cap: $765.06M.\n\n24h trading volume: $95.70M.\n\n24h price change: 1.18%."
    }
  ]
}"#;
    let history = vec![
        chat_message("tool", akash, 1),
        chat_message("tool", filecoin, 2),
    ];

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment right now, Akash or Filecoin?",
        "fallback",
    );

    assert!(
        context.contains("Typed market quote evidence from tool results"),
        "{context}"
    );
    assert!(
        context.contains("Required current market facts from typed `web__read` outputs"),
        "{context}"
    );
    assert!(
        context.contains("Akash Network live USD price quote"),
        "{context}"
    );
    assert!(context.contains("$0.783364"), "{context}");
    assert!(context.contains("$228.32M"), "{context}");
    assert!(
        context.contains("Filecoin live USD price quote"),
        "{context}"
    );
    assert!(context.contains("$0.969088"), "{context}");
    assert!(context.contains("$765.06M"), "{context}");
    assert!(!context.contains("schema_version"), "{context}");
}

#[test]
fn direct_chat_reply_sanitizer_unwraps_accidental_tool_json() {
    let output = r#"{"name":"chat__reply","arguments":{"message":"Final answer in Markdown."}}"#;
    assert_eq!(
        super::sanitize_direct_chat_reply_output(output),
        "Final answer in Markdown."
    );
}

#[test]
fn final_reply_pending_context_preserves_comparison_quote_matrix_for_model_handoff() {
    let pending = PendingSearchCompletion {
        query: "which is better investment akash filecoin".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.792457 USD.\n\nMarket cap: $232.40M.\n\n24h trading volume: $5.12M.\n\n24h price change: -1.09%."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.970942 USD.\n\nMarket cap: $764.19M.\n\n24h trading volume: $95.20M.\n\n24h price change: -1.03%."
                    .to_string(),
            },
        ],
        ..PendingSearchCompletion::default()
    };

    let context = super::final_reply_market_quote_context_from_pending(
        &pending,
        "Which is a better investment right now, Akash or Filecoin?",
    )
    .expect("pending quote context");

    assert!(
        context.contains("Typed market quote evidence from tool results"),
        "{context}"
    );
    assert!(
        context.contains("Akash Network live USD price quote"),
        "{context}"
    );
    assert!(context.contains("$0.792457"), "{context}");
    assert!(context.contains("$232.40M"), "{context}");
    assert!(context.contains("$5.12M"), "{context}");
    assert!(
        context.contains("Filecoin live USD price quote"),
        "{context}"
    );
    assert!(context.contains("$0.970942"), "{context}");
    assert!(context.contains("$764.19M"), "{context}");
    assert!(context.contains("$95.20M"), "{context}");
    assert!(!context.contains("schema_version"), "{context}");
}

#[test]
fn final_reply_pending_context_preserves_quote_and_supporting_web_evidence() {
    let pending = PendingSearchCompletion {
        query: "which is better investment akash filecoin".to_string(),
        query_contract: "Which is a better investment right now, Akash or Filecoin?".to_string(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/akash-network".to_string(),
                title: Some("Akash Network live USD price quote - CoinGecko".to_string()),
                excerpt: "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.792457 USD.\n\nMarket cap: $232.40M.\n\n24h trading volume: $5.12M.\n\n24h price change: -1.09%."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coingecko.com/en/coins/filecoin".to_string(),
                title: Some("Filecoin live USD price quote - CoinGecko".to_string()),
                excerpt: "Filecoin (filecoin) live USD quote from CoinGecko simple price API: price $0.970942 USD.\n\nMarket cap: $764.19M.\n\n24h trading volume: $95.20M.\n\n24h price change: -1.03%."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://example.com/depin-compute-storage".to_string(),
                title: Some("Decentralized compute and storage overview".to_string()),
                excerpt: "Akash Network is positioned around decentralized compute and GPU capacity. Filecoin is positioned around decentralized storage and data infrastructure. Both remain volatile DePIN assets with different risk profiles."
                    .to_string(),
            },
        ],
        ..PendingSearchCompletion::default()
    };

    let context = super::final_reply_pending_web_evidence_context(
        &pending,
        "Which is a better investment right now, Akash or Filecoin?",
    )
    .expect("pending web context");

    assert!(
        context.contains("Typed market quote evidence from tool results"),
        "{context}"
    );
    assert!(
        super::final_reply_pending_market_quote_ready(
            &pending,
            "Which is a better investment right now, Akash or Filecoin?"
        ),
        "{context}"
    );
    assert!(
        context.contains("Typed web evidence from tool results"),
        "{context}"
    );
    assert!(context.contains("$232.40M"), "{context}");
    assert!(context.contains("$764.19M"), "{context}");
    assert!(context.contains("decentralized compute"), "{context}");
    assert!(context.contains("decentralized storage"), "{context}");
    assert!(!context.contains("Story 1"), "{context}");
    assert!(!context.contains("schema_version"), "{context}");
}

#[test]
fn final_reply_evidence_context_keeps_supporting_web_evidence_with_market_quotes() {
    let quote = r#"Tool Output (web__read):
{
  "schema_version": 1,
  "tool": "web__read",
  "url": "https://api.coingecko.com/api/v3/simple/price?ids=akash-network",
  "sources": [
    {
      "title": "Akash Network live USD price quote - CoinGecko",
      "url": "https://www.coingecko.com/en/coins/akash-network",
      "snippet": "Akash Network (akash-network) live USD quote from CoinGecko simple price API: price $0.790464 USD. Market cap: $232.04M. 24h trading volume: $5.25M. 24h price change: 0.79%."
    }
  ]
}"#;
    let context_source = r#"Tool Output (web__search):
{
  "schema_version": 1,
  "tool": "web__search",
  "query": "Akash Filecoin investment comparison",
  "sources": [
    {
      "title": "Decentralized compute versus storage",
      "url": "https://example.com/depin-compute-storage",
      "snippet": "Akash Network focuses on decentralized compute and GPU capacity, while Filecoin focuses on decentralized storage and data infrastructure."
    }
  ]
}"#;
    let history = vec![
        chat_message("tool", quote, 1),
        chat_message("tool", context_source, 2),
    ];

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment right now, Akash or Filecoin?",
        "",
    );

    assert!(context.contains("price: $0.790464"), "{context}");
    assert!(context.contains("Market cap: $232.04M"), "{context}");
    assert!(context.contains("decentralized compute"), "{context}");
    assert!(context.contains("decentralized storage"), "{context}");
}

#[test]
fn final_reply_evidence_context_does_not_import_market_quotes_for_generic_current_queries() {
    let quote = r#"Tool Output (web__read):
{
  "schema_version": 1,
  "tool": "web__read",
  "url": "https://api.coingecko.com/api/v3/simple/price?ids=filecoin",
  "sources": [
    {
      "title": "Filecoin live USD price quote - CoinGecko",
      "url": "https://www.coingecko.com/en/coins/filecoin",
      "snippet": "Filecoin live quote: price $0.96 USD. Market cap: $758M."
    }
  ]
}"#;
    let history = vec![chat_message("tool", quote, 1)];

    let context = super::final_reply_evidence_context(
        &history,
        "Find current sources for today's top local AI model runtime issue.",
        "",
    );

    assert!(
        !context.contains("Typed market quote evidence from tool results"),
        "{context}"
    );
}

#[test]
fn final_reply_evidence_context_extracts_quote_matrix_from_recent_events_fallback() {
    let recent_events = concat!(
        "RECENT SESSION EVENTS:\n",
        "tool: web__read ; https://api.coingecko.com/api/v3/simple/price?ids=akash-network ; ",
        "sources=Akash Network live USD price quote - CoinGecko | ",
        "https://www.coingecko.com/en/coins/akash-network | ",
        "Akash Network (akash-network) live USD quote from CoinGecko simple price API: ",
        "price $0.787880 USD. Market cap: $230.06M. 24h trading volume: $4.33M. ",
        "24h price change: 0.47%.\n",
        "tool: web__read ; https://api.coingecko.com/api/v3/simple/price?ids=filecoin ; ",
        "sources=Filecoin live USD price quote - CoinGecko | ",
        "https://www.coingecko.com/en/coins/filecoin | ",
        "Filecoin (filecoin) live USD quote from CoinGecko simple price API: ",
        "price $0.977923 USD. Market cap: $770.06M. 24h trading volume: $73.27M. ",
        "24h price change: 0.54%.\n"
    );

    let context = super::final_reply_evidence_context(
        &[],
        "Which is a better investment right now, Akash or Filecoin?",
        recent_events,
    );

    assert!(
        context.contains("Typed market quote evidence from tool results"),
        "{context}"
    );
    assert!(context.contains("asset: Akash Network"), "{context}");
    assert!(context.contains("price: $0.787880"), "{context}");
    assert!(context.contains("Market cap: $230.06M"), "{context}");
    assert!(context.contains("24h trading volume: $4.33M"), "{context}");
    assert!(context.contains("asset: Filecoin"), "{context}");
    assert!(context.contains("price: $0.977923"), "{context}");
    assert!(context.contains("Market cap: $770.06M"), "{context}");
    assert!(context.contains("24h trading volume: $73.27M"), "{context}");
}

#[test]
fn final_reply_evidence_contradiction_detects_missing_market_quote_claim() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.790155 USD. Market cap: $229.87M. 24h price change: -1.17%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.972307 USD. Market cap: $764.91M. 24h price change: 1.26%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "The evidence provides specific live pricing and market metrics for Filecoin, while no comparable data was retrieved for Akash.";

    assert_eq!(
        super::final_reply_evidence_contradiction_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        Some("contradicts_typed_market_quote_evidence")
    );
}

#[test]
fn final_reply_evidence_contradiction_detects_live_quote_missing_search_result_claim() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.791100 USD. Market cap: $231.15M. 24h price change: -1.87%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.969536 USD. Market cap: $762.95M. 24h price change: 1.02%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "The provided search results do not contain specific live price quotes or market cap data for Akash. Without specific price data for Akash, the lack of current price data in the evidence means a definitive comparison cannot be made.";

    assert_eq!(
        super::final_reply_evidence_contradiction_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        Some("contradicts_typed_market_quote_evidence")
    );
}

#[test]
fn final_reply_evidence_contradiction_detects_missing_akash_metrics_claim() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.792457 USD. Market cap: $232.40M. 24h price change: -1.09%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.970942 USD. Market cap: $764.19M. 24h price change: -1.03%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "Akash: No price, market cap, or performance data was found in the search results. Without this data, it is impossible to determine if Akash is currently better than Filecoin.";

    assert_eq!(
        super::final_reply_evidence_contradiction_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        Some("contradicts_typed_market_quote_evidence")
    );
}

#[test]
fn final_reply_evidence_contradiction_detects_nominal_price_investment_claim() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.790155 USD. Market cap: $229.87M. 24h price change: -1.17%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.972307 USD. Market cap: $764.91M. 24h price change: 1.26%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "Filecoin appears to be the stronger investment primarily due to its higher price point and established market presence.";

    assert_eq!(
        super::final_reply_evidence_contradiction_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        Some("infers_investment_quality_from_nominal_token_price")
    );
}

#[test]
fn final_reply_evidence_contradiction_detects_lower_entry_price_investment_claim() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.790155 USD. Market cap: $229.87M. 24h price change: -1.17%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.972307 USD. Market cap: $764.91M. 24h price change: 1.26%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "Choose Akash if you prefer a lower per-token price and an accessible entry point for investors.";

    assert_eq!(
        super::final_reply_evidence_contradiction_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        Some("infers_investment_quality_from_nominal_token_price")
    );
}

#[test]
fn final_reply_evidence_contract_allows_nominal_price_disclaimer_without_using_it_as_thesis() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.788207 USD. Market cap: $230.21M. 24h trading volume: $4.65M. 24h price change: -1.60%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.976086 USD. Market cap: $768.08M. 24h trading volume: $83.59M. 24h price change: -2.82%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "Akash is quoted around $0.788, with a market cap near $230.21M and 24h volume around $4.65M. Filecoin is quoted around $0.976, with a market cap near $768.08M and 24h volume around $83.59M. While Filecoin currently trades at a higher nominal price, token price alone is not a definitive indicator of investment quality.";

    assert_eq!(
        super::final_reply_evidence_contract_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        None
    );
}

#[test]
fn final_reply_evidence_contract_detects_omitted_market_quote_metrics() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.788207 USD. Market cap: $230.21M. 24h trading volume: $4.65M. 24h price change: -1.60%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.976086 USD. Market cap: $768.08M. 24h trading volume: $83.59M. 24h price change: -2.82%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "The observed live USD prices are $0.788207 for Akash and $0.976086 for Filecoin. Price alone does not determine investment quality.";

    assert_eq!(
        super::final_reply_evidence_contract_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        Some("omits_typed_market_quote_market_caps")
    );
}

#[test]
fn final_reply_evidence_contract_accepts_preserved_market_quote_metrics() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.788207 USD. Market cap: $230.21M. 24h trading volume: $4.65M. 24h price change: -1.60%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.976086 USD. Market cap: $768.08M. 24h trading volume: $83.59M. 24h price change: -2.82%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "Akash is quoted around $0.788, with a market cap near $230.21M and 24h volume around $4.65M. Filecoin is quoted around $0.976, with a market cap near $768.08M and 24h volume around $83.59M. Filecoin is larger and more liquid, while Akash is the smaller-cap compute play.";

    assert_eq!(
        super::final_reply_evidence_contract_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        None
    );
}

#[test]
fn final_reply_evidence_contract_rejects_stale_market_scale_metrics() {
    let evidence = "Typed market quote evidence from tool results:\n\
- Akash Network live USD price quote - CoinGecko | Akash Network live USD quote: price $0.788207 USD. Market cap: $230.21M. 24h trading volume: $4.65M. 24h price change: -1.60%. | source=https://www.coingecko.com/en/coins/akash-network\n\
- Filecoin live USD price quote - CoinGecko | Filecoin live USD quote: price $0.976086 USD. Market cap: $768.08M. 24h trading volume: $83.59M. 24h price change: -2.82%. | source=https://www.coingecko.com/en/coins/filecoin";
    let message = "Akash is quoted around $0.788, with a market cap near $230.21M and 24h volume around $4.65M. Filecoin is quoted around $0.976, with a market cap near $768.08M and 24h volume around $168M.";

    assert_eq!(
        super::final_reply_evidence_contract_reason(
            message,
            evidence,
            "Which is a better investment right now, Akash or Filecoin?",
        ),
        Some("unsupported_market_quote_metric")
    );
}

#[test]
fn final_reply_evidence_context_unwraps_preview_wrapped_web_payload() {
    let preview_payload = serde_json::json!({
        "schema_version": 1,
        "tool": "web__read",
        "url": "https://coinmarketcap.com/currencies/akash-network/",
        "sources": [
            {
                "title": "Akash Network price today, AKT to USD live price",
                "url": "https://coinmarketcap.com/currencies/akash-network/",
                "snippet": "The live Akash Network price today is $0.7809 USD with a 24-hour trading volume of $6,133,102.88 USD."
            }
        ]
    });
    let wrapped = serde_json::json!({
        "original_bytes": 29148,
        "preview": preview_payload.to_string(),
        "truncated": true
    })
    .to_string();
    let history = vec![chat_message("tool", &wrapped, 1)];

    let context = super::final_reply_evidence_context(
        &history,
        "Which is a better investment right now, Akash or Filecoin?",
        "fallback",
    );

    assert!(context.contains("Tool result: web__read"), "{context}");
    assert!(context.contains("Akash Network price today"), "{context}");
    assert!(context.contains("$0.7809 USD"), "{context}");
    assert!(!context.contains("original_bytes"), "{context}");
}

