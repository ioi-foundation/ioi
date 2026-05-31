use ioi_types::app::agentic::WebRetrievalContract;

use super::*;

fn nist_answer_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        None,
    )
    .expect("retrieval contract")
}

fn retained_like_nist_answer_query_contract() -> &'static str {
    "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks."
}

fn retained_like_nist_answer_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(
        retained_like_nist_answer_query_contract(),
        None,
    )
    .expect("retrieval contract")
}

fn retained_like_nist_answer_pending() -> PendingSearchCompletion {
    PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: retained_like_nist_answer_query_contract().to_string(),
        retrieval_contract: Some(retained_like_nist_answer_contract()),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_775_102_589_241,
        deadline_ms: 1_775_102_649_241,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 is the status report on the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                    .to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards."
                        .to_string(),
            },
        ],
        min_sources: 2,
    }
}

fn weather_snapshot_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(
        "What's the weather like right now in Anderson, SC?",
        None,
    )
    .expect("retrieval contract")
}

fn weather_snapshot_pending() -> PendingSearchCompletion {
    PendingSearchCompletion {
        query: "What's the weather like right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather like right now in Anderson, SC?".to_string(),
        retrieval_contract: Some(weather_snapshot_contract()),
        url: "https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical".to_string(),
        started_step: 1,
        started_at_ms: 1_773_235_143_000,
        deadline_ms: 1_773_235_203_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical".to_string(),
            title: Some(
                "Anderson, Anderson County Airport (KAND) current conditions".to_string(),
            ),
            excerpt: "Current conditions at Anderson, Anderson County Airport (KAND); Fair; temperature 65°F (18°C); Humidity 93%; Wind Speed SW 3 mph; Barometer 30.06 in (1017.2 mb); Visibility 10.00 mi; Last update 11 Mar 8:56 am EDT.".to_string(),
        }],
        min_sources: 1,
    }
}

fn openai_api_pricing_snapshot_pending() -> PendingSearchCompletion {
    let query = "What is the latest OpenAI API pricing?";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://duckduckgo.com/html/?q=openai+api+pricing".to_string(),
        started_step: 1,
        started_at_ms: 1_776_227_441_000,
        deadline_ms: 1_776_227_561_000,
        candidate_urls: vec![
            "https://openai.com/api/pricing/".to_string(),
            "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://openai.com/api/pricing/".to_string(),
                title: Some("API Pricing | OpenAI API".to_string()),
                excerpt: "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services".to_string(),
                title: Some("Making Sense of the OpenAI API's Pricing and Services".to_string()),
                excerpt: "A guide to understanding the OpenAI API's pricing, including token costs and service tiers.".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://duckduckgo.com/html/?q=openai+api+pricing".to_string(),
            "https://openai.com/api/pricing/".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://openai.com/api/pricing/".to_string(),
            title: Some("API Pricing | OpenAI API".to_string()),
            excerpt: "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs".to_string(),
        }],
        min_sources: 1,
    }
}

fn liveish_openai_api_pricing_anchor_pending() -> PendingSearchCompletion {
    let query = "What is the latest OpenAI API pricing?";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=openai+api+pricing".to_string(),
        started_step: 1,
        started_at_ms: 1_776_229_080_000,
        deadline_ms: 1_776_229_200_000,
        candidate_urls: vec![
            "https://openai.com/api/pricing/".to_string(),
            "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
            title: Some("OpenAI API Pricing & Services - A Comprehensive Guide".to_string()),
            excerpt: "Price: Input: $1.10 per 1M tokens, Cached input: $0.275 per 1M tokens, Output: $4.40 per 1M tokens.".to_string(),
        }],
        attempted_urls: vec![
            "https://search.brave.com/search?q=openai+api+pricing".to_string(),
            "https://openai.com/api/pricing/".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://openai.com/api/pricing/".to_string(),
            title: Some("OpenAI API Pricing | OpenAI".to_string()),
            excerpt: String::new(),
        }],
        min_sources: 1,
    }
}

include!("tests_parts/document_report_contract.rs");
include!("tests_parts/market_currentness.rs");
include!("tests_parts/rendered_summary_quality.rs");
include!("tests_parts/final_selection.rs");
