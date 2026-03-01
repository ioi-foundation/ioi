use super::*;

#[test]
fn web_pipeline_min_sources_scales_with_explicit_citation_contract() {
    let query = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with 2 citations each.";
    assert_eq!(web_pipeline_min_sources(query), 3);
}

#[test]
fn web_pipeline_min_sources_defaults_without_explicit_citation_contract() {
    let query = "Summarize active cloud incidents from major status pages.";
    assert_eq!(web_pipeline_min_sources(query), 1);
}

#[test]
fn web_pipeline_required_citations_per_story_honors_for_each_clause() {
    let query = "As of now (UTC), what are the top 3 U.S. breaking stories from the last 6 hours? For each: what happened, what changed in the last hour, why it matters, and 2 source citations with absolute dates/times.";
    assert_eq!(required_citations_per_story(query), 2);
}

#[test]
fn web_pipeline_required_citations_per_story_defaults_to_two_for_generic_headlines() {
    assert_eq!(
        required_citations_per_story("Tell me today's top news headlines."),
        2
    );
}

#[test]
fn web_pipeline_treats_google_news_topics_as_search_hub() {
    assert!(is_search_hub_url(
        "https://news.google.com/topics/CAAqIggKIhxDQkFTRHdvSkwyMHZNRGxqTjNjd0VnSmxiaWdBUAE?hl=en-US&ceid=US:en"
    ));
}

#[test]
fn web_pipeline_required_story_count_defaults_to_one_for_single_fact_queries() {
    let query = "Who is the latest OpenAI CEO?";
    assert_eq!(required_story_count(query), 1);
    assert!(!query_requires_structured_synthesis(query));
}

#[test]
fn web_pipeline_required_story_count_preserves_collection_queries() {
    let query = "top active cloud incidents";
    assert_eq!(required_story_count(query), WEB_PIPELINE_REQUIRED_STORIES);
    assert!(query_requires_structured_synthesis(query));
}

#[test]
fn web_pipeline_required_story_count_handles_headline_punctuation() {
    let query = "Tell me today's top news headlines.";
    assert_eq!(required_story_count(query), WEB_PIPELINE_REQUIRED_STORIES);
    assert!(query_requires_structured_synthesis(query));
}

#[test]
fn web_pipeline_pre_read_multi_story_enforces_distinct_domain_payload() {
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
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(query, 3, &bundle);
    let domains = plan
        .candidate_urls
        .iter()
        .filter_map(|url| {
            url::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(domains.len(), 3, "expected one URL per distinct domain");
    assert!(
        plan.candidate_urls.len() >= 2,
        "expected at least two article candidates, got {:?}",
        plan.candidate_urls
    );
}

#[test]
fn web_pipeline_pre_read_multi_story_marks_probe_when_distinct_domain_floor_unmet() {
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
                url: "https://www.foxnews.com/us/example-story-one".to_string(),
                title: Some("State officials issue emergency declaration".to_string()),
                snippet: Some("Officials issued an emergency declaration overnight.".to_string()),
                domain: Some("foxnews.com".to_string()),
            },
            WebSource {
                source_id: "fox-politics".to_string(),
                rank: Some(2),
                url: "https://www.foxnews.com/politics/example-story-two".to_string(),
                title: Some("Lawmakers unveil bipartisan funding deal".to_string()),
                snippet: Some("Lawmakers unveiled a bipartisan funding deal Tuesday.".to_string()),
                domain: Some("foxnews.com".to_string()),
            },
            WebSource {
                source_id: "fox-world".to_string(),
                rank: Some(3),
                url: "https://www.foxnews.com/world/example-story-three".to_string(),
                title: Some("International summit reaches ceasefire framework".to_string()),
                snippet: Some("Delegates reached a ceasefire framework after talks.".to_string()),
                domain: Some("foxnews.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(query, 3, &bundle);
    assert_eq!(plan.candidate_urls.len(), 1);
    assert!(plan.requires_constraint_search_probe);
}

#[test]
fn web_pipeline_pre_read_multi_story_marks_probe_when_discovery_inventory_is_empty() {
    let query = "Tell me today's top news headlines.";
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some(query.to_string()),
        url: Some("https://www.bing.com/search?q=today+top+news+headlines".to_string()),
        sources: vec![],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(query, 3, &bundle);
    assert_eq!(plan.total_candidates, 0, "plan={:?}", plan);
    assert!(
        plan.requires_constraint_search_probe,
        "time-sensitive multi-story queries should request a typed probe when discovery inventory is empty: {:?}",
        plan
    );
}

#[test]
fn web_pipeline_pre_read_multi_story_prefers_article_urls_over_listing_pages() {
    let query = "Tell me today's top news headlines.";
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some(query.to_string()),
        url: Some("https://www.bing.com/search?q=today+top+news+headlines".to_string()),
        sources: vec![
            WebSource {
                source_id: "abc-home".to_string(),
                rank: Some(1),
                url: "https://abcnews.com/".to_string(),
                title: Some("ABC News".to_string()),
                snippet: Some("Breaking news and top stories.".to_string()),
                domain: Some("abcnews.com".to_string()),
            },
            WebSource {
                source_id: "abc-article".to_string(),
                rank: Some(2),
                url: "https://abcnews.com/us/story-one".to_string(),
                title: Some("Federal agency announces emergency review".to_string()),
                snippet: Some("Officials announced an emergency review Wednesday.".to_string()),
                domain: Some("abcnews.com".to_string()),
            },
            WebSource {
                source_id: "reuters-home".to_string(),
                rank: Some(3),
                url: "https://www.reuters.com/world/".to_string(),
                title: Some("Reuters World".to_string()),
                snippet: Some("Top world news headlines and analysis.".to_string()),
                domain: Some("reuters.com".to_string()),
            },
            WebSource {
                source_id: "reuters-article".to_string(),
                rank: Some(4),
                url: "https://www.reuters.com/world/story-two/".to_string(),
                title: Some("Leaders agree to emergency aid package".to_string()),
                snippet: Some(
                    "Negotiators reached an emergency aid package overnight.".to_string(),
                ),
                domain: Some("reuters.com".to_string()),
            },
            WebSource {
                source_id: "cnn-home".to_string(),
                rank: Some(5),
                url: "https://www.cnn.com/us".to_string(),
                title: Some("CNN U.S.".to_string()),
                snippet: Some("Latest headlines from across the U.S.".to_string()),
                domain: Some("cnn.com".to_string()),
            },
            WebSource {
                source_id: "cnn-article".to_string(),
                rank: Some(6),
                url: "https://www.cnn.com/2026/02/25/politics/story-three/index.html".to_string(),
                title: Some("Senate advances bipartisan budget framework".to_string()),
                snippet: Some(
                    "The Senate advanced a bipartisan budget framework Tuesday evening."
                        .to_string(),
                ),
                domain: Some("cnn.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(query, 3, &bundle);
    assert!(
        plan.candidate_urls.len() >= 2,
        "expected at least two article candidates, got {:?}",
        plan.candidate_urls
    );
    assert!(plan.candidate_urls.iter().all(|url| !matches!(
        url.as_str(),
        "https://abcnews.com/" | "https://www.reuters.com/world/" | "https://www.cnn.com/us"
    )));
    assert!(plan
        .candidate_urls
        .iter()
        .any(|url| url == "https://abcnews.com/us/story-one"));
    assert!(plan
        .candidate_urls
        .iter()
        .any(|url| url == "https://www.reuters.com/world/story-two/"));
    assert!(
        plan.candidate_urls.iter().any(|url| {
            url == "https://www.cnn.com/2026/02/25/politics/story-three/index.html"
                || url == "https://abcnews.com/us/story-one"
                || url == "https://www.reuters.com/world/story-two/"
        }),
        "expected at least one non-listing article candidate in the plan"
    );
}

#[test]
fn summary_contains_topic_and_refinement_hint() {
    let summary = summarize_search_results(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
        "<html><body><a href=\"https://example.com/a\">A</a>\nThe Internet of Intelligence explores decentralized agent coordination.\nOpen protocols enable verifiable execution and policy enforcement.</body></html>",
    );
    assert!(summary.contains("Search summary for 'internet of intelligence'"));
    assert!(summary.contains("Source URL: https://duckduckgo.com/?q=internet+of+intelligence"));
    assert!(summary.contains("Next refinement:"));
}

#[test]
fn fallback_summary_is_deterministic() {
    let msg = fallback_search_summary(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
    );
    assert_eq!(
        msg,
        "Searched 'internet of intelligence' at https://duckduckgo.com/?q=internet+of+intelligence, but structured extraction failed. Retry refinement if needed."
    );
}
