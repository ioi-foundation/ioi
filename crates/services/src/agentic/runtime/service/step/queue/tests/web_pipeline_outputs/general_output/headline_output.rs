#[test]
fn web_pipeline_headline_output_prefers_specific_articles_over_roundup_surfaces() {
    let successful_reads = vec![
        PendingSearchReadSummary {
            url: "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
            title: Some(
                "Morning Sprint: March 6 morning's top news and weather headlines - Channel 3000"
                    .to_string(),
            ),
            excerpt: "Morning roundup video covering the day's top news and weather headlines."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026".to_string(),
            title: Some(
                "Top News Headlines for Thursday, March 5, 2026 - WMAR 2 News Baltimore"
                    .to_string(),
            ),
            excerpt: "Baltimore roundup of the day's top headlines.".to_string(),
        },
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
                "Mar 6: WAFCON Postponed, Uganda Evacuates 43 Students From Iran".to_string(),
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
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: successful_reads
            .iter()
            .map(|source| source.url.clone())
            .collect(),
        candidate_source_hints: successful_reads.clone(),
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads,
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert!(
        !reply.contains("Synthesis unavailable"),
        "reply was: {}",
        reply
    );
    assert_eq!(
        extract_story_titles(&reply).len(),
        3,
        "reply was: {}",
        reply
    );
    let reply_lc = reply.to_ascii_lowercase();
    assert!(!reply_lc.contains("morning sprint"), "reply was: {}", reply);
    assert!(
        !reply_lc.contains("top news headlines for thursday"),
        "reply was: {}",
        reply
    );
    assert!(reply.contains("AP News"), "reply was: {}", reply);
    assert!(reply.contains("CNBC"), "reply was: {}", reply);
}

#[test]
fn web_pipeline_headline_reply_excludes_blocked_and_internal_probe_urls_from_citations() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.npr.org/sections/news/".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.npr.org/sections/news/".to_string(),
            title: Some("News : U.S. and World News Headlines : NPR".to_string()),
            excerpt: "Coverage of breaking stories, national and world news.".to_string(),
        }],
        attempted_urls: vec![
            "https://www.npr.org/sections/news/".to_string(),
            "ioi://quality-recovery/probe".to_string(),
        ],
        blocked_urls: vec!["https://www.npr.org/sections/news/".to_string()],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    assert!(reply.contains("Synthesis unavailable"));
    assert!(!reply.contains("What happened:"));
    assert!(!reply.contains("ioi://quality-recovery/probe"));
    assert!(!reply.contains(
        "News : U.S. and World News Headlines : NPR | https://www.npr.org/sections/news/"
    ));
    assert!(reply
        .contains("Blocked sources requiring human challenge: https://www.npr.org/sections/news/"));
}
