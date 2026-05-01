#[test]
fn web_pipeline_headline_completion_defers_when_only_roundup_pages_succeeded() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092"
                .to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
                ),
                excerpt:
                    "Daily school assembly roundup with thought of the day and headline digest."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://m.economictimes.com/news/new-updates/school-assembly-news-headlines-for-march-7-top-national-international-business-sports-update-and-thought-of-the-day/articleshow/129151758.cms".to_string(),
                title: Some(
                    "School Assembly News Headlines for March 7 Top National International Business Sports Update and Thought of the Day".to_string(),
                ),
                excerpt:
                    "School assembly roundup with top national and international updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://bestcolleges.indiatoday.in/news-detail/school-assembly-news-headlines-today-march-7-top-national-sports-and-world-news-curated-for-you-8335".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 7 Top National Sports and World News Curated for You".to_string(),
                ),
                excerpt: "Curated school assembly headlines and thought of the day.".to_string(),
            },
        ],
        min_sources: 3,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "headline completion should remain active when only low-priority roundup pages have succeeded; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_headline_completion_finishes_with_three_specific_articles_from_live_mix() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
            "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
            "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026".to_string(),
            "https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7".to_string(),
            "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384".to_string(),
            "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
            "https://www.wmar2news.com/local/top-news-headlines-for-friday-march-6".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
                title: Some(
                    "Morning Sprint: March 6 morning's top news and weather headlines - Channel 3000".to_string(),
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
            PendingSearchReadSummary {
                url: "https://www.wmar2news.com/local/top-news-headlines-for-friday-march-6".to_string(),
                title: Some("Top news headlines for Friday, March 6 - WMAR 2 News Baltimore".to_string()),
                excerpt: "Local roundup of Friday's top headlines.".to_string(),
            },
        ],
        min_sources: 3,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000)
        .expect("three specific article reads should satisfy the headline story floor");
    assert_eq!(reason, WebPipelineCompletionReason::MinSourcesReached);
}
