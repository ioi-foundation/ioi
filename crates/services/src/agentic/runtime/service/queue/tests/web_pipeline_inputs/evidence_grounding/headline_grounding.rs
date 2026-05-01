#[test]
fn web_pipeline_headline_candidate_collection_reorders_payload_noise_behind_actionable_articles() {
    let selected_urls = vec![
        "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/".to_string(),
        "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026".to_string(),
        "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "FRIDAY NEWS IN A RUSH: Top headlines in today's NewsMinute video - Sentinel Colorado"
                    .to_string(),
            ),
            excerpt: "Top world headlines and daily roundup.".to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Top news headlines for Thursday, March 5, 2026".to_string()),
            excerpt: "Local roundup of the day's top headlines.".to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            excerpt:
                "Daily school assembly roundup with thought of the day and headline digest."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092"
                .to_string(),
            title: Some(
                "High School Teacher Reveals The 1 Classroom Rule She No Longer Enforces After 25 Years".to_string(),
            ),
            excerpt:
                "A Texas teacher says some classroom rules stop helping students after 25 years in the classroom."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                .to_string(),
            title: Some(
                "Today in Africa — Mar 6, 2026: WAFCON Postponed, Uganda Evacuates 43 Students From Iran".to_string(),
            ),
            excerpt:
                "Uganda evacuated 43 students from Iran while WAFCON was postponed, according to today's regional report."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://news.google.com/rss/articles/CBMiW0FVX3lxTFBGbTBYWUpMa3NqcF9PUUFFc1pyMGQybUpPTUNqMENMaFFJb3BONVJOS3RQNUZ6UGdHQUZvcXF0elE3MXhYbTlkeEhSTjZCX2xDeERYQkUwN3hySkk?oc=5".to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com".to_string(),
            ),
            excerpt:
                "Hospitals and supply routes were hit as conflict spread in Kordofan."
                    .to_string(),
        },
    ];

    let collected = collect_projection_candidate_urls_with_locality_hint(
        "Tell me today's top news headlines.",
        3,
        &selected_urls,
        &source_hints,
        6,
        3,
        &BTreeSet::new(),
        None,
    );

    assert!(
        collected
            .iter()
            .take(3)
            .any(|url| url.contains("today.com/parents/family/viral-teacher-tiktok-cursing-rule")),
        "expected actionable article candidate to outrank payload-selected roundup noise: {:?}",
        collected
    );
    assert!(
        collected
            .iter()
            .take(3)
            .any(|url| url.contains("okayafrica.com/today-in-africa-mar-6-2026")),
        "expected additional actionable article candidate to remain in the leading set: {:?}",
        collected
    );
    assert!(
        collected
            .iter()
            .take(3)
            .all(|url| !url.contains("school-assembly-news-headlines")),
        "expected low-priority roundup page to stay behind actionable articles: {:?}",
        collected
    );
}

#[test]
fn web_pipeline_headline_bundle_success_ignores_cross_domain_noise() {
    let requested_url =
        "https://www.cbsnews.com/news/us-israel-attack-iran-world-reaction-to-war-middle-east/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.google.com/search?q=today+top+news+headlines&tbm=nws".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "As the U.S. and Israel attack Iran, governments around the world stress risks of new war in the Middle East"
                    .to_string(),
            ),
            excerpt: "Updated on: March 1, 2026 / 7:19 AM EST / CBS News.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![
            WebSource {
                source_id: "source:cbs".to_string(),
                rank: None,
                url: requested_url.to_string(),
                title: Some("CBS News".to_string()),
                snippet: Some("CBS story snippet.".to_string()),
                domain: Some("cbsnews.com".to_string()),
            },
            WebSource {
                source_id: "source:noise".to_string(),
                rank: None,
                url: "https://www.today.com/popculture/awards/where-to-watch-naacp-image-awards-2026-rcna260446"
                    .to_string(),
                title: Some("Where to Watch the 2026 NAACP Image Awards".to_string()),
                snippet: Some("Unrelated entertainment story.".to_string()),
                domain: Some("today.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![
            WebDocument {
                source_id: "source:cbs".to_string(),
                url: requested_url.to_string(),
                title: Some("CBS News".to_string()),
                content_text: "Article content from CBS.".to_string(),
                content_hash: "hash-cbs".to_string(),
                quote_spans: vec![],
            },
            WebDocument {
                source_id: "source:noise".to_string(),
                url: "https://www.today.com/popculture/awards/where-to-watch-naacp-image-awards-2026-rcna260446"
                    .to_string(),
                title: Some("Noise story".to_string()),
                content_text: "Article content from unrelated domain.".to_string(),
                content_hash: "hash-noise".to_string(),
                quote_spans: vec![],
            },
        ],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(
        pending.successful_reads.len(),
        1,
        "headline ingestion should only record evidence bound to the requested read URL"
    );
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        !pending.successful_reads[0].url.contains("today.com"),
        "cross-domain bundle noise must not be recorded as a successful read"
    );
}

#[test]
fn web_pipeline_headline_bundle_success_records_resolved_google_news_article_url() {
    let requested_url = "https://news.google.com/rss/articles/CBMiW0FVX3lxTFBGbTBYWUpMa3NqcF9PUUFFc1pyMGQybUpPTUNqMENMaFFJb3BONVJOS3RQNUZ6UGdHQUZvcXF0elE3MXhYbTlkeEhSTjZCX2xDeERYQkUwN3hySkk?oc=5";
    let resolved_url = "https://allafrica.com/stories/202603060637.html";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com"
                    .to_string(),
            ),
            excerpt: "allAfrica.com".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(resolved_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:allafrica".to_string(),
            rank: None,
            url: resolved_url.to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com"
                    .to_string(),
            ),
            snippet: Some("Hospitals and supply routes in Kordofan were hit as fighting spread."
                .to_string()),
            domain: Some("allafrica.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:allafrica".to_string(),
            url: resolved_url.to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com"
                    .to_string(),
            ),
            content_text: "Hospitals and supply routes in Kordofan were hit as fighting spread."
                .to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, resolved_url);
}

#[test]
fn web_pipeline_headline_hint_recovery_records_resolved_article_url_after_blocked_read() {
    let requested_url = "https://news.google.com/rss/articles/CBMiW0FVX3lxTFBGbTBYWUpMa3NqcF9PUUFFc1pyMGQybUpPTUNqMENMaFFJb3BONVJOS3RQNUZ6UGdHQUZvcXF0elE3MXhYbTlkeEhSTjZCX2xDeERYQkUwN3hySkk?oc=5";
    let resolved_url = "https://www.reuters.com/world/example-top-story-2026-03-06/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Trump says no deal with Iran until 'unconditional surrender' - Reuters"
                    .to_string(),
            ),
            excerpt: format!(
                "Trump said there will be no deal with Iran until 'unconditional surrender' after overnight escalation. source_url={resolved_url}"
            ),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![requested_url.to_string()],
        successful_reads: vec![],
        min_sources: 3,
    };

    let recovered = append_pending_web_success_from_hint(&mut pending, requested_url);

    assert!(
        recovered,
        "expected actionable headline hint to recover blocked read"
    );
    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, resolved_url);
}

#[test]
fn web_pipeline_headline_bundle_success_rejects_low_priority_roundup_pages() {
    let requested_url =
        "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            excerpt: "Daily school assembly roundup with thought of the day and headline digest."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "roundup".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            snippet: Some(
                "Daily school assembly roundup with thought of the day and headline digest."
                    .to_string(),
            ),
            domain: Some("sundayguardianlive.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "roundup".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            content_text:
                "Daily school assembly roundup with thought of the day, top national and sports headlines."
                    .to_string(),
            content_hash: "hash-roundup".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "headline roundup pages should not be counted as successful article evidence"
    );
}
