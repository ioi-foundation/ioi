#[test]
fn web_pipeline_constraint_grounded_probe_query_avoids_status_fallback_for_local_business_lookup() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        3,
        &[],
        Some("New York, NY"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &[],
        &grounded,
        Some("New York, NY"),
    );
    assert!(
        probe.is_none(),
        "without discovery-backed hint evidence the probe query should abstain instead of inventing new lexical fallback terms: {:?}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_excludes_noisy_hosts_for_local_business_lookup() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/Italian/".to_string(),
            title: Some("r/Italian".to_string()),
            excerpt: "Italian language and culture discussion community.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://news.google.com/rss/articles/CBMiakFVX3lxTE1paDlDQVMzckpVZjltZkhUM3RSdFh4MGtVOHFGNll6NlRKNUpqOV9UVDl4ZlBXZldpcUtMNm9JLWtZZ0dSMHlORTBRVlZTNC1mZ1dCemkzaWRCcmFMN2E5VVlZallSYjI5MVE?oc=5".to_string(),
            title: Some("Google News".to_string()),
            excerpt: "News feed entry for restaurant coverage.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        Some("New York, NY"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        &grounded,
        Some("New York, NY"),
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.reddit.com") || normalized.contains("-site:reddit.com"),
        "probe query should exclude noisy Reddit hosts: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_query_differs_for_local_business_lookup(
) {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.reddit.com/r/Italian/".to_string(),
        title: Some("r/Italian".to_string()),
        excerpt: "Italian language and culture discussion community.".to_string(),
    }];
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        "italian restaurants near me",
        Some("New York, NY"),
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.reddit.com") || normalized.contains("-site:reddit.com"),
        "probe query should preserve discovery-backed host exclusions even when prior query differs: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_excludes_noisy_price_hosts() {
    let query = "What's the current price of Bitcoin?";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://help.price.com/knowledge-base/about-price-com/".to_string(),
            title: Some("About Price.com - Help Center".to_string()),
            excerpt: "Learn about Price.com and how the help center works.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://price.com/about".to_string(),
            title: Some("About Price.com".to_string()),
            excerpt: "Company background and press information for Price.com.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 2, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 2, &hints, &grounded, None,
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.starts_with("current bitcoin price"),
        "probe should preserve the typed metric subject: {probe}"
    );
    assert!(
        normalized.contains("-site:price.com") || normalized.contains("-site:help.price.com"),
        "probe query should exclude noisy price.com hosts: {probe}"
    );
    assert!(
        !normalized.contains("about help center"),
        "probe query should not inherit provider-specific title noise: {probe}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_query_differs_for_price_lookup(
) {
    let query = "What's the current price of Bitcoin?";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.reddit.com/r/CryptoCurrency/comments/14zq3b4/why_is_the_bitcoin_price_falling_what_is_the/"
            .to_string(),
        title: Some("Why is the Bitcoin price falling?".to_string()),
        excerpt: "Current BTC price is $68,123, but this thread is community speculation about where it goes next."
            .to_string(),
    }];
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        "bitcoin price",
        None,
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.reddit.com") || normalized.contains("-site:reddit.com"),
        "probe query should preserve discovery-backed host exclusions even when prior query differs: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_equals_grounded() {
    let query = "what's the weather right now";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.weather-atlas.com/en/wyoming-usa/cheyenne".to_string(),
        title: Some("Weather today - Cheyenne, WY".to_string()),
        excerpt:
            "Current weather in Cheyenne, Wyoming: temperature 30 F, humidity 68%, wind 11 mph."
                .to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        Some("Anderson, SC"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        &grounded,
        Some("Anderson, SC"),
    )
    .expect("probe query should be generated");
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "probe should differ from prior grounded query"
    );
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("cheyenne") || normalized.contains("wyoming"),
        "expected locality-aware escalation terms in probe query: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_adds_metric_probe_terms_when_locality_query_stalls()
{
    let query = "what's the weather right now";
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        Some("New York"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        &grounded,
        Some("New York"),
    )
    .expect("probe query should be generated for stalled locality-sensitive query");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("temperature")
            && normalized.contains("humidity")
            && normalized.contains("wind"),
        "expected metric-oriented fallback probe terms: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "fallback probe query should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_stays_stable_for_headlines_when_grounded_query_matches(
) {
    let query = "Tell me today's top news headlines.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/"
                .to_string(),
            title: Some(
                "FRIDAY NEWS IN A RUSH: Top headlines in today's NewsMinute video - Sentinel Colorado"
                    .to_string(),
            ),
            excerpt: "Top world headlines and daily roundup.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026"
                .to_string(),
            title: Some("Top news headlines for Thursday, March 5, 2026".to_string()),
            excerpt: "Local roundup of the day's top headlines.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                .to_string(),
            title: Some(
                "Today in Africa — Mar 6, 2026: WAFCON Postponed, Uganda Evacuates 43 Students From Iran"
                    .to_string(),
            ),
            excerpt:
                "Uganda evacuated 43 students from Iran while WAFCON was postponed, according to today's regional report."
                    .to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 3, &hints, &grounded, None,
    );
    assert!(
        probe.is_none(),
        "headline probe query should not append lexical host exclusions when the grounded query is unchanged; got {:?}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_removes_site_exclusions_when_present_in_prior() {
    let query = "Tell me today's top news headlines.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.foxnews.com/us/example-headline".to_string(),
            title: Some("Top headlines from Fox News".to_string()),
            excerpt: "Breaking U.S. and world coverage from Fox.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://video.foxnews.com/v/123".to_string(),
            title: Some("Live coverage stream".to_string()),
            excerpt: "Video stream from Fox News.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let prior_probe = format!("{grounded} -site:www.foxnews.com -site:video.foxnews.com");
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        &prior_probe,
        None,
    )
    .expect("headline follow-up probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        !normalized.contains("-site:"),
        "headline probe query should not retain site exclusions: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&prior_probe),
        "follow-up probe should differ from previous probe query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_avoids_host_exclusion_terms_for_metric_gaps() {
    let query = "what's the weather right now in anderson, sc";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            title: Some("Anderson, South Carolina Weather Forecast".to_string()),
            excerpt: "Providing a local hourly Anderson (South Carolina) weather forecast."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677"
                .to_string(),
            title: Some("Anderson, SC Weather Forecast".to_string()),
            excerpt: "Anderson, SC Weather Forecast, with current conditions and next 3 days."
                .to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 2, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 2, &hints, &grounded, None,
    );
    if let Some(candidate) = probe {
        let normalized = candidate.to_ascii_lowercase();
        assert!(
            !normalized.contains("-site:"),
            "probe query should not contain host-exclusion operators: {}",
            candidate
        );
    }
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_avoids_host_exclusions_for_incident_queries() {
    let query = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with citations.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/MicrosoftTeams/comments/1crvhbg/accidentally_found_the_best_way_to_keep_active/".to_string(),
            title: Some("Accidentally found the best way to keep active status".to_string()),
            excerpt: "Discussion thread repeating active-status phrasing.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/WindowsHelp/comments/17qndbf/search_active_directory_in_windows_11/".to_string(),
            title: Some("Search Active Directory in Windows 11".to_string()),
            excerpt: "Another thread unrelated to provider status dashboards.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 3, &hints, &grounded, None,
    );
    if let Some(candidate) = probe {
        let normalized = candidate.to_ascii_lowercase();
        assert!(
            !normalized.contains("-site:"),
            "probe query should not contain host-exclusion operators: {}",
            candidate
        );
    }
}
