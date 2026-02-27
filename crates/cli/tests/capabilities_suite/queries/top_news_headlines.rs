use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "top_news_headlines",
        query: "Tell me today's top news headlines.",
        success_definition: "Return today's top headlines with article-level citation quality, not mostly homepage titles.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: true,
        expected_pass: true,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 0.80,
        allow_retry_blocked_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let lower_reply = obs.final_reply.to_ascii_lowercase();
    let citation_urls = extract_citation_urls(&obs.final_reply);
    let unique_citation_urls = citation_urls
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let domains = extract_domains(&citation_urls);
    let source_keys = extract_citation_source_keys(&obs.final_reply);
    let article_like_url_set = unique_citation_urls
        .iter()
        .filter(|url| is_article_like_url(url))
        .collect::<std::collections::BTreeSet<_>>();
    let article_like_urls = article_like_url_set.len();
    let article_like_domains = article_like_url_set
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let unique_article_domains = extract_domains(&article_like_domains)
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let unique_domains = domains
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let unique_source_keys = source_keys
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let wrapper_url_count = citation_urls
        .iter()
        .filter(|url| is_news_feed_wrapper_url(url))
        .count();
    let wrapper_only_urls = !citation_urls.is_empty() && wrapper_url_count == citation_urls.len();
    let has_explicit_floor_failure = lower_reply
        .contains("synthesis unavailable: grounded evidence did not satisfy the multi-story floor");
    let has_metadata_only_failure = lower_reply.contains("metadata-only");
    let has_insufficient_source_floor = lower_reply.contains("distinct_actionable_sources=1 of 3")
        || lower_reply.contains("distinct_actionable_sources=0 of 3");
    let has_constrained_fallback_inventory =
        lower_reply.contains("fallback citation inventory from constrained source set");
    let has_challenge_markers = contains_challenge_marker(&lower_reply)
        || citation_urls
            .iter()
            .any(|url| is_challenge_or_blocked_url(url));

    let has_three_story_markers = lower_reply.contains("story 1")
        && lower_reply.contains("story 2")
        && lower_reply.contains("story 3");
    let story_titles = extract_story_titles(&obs.final_reply);
    let story_citation_urls = extract_story_citation_urls(&obs.final_reply);
    let shared_story_topics = shared_story_anchor_tokens(&story_titles);
    let story_topic_diversity_present =
        !has_three_story_markers || (story_titles.len() >= 3 && shared_story_topics.is_empty());
    let story_titles_specific = !has_three_story_markers
        || (story_titles.len() >= 3
            && story_titles
                .iter()
                .take(3)
                .all(|title| story_title_has_specificity(title)));
    let story_citation_uniqueness_present =
        !has_three_story_markers || story_citation_uniqueness_present(&story_citation_urls);
    let readability_floor_satisfied = parse_verification_readability_floor(&lower_reply)
        .map(|(retrieved, required)| retrieved >= required)
        .unwrap_or(true);
    let has_article_level_citations = article_like_urls >= 3 && unique_article_domains >= 3;
    let overall_confidence_not_low = !lower_reply.contains("overall confidence: low")
        || (has_article_level_citations
            && unique_domains >= 3
            && !has_explicit_floor_failure
            && !has_insufficient_source_floor);
    let narrative_headline_density = infer_narrative_headline_density(&obs.final_reply);
    let has_narrative_multi_headline_shape = narrative_headline_density >= 3;
    let wrapper_share_bounded =
        citation_urls.is_empty() || wrapper_url_count.saturating_mul(2) <= citation_urls.len();

    let used_web_path = has_tool_with_token(&obs.routing_tools, "web__search")
        || has_tool_with_token(&obs.routing_tools, "web__read")
        || has_tool_with_token(&obs.workload_tools, "web__search")
        || has_tool_with_token(&obs.workload_tools, "web__read");

    let checks = vec![
        LocalCheck::new(
            "completed_with_reply",
            obs.completed && !obs.final_reply.trim().is_empty(),
            format!(
                "status={} reply_len={}",
                obs.final_status,
                obs.final_reply.chars().count()
            ),
        ),
        LocalCheck::new(
            "headline_structure_present",
            has_three_story_markers || has_narrative_multi_headline_shape,
            truncate_chars(&obs.final_reply, 180),
        ),
        LocalCheck::new(
            "at_least_three_urls_present",
            unique_citation_urls.len() >= 3,
            format!(
                "citation_url_count={} unique_citation_url_count={} sample={:?}",
                citation_urls.len(),
                unique_citation_urls.len(),
                unique_citation_urls.iter().take(4).collect::<Vec<_>>()
            ),
        ),
        LocalCheck::new(
            "article_level_citations_present",
            has_article_level_citations,
            format!(
                "article_like_urls={} unique_article_domains={} citation_urls={:?}",
                article_like_urls, unique_article_domains, citation_urls
            ),
        ),
        LocalCheck::new(
            "source_independence_present",
            unique_domains >= 3,
            format!(
                "unique_domains={} unique_source_keys={} domains={:?} source_keys={:?}",
                unique_domains, unique_source_keys, domains, source_keys
            ),
        ),
        LocalCheck::new(
            "wrapper_inventory_not_single_source",
            (!wrapper_only_urls || unique_source_keys >= 3)
                && !(wrapper_only_urls && has_constrained_fallback_inventory),
            format!(
                "wrapper_url_count={} url_count={} unique_source_keys={} constrained_fallback_inventory={}",
                wrapper_url_count,
                citation_urls.len(),
                unique_source_keys,
                has_constrained_fallback_inventory
            ),
        ),
        LocalCheck::new(
            "wrapper_share_bounded",
            wrapper_share_bounded,
            format!(
                "wrapper_url_count={} url_count={}",
                wrapper_url_count,
                citation_urls.len()
            ),
        ),
        LocalCheck::new(
            "no_access_or_challenge_markers",
            !has_challenge_markers,
            truncate_chars(&obs.final_reply, 220),
        ),
        LocalCheck::new(
            "story_topic_diversity_present",
            story_topic_diversity_present,
            format!(
                "story_titles={:?} shared_story_topics={:?}",
                story_titles, shared_story_topics
            ),
        ),
        LocalCheck::new(
            "story_titles_specific",
            story_titles_specific,
            format!("story_titles={:?}", story_titles),
        ),
        LocalCheck::new(
            "story_citation_uniqueness_present",
            story_citation_uniqueness_present,
            format!("story_citation_urls={:?}", story_citation_urls),
        ),
        LocalCheck::new(
            "verification_readability_floor_satisfied",
            readability_floor_satisfied,
            truncate_chars(&obs.final_reply, 220),
        ),
        LocalCheck::new(
            "overall_confidence_not_low",
            overall_confidence_not_low,
            truncate_chars(&obs.final_reply, 220),
        ),
        LocalCheck::new(
            "no_failure_fallback_markers",
            !has_explicit_floor_failure
                && !has_metadata_only_failure
                && !has_insufficient_source_floor
                && !(wrapper_only_urls && has_constrained_fallback_inventory),
            truncate_chars(&obs.final_reply, 220),
        ),
        LocalCheck::new(
            "web_path_seen",
            used_web_path,
            format!(
                "routing_tools={:?} workload_tools={:?}",
                obs.routing_tools, obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "recency_signal_present",
            contains_any(&lower_reply, &["today", "as of", "utc", "run timestamp"]),
            truncate_chars(&obs.final_reply, 120),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_article_like_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if is_news_feed_wrapper_url(&lower) {
        return false;
    }
    if is_challenge_or_blocked_url(&lower) {
        return false;
    }
    if is_listing_url(&lower) {
        return false;
    }
    if contains_any(
        &lower,
        &[
            "/category/",
            "/categories/",
            "/topic/",
            "/topics/",
            "/tag/",
            "/tags/",
            "/section/",
            "/sections/",
            "/author/",
            "/authors/",
            "/collection/",
            "/collections/",
            "/hub/",
            "/hubs/",
        ],
    ) {
        return false;
    }
    let stripped = lower
        .split_once("://")
        .map(|(_, value)| value)
        .unwrap_or(lower.as_str());
    let path = stripped
        .split_once('/')
        .map(|(_, value)| value)
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
        .trim_matches('/');
    if path.is_empty() {
        return false;
    }
    let segments = path
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }

    let has_year_segment = segments.iter().any(|segment| {
        segment.len() == 4
            && segment.starts_with("20")
            && segment.chars().all(|ch| ch.is_ascii_digit())
    });
    let has_slug_segment = segments.iter().any(|segment| {
        segment
            .split('-')
            .filter(|token| !token.trim().is_empty() && token.len() >= 3)
            .count()
            >= 3
    });
    let has_alphanumeric_id_segment = segments.iter().any(|segment| {
        segment.len() >= 10
            && segment.chars().any(|ch| ch.is_ascii_alphabetic())
            && segment.chars().any(|ch| ch.is_ascii_digit())
    });
    let terminal = segments.last().copied().unwrap_or_default();
    let terminal_slug_tokens = terminal
        .split('-')
        .filter(|token| !token.trim().is_empty() && token.len() >= 3)
        .count();
    let terminal_has_structure = terminal_slug_tokens >= 3
        || terminal.chars().filter(|ch| ch.is_ascii_digit()).count() >= 4
        || (terminal.len() >= 10
            && terminal.chars().any(|ch| ch.is_ascii_alphabetic())
            && terminal.chars().any(|ch| ch.is_ascii_digit()));
    let has_article_keyword_path = contains_any(
        &lower,
        &[
            "/article/",
            "/story/",
            "/live/",
            "/news/",
            "/world/",
            "/politics/",
            "/business/",
            "/us/",
        ],
    );

    (has_alphanumeric_id_segment
        || (has_year_segment && terminal_has_structure)
        || (has_article_keyword_path && terminal_has_structure && segments.len() >= 2)
        || (segments.len() >= 3 && has_slug_segment && terminal_has_structure))
        && !is_listing_url(&lower)
}

fn extract_domains(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|url| {
            let stripped = url
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let host = stripped.split('/').next()?.trim();
            if host.is_empty() {
                None
            } else {
                Some(host.trim_start_matches("www.").to_string())
            }
        })
        .collect::<Vec<_>>()
}

fn infer_narrative_headline_density(reply: &str) -> usize {
    reply
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("- ")
                || line.starts_with("* ")
                || starts_with_numbered_item(line)
                || line.ends_with(':')
        })
        .count()
}

fn extract_story_citation_urls(reply: &str) -> Vec<Vec<String>> {
    let mut stories: Vec<Vec<String>> = Vec::new();
    let mut current_story: Option<usize> = None;

    for line in reply.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("story ") {
            stories.push(Vec::new());
            current_story = Some(stories.len().saturating_sub(1));
            continue;
        }
        if lower.starts_with("additional source inventory:") {
            current_story = None;
            continue;
        }
        let Some(idx) = current_story else {
            continue;
        };
        if !trimmed.starts_with("- ") || !trimmed.contains(" | http") {
            continue;
        }
        if let Some(url) = trimmed
            .split(" | ")
            .find(|segment| segment.starts_with("http://") || segment.starts_with("https://"))
            .map(str::trim)
        {
            stories[idx].push(url.to_string());
        }
    }

    stories
}

fn is_news_feed_wrapper_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("https://news.google.com/rss/articles/")
        || lower.starts_with("https://news.google.com/rss/read/")
        || lower.starts_with("https://news.google.com/rss/topics/")
}

fn extract_citation_urls(reply: &str) -> Vec<String> {
    reply
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("- ") || !trimmed.contains(" | http") {
                return None;
            }
            trimmed
                .split(" | ")
                .find(|segment| segment.starts_with("http://") || segment.starts_with("https://"))
                .map(|value| value.trim().to_string())
        })
        .collect()
}

fn story_title_has_specificity(title: &str) -> bool {
    const GENERIC_TOKENS: &[&str] = &[
        "top",
        "news",
        "headline",
        "headlines",
        "latest",
        "breaking",
        "story",
        "stories",
        "update",
        "updates",
        "today",
        "live",
        "report",
        "reports",
        "listen",
        "watch",
        "now",
    ];
    let tokens = title
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if tokens.len() < 2 {
        return false;
    }
    let informative_tokens = tokens
        .iter()
        .filter(|token| token.len() >= 3 && !GENERIC_TOKENS.contains(&token.as_str()))
        .count();
    informative_tokens >= 2
}

fn story_citation_uniqueness_present(stories: &[Vec<String>]) -> bool {
    if stories.len() < 3 {
        return false;
    }
    let bounded = stories.iter().take(3).collect::<Vec<_>>();
    if bounded.iter().any(|urls| urls.is_empty()) {
        return false;
    }

    let mut counts = std::collections::HashMap::<String, usize>::new();
    for urls in &bounded {
        let unique = urls.iter().collect::<std::collections::BTreeSet<_>>();
        for url in unique {
            *counts.entry((*url).to_string()).or_default() += 1;
        }
    }

    let stories_with_unique_url = bounded
        .iter()
        .filter(|urls| {
            let unique = urls.iter().collect::<std::collections::BTreeSet<_>>();
            unique
                .iter()
                .any(|url| counts.get(&(*url).to_string()).copied().unwrap_or(0) == 1)
        })
        .count();

    stories_with_unique_url >= 2
}

fn parse_verification_readability_floor(lower_reply: &str) -> Option<(usize, usize)> {
    let marker = "verification receipt -> retrieved ";
    let (_, remainder) = lower_reply.split_once(marker)?;
    let (retrieved_part, remainder) = remainder.split_once(" of ")?;
    let (required_part, _) = remainder.split_once(" required distinct readable sources")?;
    let retrieved = retrieved_part
        .split_whitespace()
        .next()?
        .parse::<usize>()
        .ok()?;
    let required = required_part
        .split_whitespace()
        .next()?
        .parse::<usize>()
        .ok()?;
    Some((retrieved, required))
}

fn contains_challenge_marker(lower_reply: &str) -> bool {
    contains_any(
        lower_reply,
        &[
            "are you a robot",
            "access denied",
            "enable javascript",
            "enable js",
            "verify you are human",
            "recaptcha",
        ],
    )
}

fn is_challenge_or_blocked_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "errors.edgesuite.net",
            "/captcha",
            "are-you-a-robot",
            "challenge",
            "verify",
        ],
    )
}

fn is_listing_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    [
        "/latest",
        "/latest/",
        "/world",
        "/world/",
        "/news",
        "/news/",
        "/top-stories",
        "/top-stories/",
        "/latest-stories",
        "/latest-stories/",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn extract_citation_source_keys(reply: &str) -> Vec<String> {
    reply
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("- ") || !trimmed.contains(" | http") {
                return None;
            }
            let label = trimmed
                .strip_prefix("- ")
                .and_then(|value| value.split(" | ").next())
                .unwrap_or_default()
                .trim();
            if label.is_empty() {
                return None;
            }
            let outlet = if let Some((_, right)) = label.rsplit_once(" - ") {
                right.trim()
            } else {
                return None;
            };
            let normalized = outlet
                .to_ascii_lowercase()
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let token_count = normalized.split_whitespace().count();
            if normalized.is_empty() || token_count == 0 || token_count > 6 {
                None
            } else {
                Some(normalized)
            }
        })
        .collect()
}

fn extract_story_titles(reply: &str) -> Vec<String> {
    reply
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let lower = trimmed.to_ascii_lowercase();
            if !lower.starts_with("story ") {
                return None;
            }
            let (_, rest) = trimmed.split_once(':')?;
            let title_portion = if let Some((left, _)) = rest.split_once("What happened:") {
                left.trim()
            } else {
                rest.trim()
            };
            if title_portion.is_empty() {
                None
            } else {
                Some(title_portion.to_string())
            }
        })
        .collect()
}

fn shared_story_anchor_tokens(story_titles: &[String]) -> Vec<String> {
    const STORY_STOPWORDS: &[&str] = &[
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "what",
        "happened",
        "story",
        "stories",
        "today",
        "top",
        "news",
        "headline",
        "headlines",
        "breaking",
        "latest",
        "update",
        "updates",
        "report",
        "reports",
        "key",
        "evidence",
        "media",
        "coverage",
        "live",
        "us",
        "u",
        "s",
    ];
    let token_sets = story_titles
        .iter()
        .map(|title| {
            title
                .to_ascii_lowercase()
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
                .collect::<String>()
                .split_whitespace()
                .filter_map(|token| {
                    let normalized = token.trim();
                    if normalized.len() < 3 || STORY_STOPWORDS.contains(&normalized) {
                        return None;
                    }
                    Some(normalized.to_string())
                })
                .collect::<std::collections::BTreeSet<_>>()
        })
        .filter(|set| !set.is_empty())
        .collect::<Vec<_>>();
    if token_sets.len() < 3 {
        return Vec::new();
    }
    let mut iter = token_sets.into_iter();
    let mut shared = iter.next().unwrap_or_default();
    for set in iter {
        shared = shared
            .intersection(&set)
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if shared.is_empty() {
            break;
        }
    }
    shared.into_iter().collect()
}

fn starts_with_numbered_item(line: &str) -> bool {
    let mut digits = 0usize;
    for ch in line.chars() {
        if ch.is_ascii_digit() {
            digits += 1;
            continue;
        }
        return ch == '.' && digits > 0;
    }
    false
}
