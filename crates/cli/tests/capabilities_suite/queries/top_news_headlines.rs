use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    contains_any, has_cec_receipt, has_contract_failure_evidence, has_tool_with_token,
    has_verification_check, max_verification_usize, truncate_chars, verification_values,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
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
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 0.80,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let lower_reply = obs.final_reply.to_ascii_lowercase();
    let citation_urls = extract_runtime_selected_urls(obs);
    let unique_citation_urls = citation_urls
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let domains = extract_domains(&citation_urls);
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
    let wrapper_url_count = citation_urls
        .iter()
        .filter(|url| is_news_feed_wrapper_url(url))
        .count();
    let wrapper_only_urls = !citation_urls.is_empty() && wrapper_url_count == citation_urls.len();

    let runtime_url_evidence_present = !citation_urls.is_empty();
    let has_three_story_markers = lower_reply.contains("story 1")
        && lower_reply.contains("story 2")
        && lower_reply.contains("story 3");
    let story_titles = extract_story_titles(&obs.final_reply);
    let structured_story_count = story_titles.len();
    let has_structured_multi_story_shape = structured_story_count >= 3;
    let has_structured_story_section =
        lower_reply.contains("story 1") && lower_reply.contains("citations:");
    let has_article_level_citations = article_like_urls >= 3 && unique_article_domains >= 3;
    let narrative_headline_density = infer_narrative_headline_density(&obs.final_reply);
    let has_narrative_multi_headline_shape = narrative_headline_density >= 3;
    let headline_structure_present = has_three_story_markers
        || has_structured_multi_story_shape
        || has_narrative_multi_headline_shape;
    let wrapper_share_bounded =
        citation_urls.is_empty() || wrapper_url_count.saturating_mul(2) <= citation_urls.len();
    let cec_contract_gate_satisfied =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let no_contract_failure_evidence = !has_contract_failure_evidence(obs);
    let observed_sources_success = max_verification_usize(obs, "web_sources_success").unwrap_or(0);
    let required_sources = max_verification_usize(obs, "web_min_sources").unwrap_or(0);
    let source_floor_receipt_met =
        required_sources == 0 || observed_sources_success >= required_sources;
    let required_story_floor =
        max_verification_usize(obs, "web_headline_story_floor_required").unwrap_or(3);
    let required_story_slots = required_story_floor.max(1);
    let story_citation_urls = extract_story_citation_urls(&obs.final_reply);
    let selected_url_keys = unique_citation_urls
        .iter()
        .filter_map(|url| normalize_story_url_key(url))
        .collect::<std::collections::BTreeSet<_>>();
    let aligned_story_slots = story_citation_urls
        .iter()
        .take(required_story_slots)
        .filter(|story_urls| {
            story_urls.iter().any(|url| {
                normalize_story_url_key(url)
                    .map(|key| selected_url_keys.contains(&key))
                    .unwrap_or(false)
            })
        })
        .count();
    let required_aligned_story_slots = required_story_slots.saturating_sub(1).max(1);
    let story_anchor_alignment_met = story_citation_urls.len() >= required_story_slots
        && selected_url_keys.len() >= required_story_slots
        && aligned_story_slots >= required_aligned_story_slots;
    let typed_story_floor_receipt_met =
        has_verification_check(obs, "web_headline_story_floor_met=true");
    let story_floor_shape_met = structured_story_count >= required_story_floor.max(1);
    let headline_selected_sources_total =
        max_verification_usize(obs, "web_headline_selected_sources_total").unwrap_or(0);
    let headline_selected_sources_low_priority =
        max_verification_usize(obs, "web_headline_selected_sources_low_priority").unwrap_or(0);
    let headline_selected_sources_distinct_domains =
        max_verification_usize(obs, "web_headline_selected_sources_distinct_domains").unwrap_or(0);
    let headline_quality_floor_receipt_met =
        has_verification_check(obs, "web_headline_selected_sources_quality_floor_met=true");
    let observed_blocked_sources = max_verification_usize(obs, "web_sources_blocked").unwrap_or(0);
    let has_terminal_challenge_surface = lower_reply
        .contains("blocked sources requiring human challenge")
        || contains_challenge_marker(&lower_reply)
        || citation_urls
            .iter()
            .any(|url| is_challenge_or_blocked_url(url));
    let challenge_blocked_objective = observed_blocked_sources > 0
        && (!source_floor_receipt_met || !typed_story_floor_receipt_met);
    let has_challenge_markers = has_terminal_challenge_surface || challenge_blocked_objective;

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
            headline_structure_present,
            truncate_chars(&obs.final_reply, 180),
        ),
        LocalCheck::new(
            "source_floor_receipt_met",
            source_floor_receipt_met,
            format!(
                "web_sources_success={} web_min_sources={} verification_checks={:?}",
                observed_sources_success, required_sources, obs.verification_checks
            ),
        ),
        LocalCheck::new(
            "headline_story_floor_receipt_met",
            typed_story_floor_receipt_met && story_floor_shape_met,
            format!(
                "web_headline_story_floor_met={} required_story_floor={} structured_story_count={} has_structured_story_section={}",
                typed_story_floor_receipt_met,
                required_story_floor,
                structured_story_count,
                has_structured_story_section
            ),
        ),
        LocalCheck::new(
            "story_citation_alignment_with_selected_urls",
            story_anchor_alignment_met,
            format!(
                "required_story_slots={} required_aligned_story_slots={} parsed_story_slots={} aligned_story_slots={} selected_url_count={} selected_urls={:?}",
                required_story_slots,
                required_aligned_story_slots,
                story_citation_urls.len(),
                aligned_story_slots,
                selected_url_keys.len(),
                unique_citation_urls.iter().take(6).collect::<Vec<_>>()
            ),
        ),
        LocalCheck::new(
            "headline_quality_floor_receipt_met",
            headline_quality_floor_receipt_met,
            format!(
                "quality_floor_receipt_met={} selected_sources_total={} low_priority_sources={} distinct_domains={} required_story_floor={}",
                headline_quality_floor_receipt_met,
                headline_selected_sources_total,
                headline_selected_sources_low_priority,
                headline_selected_sources_distinct_domains,
                required_story_floor
            ),
        ),
        LocalCheck::new(
            "runtime_url_evidence_present",
            runtime_url_evidence_present,
            format!(
                "runtime_selected_url_count={} values={:?}",
                unique_citation_urls.len(),
                unique_citation_urls.iter().take(6).collect::<Vec<_>>()
            ),
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
            format!("unique_domains={} domains={:?}", unique_domains, domains),
        ),
        LocalCheck::new(
            "wrapper_inventory_not_single_source",
            !wrapper_only_urls || unique_domains >= 3,
            format!(
                "wrapper_url_count={} url_count={} unique_domains={}",
                wrapper_url_count,
                citation_urls.len(),
                unique_domains
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
            format!(
                "blocked_sources={} terminal_challenge_surface={} source_floor_receipt_met={} story_floor_receipt_met={} excerpt={}",
                observed_blocked_sources,
                has_terminal_challenge_surface,
                source_floor_receipt_met,
                typed_story_floor_receipt_met,
                truncate_chars(&obs.final_reply, 160)
            ),
        ),
        LocalCheck::new(
            "cec_contract_gate_satisfied",
            cec_contract_gate_satisfied,
            format!("cec_receipts={:?}", obs.cec_receipts),
        ),
        LocalCheck::new(
            "no_contract_failure_evidence",
            no_contract_failure_evidence,
            format!(
                "action_error_classes={:?} routing_failure_classes={:?} verification_checks={:?}",
                obs.action_error_classes, obs.routing_failure_classes, obs.verification_checks
            ),
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
            contains_any(&lower_reply, &["today", "as of", "utc", "run timestamp"])
                || obs.query.to_ascii_lowercase().contains("today"),
            truncate_chars(&obs.final_reply, 120),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn extract_runtime_selected_urls(obs: &RunObservation) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for value in verification_values(obs, "web_pre_read_selected_url_values") {
        for token in value.split('|') {
            let trimmed = token.trim();
            if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
                continue;
            }
            let normalized_key = trimmed.to_ascii_lowercase();
            if seen.insert(normalized_key) {
                urls.push(trimmed.to_string());
            }
        }
    }
    urls
}

fn normalize_story_url_key(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return None;
    }
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let (host, remainder) = without_scheme
        .split_once('/')
        .map(|(left, right)| (left, right))
        .unwrap_or((without_scheme, ""));
    let host = host.trim().trim_start_matches("www.").to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let path = remainder
        .split('#')
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
        .trim_matches('/')
        .to_ascii_lowercase();
    if path.is_empty() {
        Some(host)
    } else {
        Some(format!("{host}/{path}"))
    }
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
        if lower.starts_with("story ") || starts_with_numbered_item(trimmed) {
            stories.push(Vec::new());
            current_story = Some(stories.len().saturating_sub(1));
            if let Some(idx) = current_story {
                for url in extract_urls_from_text(trimmed) {
                    stories[idx].push(url);
                }
            }
            continue;
        }
        if lower.starts_with("additional source inventory:") {
            current_story = None;
            continue;
        }
        let Some(idx) = current_story else {
            continue;
        };
        for url in extract_urls_from_text(trimmed) {
            stories[idx].push(url);
        }
    }

    if stories.iter().all(|urls| urls.is_empty()) {
        let indexed_urls = extract_indexed_citation_urls(reply);
        for (index, url) in indexed_urls.into_iter().enumerate() {
            if let Some(story_urls) = stories.get_mut(index) {
                story_urls.push(url);
            }
        }
    }

    stories
}

fn extract_urls_from_text(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut cursor = text;

    loop {
        let start = cursor.find("https://").or_else(|| cursor.find("http://"));
        let Some(start) = start else {
            break;
        };
        let remainder = &cursor[start..];
        let end = remainder
            .find(|ch: char| {
                ch.is_whitespace() || matches!(ch, ')' | '(' | ']' | '[' | '<' | '>' | '"' | '\'')
            })
            .unwrap_or(remainder.len());
        let candidate = remainder[..end]
            .trim_end_matches(|ch: char| ",.;:!?".contains(ch))
            .trim();
        if !candidate.is_empty() {
            urls.push(candidate.to_string());
        }
        if start + end >= cursor.len() {
            break;
        }
        cursor = &cursor[start + end..];
    }

    urls
}

fn extract_indexed_citation_urls(reply: &str) -> Vec<String> {
    let mut indexed = Vec::<(usize, String)>::new();
    for line in reply.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('[') {
            continue;
        }
        let Some(close_bracket) = trimmed.find(']') else {
            continue;
        };
        let index = trimmed[1..close_bracket].trim().parse::<usize>().ok();
        let Some(index) = index else {
            continue;
        };
        let url = extract_urls_from_text(&trimmed[close_bracket + 1..])
            .into_iter()
            .next();
        let Some(url) = url else {
            continue;
        };
        indexed.push((index, url));
    }
    indexed.sort_by_key(|(index, _)| *index);
    indexed.into_iter().map(|(_, url)| url).collect()
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
            if lower.starts_with("story ") {
                let (_, rest) = trimmed.split_once(':')?;
                let title_portion = if let Some((left, _)) = rest.split_once("What happened:") {
                    left.trim()
                } else {
                    rest.trim()
                };
                if title_portion.is_empty() {
                    return None;
                }
                return Some(title_portion.to_string());
            }
            if starts_with_numbered_item(trimmed) {
                let (_, rest) = trimmed.split_once('.')?;
                let content = rest.trim();
                if content.is_empty() {
                    return None;
                }
                let title = if let Some(title) = extract_bold_segment(content) {
                    title
                } else if let Some((left, _)) = content.split_once(" - ") {
                    left.trim().to_string()
                } else {
                    content.to_string()
                };
                if title.is_empty() {
                    None
                } else {
                    Some(title)
                }
            } else {
                None
            }
        })
        .collect()
}

fn extract_bold_segment(content: &str) -> Option<String> {
    let start = content.find("**")?;
    let remainder = &content[start + 2..];
    let end = remainder.find("**")?;
    let value = remainder[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
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
