use ioi_api::runtime_harness::{
    ArtifactRetrievalPlan, ArtifactSourceReference, StudioArtifactBrief,
};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use url::Url;

static ITEM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<item>\s*(.*?)\s*</item>").expect("valid rss item regex"));
static TITLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<title>(.*?)</title>").expect("valid rss title regex"));
static LINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<link>(.*?)</link>").expect("valid rss link regex"));
static DESCRIPTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<description>(.*?)</description>").expect("valid rss description regex")
});
static TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<[^>]+>").expect("valid html tag regex"));
#[cfg(test)]
static QUOTE_QUERY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"for "([^"]+)""#).expect("valid source reason query regex"));
static TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-z0-9]{3,}").expect("valid token regex"));

const QUERY_LIMIT: usize = 3;
const RESULT_LIMIT: usize = 6;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RetrievalPlanResponse {
    normalized_topic: String,
    #[serde(default)]
    queries: Vec<String>,
    #[serde(default)]
    desired_source_kinds: Vec<String>,
    #[serde(default)]
    avoid_source_kinds: Vec<String>,
    #[serde(default)]
    freshness_mode: Option<String>,
    reason: String,
}

fn decode_xml_entities(raw: &str) -> String {
    raw.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .trim()
        .to_string()
}

fn extract_tag(regex: &Regex, raw: &str) -> Option<String> {
    regex
        .captures(raw)
        .and_then(|captures| captures.get(1))
        .map(|value| decode_xml_entities(value.as_str()))
        .filter(|value| !value.trim().is_empty())
}

fn domain_for_url(raw: &str) -> Option<String> {
    Url::parse(raw)
        .ok()
        .and_then(|url| url.domain().map(|domain| domain.to_string()))
}

fn normalized_subject(brief: &StudioArtifactBrief) -> Option<String> {
    if !brief.subject_domain.trim().is_empty() {
        return Some(brief.subject_domain.trim().to_string());
    }

    let candidates = [
        brief.job_to_be_done.trim(),
        brief.artifact_thesis.trim(),
        brief.audience.trim(),
    ];
    candidates
        .into_iter()
        .find(|candidate| !candidate.is_empty())
        .map(ToOwned::to_owned)
}

fn explainer_search_subject(subject: &str) -> String {
    let trimmed = subject.trim();
    if let Some(prefix) = trimmed.strip_suffix(" computers") {
        let prefix = prefix.trim();
        if !prefix.is_empty() {
            return format!("{prefix} computing");
        }
    }
    trimmed.to_string()
}

fn build_queries(brief: &StudioArtifactBrief) -> Vec<String> {
    let mut queries = Vec::new();

    if let Some(subject) = normalized_subject(brief) {
        let search_subject = explainer_search_subject(&subject);
        queries.push(search_subject.clone());
        let concept_focus = brief
            .required_concepts
            .iter()
            .map(|concept| concept.trim())
            .filter(|concept| !concept.is_empty())
            .filter(|concept| !concept.eq_ignore_ascii_case(&search_subject))
            .take(2)
            .collect::<Vec<_>>();
        if !concept_focus.is_empty() {
            queries.push(format!("{search_subject} {}", concept_focus.join(" ")));
        }
    }

    queries.extend(
        brief
            .factual_anchors
            .iter()
            .chain(brief.reference_hints.iter())
            .map(|entry| entry.trim())
            .filter(|entry| !entry.is_empty())
            .map(ToOwned::to_owned),
    );

    let mut seen = HashSet::new();
    queries
        .into_iter()
        .filter(|query| seen.insert(query.to_ascii_lowercase()))
        .take(QUERY_LIMIT)
        .collect()
}

fn fallback_retrieval_plan(brief: &StudioArtifactBrief) -> Option<ArtifactRetrievalPlan> {
    let queries = build_queries(brief);
    if queries.is_empty() {
        return None;
    }
    let normalized_topic = normalized_subject(brief).unwrap_or_else(|| queries[0].clone());
    Some(ArtifactRetrievalPlan {
        normalized_topic,
        queries,
        desired_source_kinds: vec![
            "official".to_string(),
            "educational".to_string(),
            "reference".to_string(),
        ],
        avoid_source_kinds: vec!["finance".to_string(), "breaking_news".to_string()],
        freshness_mode: Some("evergreen".to_string()),
        reason: "Fallback retrieval plan derived from the artifact brief.".to_string(),
    })
}

async fn plan_retrieval_for_brief(
    runtime: Arc<dyn InferenceRuntime>,
    brief: &StudioArtifactBrief,
) -> Option<ArtifactRetrievalPlan> {
    let prompt = serde_json::json!({
        "system": "You plan web retrieval for a source-backed artifact. Return only JSON.",
        "task": "Create a tiny retrieval plan for an explainer or report artifact. Prefer canonical sources and avoid noisy news/finance results unless the brief explicitly asks for them.",
        "schema": {
            "normalizedTopic": "string",
            "queries": ["string"],
            "desiredSourceKinds": ["string"],
            "avoidSourceKinds": ["string"],
            "freshnessMode": "string|null",
            "reason": "string"
        },
        "rules": [
            "Return 2 to 4 search queries.",
            "Keep queries short and web-realistic.",
            "Prefer official, educational, standards, and reference source types for explainer prompts.",
            "Avoid topic-specific domain hardcoding.",
            "Do not include prose outside the JSON object."
        ],
        "brief": brief,
    });
    let input = serde_json::to_vec(&prompt).ok()?;
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.2,
                json_mode: true,
                max_tokens: 320,
                ..Default::default()
            },
        )
        .await
        .ok()?;
    let raw = String::from_utf8(output).ok()?;
    let response = serde_json::from_str::<RetrievalPlanResponse>(&raw).ok()?;
    let normalized_topic = response.normalized_topic.trim().to_string();
    if normalized_topic.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    let queries = response
        .queries
        .into_iter()
        .map(|query| query.trim().to_string())
        .filter(|query| !query.is_empty())
        .filter(|query| seen.insert(query.to_ascii_lowercase()))
        .take(4)
        .collect::<Vec<_>>();
    if queries.is_empty() {
        return None;
    }
    Some(ArtifactRetrievalPlan {
        normalized_topic,
        queries,
        desired_source_kinds: response.desired_source_kinds,
        avoid_source_kinds: response.avoid_source_kinds,
        freshness_mode: response.freshness_mode,
        reason: response.reason.trim().to_string(),
    })
}

fn extract_tokens(raw: &str) -> HashSet<String> {
    TOKEN_RE
        .find_iter(&raw.to_ascii_lowercase())
        .map(|token| token.as_str().to_string())
        .collect()
}

fn normalize_source_kind(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace('-', "_")
}

fn infer_authority_signals(domain: &str, title: &str, excerpt: Option<&str>) -> HashSet<String> {
    let lower_domain = domain.to_ascii_lowercase();
    let lower_title = title.to_ascii_lowercase();
    let lower_excerpt = excerpt.unwrap_or_default().to_ascii_lowercase();
    let combined = format!("{lower_title} {lower_excerpt}");
    let mut signals = HashSet::new();

    if lower_domain.ends_with(".gov")
        || lower_domain.contains(".gov.")
        || lower_domain.contains("nasa")
        || lower_domain.contains("nist")
        || lower_domain.contains("nih")
        || lower_domain.contains("noaa")
        || lower_domain.contains("energy.gov")
        || lower_domain.contains("anl.gov")
    {
        signals.insert("government".to_string());
    }
    if lower_domain.ends_with(".edu")
        || lower_domain.contains(".edu.")
        || combined.contains("university")
        || combined.contains("institute of technology")
        || combined.contains("laboratory")
    {
        signals.insert("academic".to_string());
    }
    if lower_domain.contains("iso.org")
        || lower_domain.contains("ieee.org")
        || lower_domain.contains("w3.org")
        || combined.contains("standards body")
        || combined.contains("specification")
    {
        signals.insert("standards_body".to_string());
    }
    if lower_domain.contains("museum")
        || lower_domain.contains("encyclopedia")
        || lower_domain.contains("britannica")
    {
        signals.insert("reference_institution".to_string());
    }
    if lower_domain.contains("wordpress")
        || lower_domain.contains("blog")
        || lower_domain.contains("substack")
        || combined.contains("sponsored")
        || combined.contains("advertisement")
    {
        signals.insert("blog_like".to_string());
    }

    signals
}

fn infer_source_kinds(domain: &str, title: &str, excerpt: Option<&str>) -> HashSet<String> {
    let lower_domain = domain.to_ascii_lowercase();
    let lower_title = title.to_ascii_lowercase();
    let lower_excerpt = excerpt.unwrap_or_default().to_ascii_lowercase();
    let combined = format!("{lower_title} {lower_excerpt}");
    let mut kinds = HashSet::new();

    if lower_domain.ends_with(".gov")
        || lower_domain.contains("nist")
        || lower_domain.contains("nih")
        || lower_domain.contains("nasa")
    {
        kinds.insert("official".to_string());
    }
    if lower_domain.ends_with(".edu") {
        kinds.insert("educational".to_string());
    }
    if lower_domain.contains("iso.org")
        || lower_domain.contains("ieee.org")
        || lower_domain.contains("w3.org")
        || combined.contains("standard")
        || combined.contains("specification")
    {
        kinds.insert("standards".to_string());
    }
    if lower_domain.contains("wikipedia.org")
        || combined.contains("encyclopedia")
        || combined.contains("reference")
    {
        kinds.insert("reference".to_string());
    }
    if combined.contains("guide")
        || combined.contains("tutorial")
        || combined.contains("explained")
        || combined.contains("beginner")
        || combined.contains("basics")
        || lower_title.starts_with("what is ")
    {
        kinds.insert("educational".to_string());
    }
    if lower_domain.contains("news")
        || combined.contains("breaking")
        || combined.contains("latest")
        || combined.contains("today")
        || combined.contains("opinion")
    {
        kinds.insert("news".to_string());
    }
    if lower_domain.contains("finance")
        || lower_domain.contains("invest")
        || lower_domain.contains("market")
        || combined.contains("stock")
        || combined.contains("shares")
        || combined.contains("earnings")
        || combined.contains("investor")
        || combined.contains("price target")
    {
        kinds.insert("finance".to_string());
    }
    if kinds.is_empty() {
        kinds.insert("general".to_string());
    }

    kinds
}

fn authority_score(authority_signals: &HashSet<String>) -> i32 {
    let mut score = 0;
    if authority_signals.contains("government") {
        score += 85;
    }
    if authority_signals.contains("academic") {
        score += 75;
    }
    if authority_signals.contains("standards_body") {
        score += 65;
    }
    if authority_signals.contains("reference_institution") {
        score += 35;
    }
    if authority_signals.contains("blog_like") {
        score -= 55;
    }
    score
}

fn source_kind_score(
    source_kinds: &HashSet<String>,
    desired_source_kinds: &HashSet<String>,
    avoid_source_kinds: &HashSet<String>,
) -> i32 {
    let mut score = 0;
    score += 80 * source_kinds.intersection(desired_source_kinds).count() as i32;
    score -= 120 * source_kinds.intersection(avoid_source_kinds).count() as i32;
    if source_kinds.contains("official") {
        score += 70;
    }
    if source_kinds.contains("educational") {
        score += 55;
    }
    if source_kinds.contains("standards") {
        score += 50;
    }
    if source_kinds.contains("reference") {
        score += 35;
    }
    if source_kinds.contains("news") {
        score -= 35;
    }
    if source_kinds.contains("finance") {
        score -= 45;
    }
    score
}

fn source_rank(
    title: &str,
    domain: &str,
    excerpt: Option<&str>,
    query_tokens: &HashSet<String>,
    desired_source_kinds: &HashSet<String>,
    avoid_source_kinds: &HashSet<String>,
) -> i32 {
    let lower_title = title.to_ascii_lowercase();
    let excerpt_tokens = excerpt.map(extract_tokens).unwrap_or_default();
    let title_tokens = extract_tokens(title);
    let authority_signals = infer_authority_signals(domain, title, excerpt);
    let source_kinds = infer_source_kinds(domain, title, excerpt);

    let mut score = authority_score(&authority_signals)
        + source_kind_score(&source_kinds, desired_source_kinds, avoid_source_kinds);
    if lower_title.contains("explained") || lower_title.starts_with("what is ") {
        score += 45;
    }
    if lower_title.contains("beginner") || lower_title.contains("basics") {
        score += 20;
    }

    score += 12 * title_tokens.intersection(query_tokens).count() as i32;
    score += 4 * excerpt_tokens.intersection(query_tokens).count() as i32;
    score
}

fn diversity_penalty(
    selected_sources: &[ArtifactSourceReference],
    candidate: &ArtifactSourceReference,
) -> i32 {
    let Some(candidate_domain) = candidate.domain.as_ref() else {
        return 0;
    };
    let same_domain_count = selected_sources
        .iter()
        .filter(|source| source.domain.as_ref() == Some(candidate_domain))
        .count() as i32;

    let candidate_kinds = infer_source_kinds(
        candidate_domain,
        &candidate.title,
        candidate.excerpt.as_deref(),
    );
    let same_kind_count = selected_sources
        .iter()
        .filter(|source| {
            let Some(domain) = source.domain.as_ref() else {
                return false;
            };
            infer_source_kinds(domain, &source.title, source.excerpt.as_deref()) == candidate_kinds
        })
        .count() as i32;

    60 * same_domain_count + 20 * same_kind_count
}

fn parse_bing_search_rss(
    xml: &str,
    query: &str,
    source_id_prefix: &str,
    desired_source_kinds: &HashSet<String>,
    avoid_source_kinds: &HashSet<String>,
) -> Vec<ArtifactSourceReference> {
    let query_tokens = extract_tokens(query);
    let mut out = ITEM_RE
        .captures_iter(xml)
        .take(RESULT_LIMIT * 3)
        .enumerate()
        .filter_map(|(index, captures)| {
            let item = captures.get(1)?.as_str();
            let title = extract_tag(&TITLE_RE, item)?;
            let url = extract_tag(&LINK_RE, item)?;
            let domain = domain_for_url(&url)?;
            let excerpt = extract_tag(&DESCRIPTION_RE, item)
                .map(|value| TAG_RE.replace_all(&value, " ").to_string())
                .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
                .filter(|value| !value.is_empty());
            let score = source_rank(
                &title,
                &domain,
                excerpt.as_deref(),
                &query_tokens,
                desired_source_kinds,
                avoid_source_kinds,
            );
            Some((
                score,
                ArtifactSourceReference {
                    source_id: format!("{source_id_prefix}:{index}"),
                    origin_prompt_event_id: String::new(),
                    title,
                    url: Some(url),
                    domain: Some(domain),
                    excerpt,
                    retrieved_at_ms: None,
                    freshness: Some("web_search".to_string()),
                    reason: format!("Retrieved from Bing web search for \"{query}\"."),
                },
            ))
        })
        .collect::<Vec<_>>();

    out.sort_by_key(|(score, source)| {
        let domain = source.domain.clone().unwrap_or_default();
        (Reverse(*score), domain, source.title.clone())
    });
    out.into_iter()
        .map(|(_, source)| source)
        .take(RESULT_LIMIT)
        .collect()
}

#[cfg(test)]
pub(super) fn source_query_from_reason(reason: &str) -> Option<String> {
    QUOTE_QUERY_RE
        .captures(reason)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) async fn retrieve_research_sources_for_brief(
    runtime: Arc<dyn InferenceRuntime>,
    brief: &StudioArtifactBrief,
) -> Vec<ArtifactSourceReference> {
    let retrieval_plan = plan_retrieval_for_brief(runtime, brief)
        .await
        .or_else(|| fallback_retrieval_plan(brief));
    let Some(retrieval_plan) = retrieval_plan else {
        return Vec::new();
    };
    let queries = retrieval_plan.queries;
    if queries.is_empty() {
        return Vec::new();
    }
    let desired_source_kinds = retrieval_plan
        .desired_source_kinds
        .iter()
        .map(|kind| normalize_source_kind(kind))
        .collect::<HashSet<_>>();
    let avoid_source_kinds = retrieval_plan
        .avoid_source_kinds
        .iter()
        .map(|kind| normalize_source_kind(kind))
        .collect::<HashSet<_>>();

    let client = match Client::builder()
        .timeout(Duration::from_secs(4))
        .user_agent("Mozilla/5.0 (compatible; ioi-studio/1.0)")
        .build()
    {
        Ok(client) => client,
        Err(_) => return Vec::new(),
    };

    let mut ranked_by_url = HashMap::<String, (i32, ArtifactSourceReference)>::new();
    for (query_index, query) in queries.iter().enumerate() {
        let response = match client
            .get("https://www.bing.com/search")
            .query(&[
                ("format", "rss"),
                ("q", query.as_str()),
                ("setlang", "en-US"),
            ])
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => continue,
        };
        let xml = match response.error_for_status() {
            Ok(response) => match response.text().await {
                Ok(text) => text,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        for source in parse_bing_search_rss(
            &xml,
            query,
            &format!("bing:{query_index}"),
            &desired_source_kinds,
            &avoid_source_kinds,
        ) {
            let Some(url) = source.url.as_ref() else {
                continue;
            };
            let domain = source.domain.clone().unwrap_or_default();
            let score = source_rank(
                &source.title,
                &domain,
                source.excerpt.as_deref(),
                &extract_tokens(query),
                &desired_source_kinds,
                &avoid_source_kinds,
            );
            match ranked_by_url.get(url) {
                Some((existing_score, _)) if *existing_score >= score => {}
                _ => {
                    ranked_by_url.insert(url.clone(), (score, source));
                }
            }
        }
    }

    let mut ranked_sources = ranked_by_url.into_values().collect::<Vec<_>>();
    ranked_sources.sort_by_key(|(score, source)| {
        (
            Reverse(*score),
            source.domain.clone().unwrap_or_default(),
            source.title.clone(),
        )
    });
    let mut selected = Vec::new();
    while selected.len() < RESULT_LIMIT && !ranked_sources.is_empty() {
        let Some((best_index, _, _, _)) = ranked_sources
            .iter()
            .enumerate()
            .map(|(index, (score, source))| {
                (
                    index,
                    score - diversity_penalty(&selected, source),
                    source.domain.clone().unwrap_or_default(),
                    source.title.clone(),
                )
            })
            .max_by_key(|(_, adjusted_score, domain, title)| {
                (
                    *adjusted_score,
                    Reverse(domain.clone()),
                    Reverse(title.clone()),
                )
            })
        else {
            break;
        };
        let (_, source) = ranked_sources.remove(best_index);
        selected.push(source);
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::{
        infer_authority_signals, infer_source_kinds, parse_bing_search_rss,
        source_query_from_reason,
    };
    use std::collections::HashSet;

    #[test]
    fn parses_bing_sources_into_real_source_refs() {
        let xml = r#"
        <rss><channel>
          <item>
            <title>Quantum computing - Wikipedia</title>
            <link>https://en.wikipedia.org/wiki/Quantum_computing</link>
            <description>A quantum computer is a computer that exploits quantum phenomena.</description>
          </item>
          <item>
            <title>What is quantum computing? - IBM</title>
            <link>https://www.ibm.com/think/topics/quantum-computing</link>
            <description>Quantum computing is an emergent field of computer science.</description>
          </item>
          <item>
            <title>Quantum Computing Explained | NIST</title>
            <link>https://www.nist.gov/quantum-information-science/quantum-computing-explained</link>
            <description>Scientists have explored how quantum computers could simulate quantum rules.</description>
          </item>
        </channel></rss>
        "#;
        let refs = parse_bing_search_rss(
            xml,
            "quantum computing explained",
            "bing:0",
            &HashSet::from([
                "official".to_string(),
                "educational".to_string(),
                "reference".to_string(),
            ]),
            &HashSet::from(["finance".to_string(), "breaking_news".to_string()]),
        );
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].domain.as_deref(), Some("www.nist.gov"));
        assert!(refs.iter().any(|source| source.title.contains("IBM")));
        assert!(refs[0].reason.contains("quantum computing explained"));
    }

    #[test]
    fn infers_generic_source_kinds_without_topic_allowlists() {
        let official = infer_source_kinds(
            "www.nist.gov",
            "Quantum Computing Explained | NIST",
            Some("Scientists have explored how quantum computers could simulate quantum rules."),
        );
        assert!(official.contains("official"));

        let educational = infer_source_kinds(
            "www.example.edu",
            "Quantum computing basics for beginners",
            Some("A tutorial guide to quantum computing."),
        );
        assert!(educational.contains("educational"));

        let finance = infer_source_kinds(
            "www.example.com",
            "Quantum computing stock price surges on investor optimism",
            Some("Market reaction and earnings outlook."),
        );
        assert!(finance.contains("finance"));
    }

    #[test]
    fn infers_generic_authority_signals_for_institutional_sources() {
        let government = infer_authority_signals(
            "science.nasa.gov",
            "What is Quantum Science? Quantum Leaps - NASA Science",
            Some("NASA overview of quantum science and missions."),
        );
        assert!(government.contains("government"));

        let academic = infer_authority_signals(
            "scienceexchange.caltech.edu",
            "What Is Quantum Physics? - Caltech Science Exchange",
            Some("Caltech explainer about quantum physics."),
        );
        assert!(academic.contains("academic"));

        let blog_like = infer_authority_signals(
            "example.substack.com",
            "A beginner guide to quantum",
            Some("Sponsored explainer for subscribers."),
        );
        assert!(blog_like.contains("blog_like"));
    }

    #[test]
    fn extracts_query_from_reason() {
        assert_eq!(
            source_query_from_reason(
                "Retrieved from Bing web search for \"quantum computing explained\"."
            ),
            Some("quantum computing explained".to_string())
        );
    }
}
