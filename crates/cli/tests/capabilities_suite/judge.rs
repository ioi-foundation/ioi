use anyhow::{anyhow, Result};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use super::types::{LocalJudgeResult, QueryCase, RunObservation};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArbiterVerdict {
    pub pass: bool,
    pub confidence: String,
    pub rationale: String,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub failures: Vec<String>,
}

pub async fn run_arbiter(
    runtime: Arc<dyn InferenceRuntime>,
    case: &QueryCase,
    observation: &RunObservation,
    local: &LocalJudgeResult,
) -> Result<ArbiterVerdict> {
    let contract_failure_marker = observation_has_contract_failure_marker(observation);

    let final_reply_excerpt = observation
        .final_reply
        .chars()
        .take(1_800)
        .collect::<String>();

    let action_evidence = observation
        .action_evidence
        .iter()
        .take(8)
        .map(|entry| {
            json!({
                "tool_name": entry.tool_name,
                "agent_status": entry.agent_status,
                "output_excerpt": truncate_chars(&entry.output_excerpt, 180),
            })
        })
        .collect::<Vec<_>>();

    let event_excerpt = observation
        .event_excerpt
        .iter()
        .take(12)
        .map(|line| truncate_chars(line, 180))
        .collect::<Vec<_>>();

    let local_checks = local
        .checks
        .iter()
        .map(|check| {
            json!({
                "name": check.name,
                "passed": check.passed,
                "detail": truncate_chars(&check.detail, 180),
            })
        })
        .collect::<Vec<_>>();

    let payload = json!({
        "case_id": case.id,
        "query": case.query,
        "success_definition": case.success_definition,
        "run_timestamp_ms": observation.run_timestamp_ms,
        "run_timestamp_iso_utc": observation.run_timestamp_iso_utc,
        "completion": {
            "completed": observation.completed,
            "failed": observation.failed,
            "final_status": observation.final_status,
            "paused_retry_blocked_unexpected_state": is_retry_blocked_unexpected_state(observation),
            "elapsed_ms": observation.elapsed_ms,
            "chat_reply_count": observation.chat_reply_count,
        },
        "signals": {
            "action_tools": observation.action_tools,
            "routing_tools": observation.routing_tools,
            "workload_tools": observation.workload_tools,
            "verification_checks": observation.verification_checks,
            "approval_required_events": observation.approval_required_events,
            "contract_failure_marker": contract_failure_marker,
            "action_evidence": action_evidence,
            "event_excerpt": event_excerpt,
        },
        "local_judge": {
            "pass": local.pass,
            "score": local.score,
            "checks": local_checks,
            "failures": local.failures,
        },
        "final_reply_excerpt": final_reply_excerpt,
        "final_reply_char_len": observation.final_reply.chars().count(),
        "screenshot_signals": if case.id == "take_a_screenshot_of_my_desktop" {
            let approval_gate_seen = observation.approval_required_events > 0
                || observation
                    .verification_checks
                    .iter()
                    .any(|check| check.eq_ignore_ascii_case("policy_decision=require_approval"));
            let policy_decision_allow = observation
                .verification_checks
                .iter()
                .any(|check| {
                    check.eq_ignore_ascii_case("policy_decision=approved")
                        || check.eq_ignore_ascii_case("policy_decision=allowed")
                });
            json!({
                "capture_action_count": capture_action_count(observation),
                "computer_screenshot_success_count": computer_screenshot_success_count(observation),
                "gui_snapshot_count": gui_snapshot_count(observation),
                "computer_action_seen": has_tool_token(&observation.action_tools, "computer"),
                "capture_route_seen": has_tool_token(&observation.routing_tools, "computer"),
                "policy_decision_allow": policy_decision_allow,
                "approval_gate_seen": approval_gate_seen,
                "approval_transition_seen": approval_gate_seen && policy_decision_allow,
                "no_gui_snapshot_fallback": gui_snapshot_count(observation) == 0
                    && !has_tool_token(&observation.routing_tools, "gui__snapshot"),
                "contract_failure_marker": contract_failure_marker,
            })
        } else {
            serde_json::Value::Null
        },
        "top_news_signals": if case.id == "top_news_headlines" {
            let citation_urls = extract_citation_urls(&observation.final_reply);
            json!({
                "wrapper_url_count": citation_urls
                    .iter()
                    .filter(|url| is_news_feed_wrapper_url(url))
                    .count(),
                "citation_url_count": citation_urls.len(),
                "contains_constrained_fallback_inventory": observation
                    .final_reply
                    .to_ascii_lowercase()
                    .contains("fallback citation inventory from constrained source set"),
                "contains_challenge_markers": contains_challenge_marker(
                    &observation.final_reply.to_ascii_lowercase()
                ),
                "story_titles": extract_story_titles(&observation.final_reply),
                "shared_story_anchor_tokens": shared_story_anchor_tokens(&extract_story_titles(&observation.final_reply)),
            })
        } else {
            serde_json::Value::Null
        },
    });

    let prompt = format!(
        "You are a non-deterministic arbiter for live desktop capability tests.\n\
Return JSON only with exact schema:\n\
{{\"pass\":bool,\"confidence\":\"high|medium|low\",\"score\":number,\"rationale\":string,\"failures\":[string]}}\n\
Rules:\n\
1) Judge whether the query objective was successfully completed in this run.\n\
2) `completion.completed=false` should generally be pass=false, unless there is strong local runtime evidence and `completion.paused_retry_blocked_unexpected_state=true` with no contract failure markers.\n\
3) Empty `final_reply_excerpt` can still pass when action/tool evidence clearly contains the successful outcome (for example math/system/app actions).\n\
4) Treat local_judge checks as strong runtime evidence, but you may override only with clear contrary evidence.\n\
5) `score` must be in [0,1].\n\
6) If pass=true then failures must be [].\n\
7) For `case_id=top_news_headlines`, if `local_judge.failures` is non-empty then pass MUST be false.\n\
8) For `case_id=top_news_headlines`, wrapper-only constrained fallback inventory, repeated shared story anchor tokens, or challenge/captcha/access-denied story evidence MUST be judged as failure.\n\
9) For `case_id=top_news_headlines`, if `local_judge.pass=true` and there is no explicit multi-story floor failure marker, pass MUST be true.\n\
10) For `case_id=take_a_screenshot_of_my_desktop`, approval-gate evidence is mandatory before capture success: `screenshot_signals.approval_transition_seen=true`, plus capture action evidence `screenshot_signals.capture_action_count >= 1`, `screenshot_signals.capture_route_seen=true`, and `screenshot_signals.no_gui_snapshot_fallback=true`.\n\
11) For `case_id=take_a_screenshot_of_my_desktop`, if `local_judge.failures` is non-empty then pass MUST be false.\n\
12) For `case_id=take_a_screenshot_of_my_desktop`, if `local_judge.pass=true` and `screenshot_signals.contract_failure_marker=false`, pass MUST be true.\n\
13) For non-strict cases (all except `top_news_headlines`), if `local_judge.pass=true`, `local_judge.failures=[]`, `completion.completed=true`, `completion.failed=false`, and `signals.contract_failure_marker=false`, pass SHOULD be true unless there is explicit contrary runtime evidence.\n\
Payload:\n{}",
        serde_json::to_string(&payload)?
    );

    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.4,
        json_mode: true,
        max_tokens: 500,
    };

    let mut raw: Option<Vec<u8>> = None;
    let mut last_err: Option<String> = None;
    for attempt in 1..=4usize {
        match runtime
            .execute_inference([0u8; 32], prompt.as_bytes(), options.clone())
            .await
        {
            Ok(bytes) => {
                raw = Some(bytes);
                break;
            }
            Err(err) => {
                let msg = err.to_string();
                let is_rate_limit = msg.contains("429")
                    || msg.to_ascii_lowercase().contains("rate limit")
                    || msg.to_ascii_lowercase().contains("rate_limit");
                last_err = Some(msg.clone());
                if is_rate_limit && attempt < 4 {
                    let backoff_secs = 8u64 * attempt as u64;
                    sleep(Duration::from_secs(backoff_secs)).await;
                    continue;
                }
                break;
            }
        }
    }
    let raw = raw.ok_or_else(|| {
        anyhow!(
            "arbiter inference failed: {}",
            last_err.unwrap_or_else(|| "unknown error".to_string())
        )
    })?;
    let text = String::from_utf8(raw).map_err(|_| anyhow!("arbiter response was not UTF-8"))?;
    let json_text = extract_json_object(&text)
        .ok_or_else(|| anyhow!("arbiter did not return JSON object: {}", text))?;

    let mut verdict: ArbiterVerdict = serde_json::from_str(json_text)
        .map_err(|e| anyhow!("failed to parse arbiter verdict: {} raw={}", e, text))?;

    if case.id == "top_news_headlines" {
        let reply_lower = observation.final_reply.to_ascii_lowercase();
        let explicit_floor_failure = reply_lower.contains(
            "synthesis unavailable: grounded evidence did not satisfy the multi-story floor",
        );
        if local.pass && local.failures.is_empty() && !explicit_floor_failure {
            verdict.pass = true;
            verdict.failures.clear();
            if verdict.score < 0.8 {
                verdict.score = 0.8;
            }
            if verdict.confidence == "low" {
                verdict.confidence = "medium".to_string();
            }
            if verdict.rationale.trim().is_empty() {
                verdict.rationale = "Top-news local verification satisfied structural and source-diversity requirements.".to_string();
            }
        }
    }

    if case.id == "take_a_screenshot_of_my_desktop" {
        let capture_observed = capture_action_count(observation) > 0;
        let approval_gate_seen = observation.approval_required_events > 0
            || observation
                .verification_checks
                .iter()
                .any(|check| check.eq_ignore_ascii_case("policy_decision=require_approval"));
        let policy_decision_allow = observation.verification_checks.iter().any(|check| {
            check.eq_ignore_ascii_case("policy_decision=approved")
                || check.eq_ignore_ascii_case("policy_decision=allowed")
        });
        let approval_transition_seen = approval_gate_seen && policy_decision_allow;
        let no_gui_snapshot_fallback = gui_snapshot_count(observation) == 0
            && !has_tool_token(&observation.routing_tools, "gui__snapshot");
        let capture_route_seen = has_tool_token(&observation.routing_tools, "computer");
        if local.pass
            && local.failures.is_empty()
            && approval_transition_seen
            && capture_observed
            && capture_route_seen
            && no_gui_snapshot_fallback
            && !contract_failure_marker
        {
            verdict.pass = true;
            verdict.failures.clear();
            if verdict.score < 0.8 {
                verdict.score = 0.8;
            }
            if verdict.confidence == "low" {
                verdict.confidence = "medium".to_string();
            }
            if verdict.rationale.trim().is_empty() {
                verdict.rationale =
                    "Screenshot local verification satisfied execution and contract requirements."
                        .to_string();
            }
        }
    }

    let completion_or_retry_blocked =
        observation.completed || (is_retry_blocked_unexpected_state(observation) && local.pass);

    if !is_strict_arbiter_case(case.id)
        && local.pass
        && local.failures.is_empty()
        && completion_or_retry_blocked
        && !observation.failed
        && !contract_failure_marker
    {
        verdict.pass = true;
        verdict.failures.clear();
        if verdict.score < 0.8 {
            verdict.score = 0.8;
        }
        if verdict.confidence == "low" {
            verdict.confidence = "medium".to_string();
        }
        if verdict.rationale.trim().is_empty() {
            verdict.rationale = "Local runtime verification satisfied completion criteria; no terminal contract failure markers observed."
                .to_string();
        }
    }

    if !matches!(verdict.confidence.as_str(), "high" | "medium" | "low") {
        return Err(anyhow!(
            "arbiter returned invalid confidence '{}'; expected high|medium|low",
            verdict.confidence
        ));
    }
    if !(0.0..=1.0).contains(&verdict.score) {
        return Err(anyhow!(
            "arbiter returned score outside 0..1: {}",
            verdict.score
        ));
    }
    if verdict.pass && !verdict.failures.is_empty() {
        return Err(anyhow!(
            "arbiter returned pass=true with non-empty failures: {:?}",
            verdict.failures
        ));
    }

    Ok(verdict)
}

fn is_retry_blocked_unexpected_state(observation: &RunObservation) -> bool {
    observation
        .final_status
        .to_ascii_lowercase()
        .contains("retry blocked: unchanged attemptkey for unexpectedstate")
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        compact
    } else {
        compact.chars().take(max_chars).collect::<String>() + "..."
    }
}

fn is_strict_arbiter_case(case_id: &str) -> bool {
    matches!(case_id, "top_news_headlines")
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

fn contains_challenge_marker(lower_reply: &str) -> bool {
    [
        "are you a robot",
        "access denied",
        "enable javascript",
        "enable js",
        "verify you are human",
        "recaptcha",
    ]
    .iter()
    .any(|needle| lower_reply.contains(needle))
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
            let title = if let Some((left, _)) = rest.split_once("What happened:") {
                left.trim()
            } else {
                rest.trim()
            };
            if title.is_empty() {
                None
            } else {
                Some(title.to_string())
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

fn has_tool_token(tools: &[String], token: &str) -> bool {
    tools
        .iter()
        .any(|tool| tool.to_ascii_lowercase().contains(token))
}

fn capture_action_count(observation: &RunObservation) -> usize {
    computer_screenshot_success_count(observation)
}

fn computer_screenshot_success_count(observation: &RunObservation) -> usize {
    observation
        .action_evidence
        .iter()
        .filter(|entry| {
            entry.tool_name.eq_ignore_ascii_case("computer")
                && entry.agent_status.eq_ignore_ascii_case("completed")
                && screenshot_success_output(&entry.output_excerpt)
        })
        .count()
}

fn gui_snapshot_count(observation: &RunObservation) -> usize {
    observation
        .action_evidence
        .iter()
        .filter(|entry| entry.tool_name.eq_ignore_ascii_case("gui__snapshot"))
        .count()
}

fn screenshot_success_output(output: &str) -> bool {
    let trimmed = output.trim();
    trimmed == "Screenshot captured"
        || trimmed.starts_with("Screenshot captured:")
        || trimmed.starts_with("Screenshot captured ")
}

fn observation_has_contract_failure_marker(observation: &RunObservation) -> bool {
    let mut corpus = Vec::<String>::new();
    corpus.push(observation.final_reply.clone());
    corpus.extend(observation.verification_checks.iter().cloned());
    corpus.extend(observation.event_excerpt.iter().cloned());
    corpus.extend(
        observation
            .action_evidence
            .iter()
            .map(|entry| format!("{} {}", entry.agent_status, entry.output_excerpt)),
    );
    corpus
        .iter()
        .any(|segment| has_contract_failure_marker(segment))
}

fn has_contract_failure_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "execution_contract_gate_blocked=true",
        "cec_terminal_error=true",
        "execution contract unmet",
        "base_error_class=executioncontractviolation",
        "error_class=executioncontractviolation",
        "error_class=discoverymissing",
        "error_class=synthesisfailed",
        "error_class=executionfailedterminal",
        "error_class=verificationmissing",
        "error_class=postconditionfailed",
        "failed_stage=",
        "missing_receipts=",
        "missing_postconditions=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}
