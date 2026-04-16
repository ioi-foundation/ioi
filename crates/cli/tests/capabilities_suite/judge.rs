use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::{agentic::InferenceOptions, FinalityTier};
use ioi_types::error::VmError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use super::types::{
    has_policy_decision, has_typed_contract_failure_evidence, observation_has_tool_name,
    LocalJudgeResult, QueryCase, RunObservation,
};

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

fn typed_action_evidence(action_evidence: &RunObservation) -> Vec<Value> {
    action_evidence
        .action_evidence
        .iter()
        .take(8)
        .map(|entry| {
            json!({
                "tool_name": entry.tool_name,
                "agent_status": entry.agent_status,
                "error_class": entry.error_class,
            })
        })
        .collect::<Vec<_>>()
}

fn local_check_payload(local: &LocalJudgeResult) -> Vec<Value> {
    local
        .checks
        .iter()
        .map(|check| {
            json!({
                "name": check.name,
                "passed": check.passed,
                "detail": truncate_chars(&check.detail, 180),
            })
        })
        .collect::<Vec<_>>()
}

fn screenshot_signals_payload(
    observation: &RunObservation,
    contract_failure_marker: bool,
) -> Value {
    let screenshot = observation.screenshot.as_ref();
    let approval_gate_seen = screenshot
        .map(|screenshot| screenshot.approval_gate_seen)
        .unwrap_or_else(|| {
            observation.approval_required_events > 0
                || has_policy_decision(observation, "require_approval")
        });
    let approval_transition_seen = screenshot
        .map(|screenshot| screenshot.approval_transition_seen)
        .unwrap_or_else(|| {
            let policy_decision_allow = has_policy_decision(observation, "approved")
                || has_policy_decision(observation, "allowed");
            approval_gate_seen && policy_decision_allow
        });
    let capture_route_seen = screenshot
        .map(|screenshot| screenshot.capture_route_seen)
        .unwrap_or_else(|| observation_has_tool_name(observation, "screen"));
    let capture_route_terminalized = screenshot
        .map(|screenshot| screenshot.capture_route_terminalized)
        .unwrap_or(false);
    let incident_resolved = screenshot
        .map(|screenshot| screenshot.incident_resolved)
        .unwrap_or(false);
    let capture_runtime_evidence = screenshot
        .map(|screenshot| screenshot.capture_action_count > 0)
        .unwrap_or(false)
        || (capture_route_terminalized
            && capture_route_seen
            && approval_transition_seen
            && incident_resolved);

    json!({
        "capture_action_count": screenshot
            .map(|screenshot| screenshot.capture_action_count)
            .unwrap_or(0),
        "gui_snapshot_count": screenshot
            .map(|screenshot| screenshot.gui_snapshot_action_count)
            .unwrap_or(0),
        "computer_action_seen": observation_has_tool_name(observation, "screen"),
        "capture_route_seen": capture_route_seen,
        "approval_gate_seen": approval_gate_seen,
        "approval_transition_seen": approval_transition_seen,
        "capture_route_terminalized": capture_route_terminalized,
        "incident_resolved": incident_resolved,
        "capture_runtime_evidence": capture_runtime_evidence,
        "no_gui_snapshot_fallback": screenshot
            .map(|screenshot| screenshot.no_gui_snapshot_fallback)
            .unwrap_or(false),
        "contract_failure_marker": contract_failure_marker,
    })
}

fn truncate_string_vec(values: &[String], max_items: usize, max_chars: usize) -> Vec<String> {
    values
        .iter()
        .take(max_items)
        .map(|value| truncate_chars(value, max_chars))
        .collect::<Vec<_>>()
}

fn web_observation_payload(observation: &RunObservation) -> Value {
    let Some(web) = observation.web.as_ref() else {
        return Value::Null;
    };

    json!({
        "query_contract": web
            .query_contract
            .as_deref()
            .map(|value| truncate_chars(value, 220)),
        "currentness_required": web.currentness_required,
        "semantic_subject_alignment_required": web.semantic_subject_alignment_required,
        "semantic_subject_alignment_floor_met": web.semantic_subject_alignment_floor_met,
        "selected_source_quality_floor_met": web.selected_source_quality_floor_met,
        "selected_source_subject_alignment_floor_met": web.selected_source_subject_alignment_floor_met,
        "selected_source_count": web.selected_source_count,
        "selected_source_distinct_domains": web.selected_source_distinct_domains,
        "selected_source_urls": truncate_string_vec(&web.selected_source_urls, 8, 180),
        "local_business_entity_anchor_floor_met": web.local_business_entity_anchor_floor_met,
        "local_business_entity_anchor_source_urls": truncate_string_vec(
            &web.local_business_entity_anchor_source_urls,
            8,
            180,
        ),
        "local_business_entity_anchor_mismatched_urls": truncate_string_vec(
            &web.local_business_entity_anchor_mismatched_urls,
            8,
            180,
        ),
        "semantic_subject_alignment_urls": truncate_string_vec(
            &web.semantic_subject_alignment_urls,
            8,
            180,
        ),
        "local_business_menu_inventory_floor_met": web.local_business_menu_inventory_floor_met,
        "local_business_menu_inventory_total_item_count": web.local_business_menu_inventory_total_item_count,
        "local_business_menu_inventory_source_urls": truncate_string_vec(
            &web.local_business_menu_inventory_source_urls,
            8,
            180,
        ),
        "story_slots_observed": web.story_slots_observed,
        "story_slot_floor_met": web.story_slot_floor_met,
        "story_citation_floor_met": web.story_citation_floor_met,
        "comparison_ready": web.comparison_ready,
        "provider_candidates": web
            .provider_candidates
            .iter()
            .take(8)
            .map(|candidate| {
                json!({
                    "provider_id": candidate.provider_id,
                    "source_count": candidate.source_count,
                    "selected": candidate.selected,
                    "success": candidate.success,
                    "execution_attempted": candidate.execution_attempted,
                    "execution_satisfied": candidate.execution_satisfied,
                    "execution_failure_reason": candidate.execution_failure_reason,
                    "challenge_reason": candidate.challenge_reason,
                    "request_url": candidate
                        .request_url
                        .as_deref()
                        .map(|value| truncate_chars(value, 180)),
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn nist_receipt_allowed(stage: &str, key: &str) -> bool {
    matches!(
        (stage, key),
        ("execution", "query_contract")
            | ("execution", "retrieval_contract")
            | ("execution", "currentness_required")
            | ("provider_selection", "provider_selected")
            | ("discovery", "semantic_subject_alignment_required")
            | ("discovery", "semantic_subject_alignment_floor")
            | ("verification", "source_floor")
            | ("verification", "selected_source_quality_floor")
            | ("verification", "selected_source_identifier_coverage_floor")
            | ("verification", "final_output_contract_ready")
            | ("verification", "briefing_document_layout")
            | ("verification", "briefing_render_heading_floor")
            | (
                "verification",
                "briefing_rendered_required_section_label_floor"
            )
            | ("verification", "briefing_story_headers_absent")
            | ("verification", "briefing_comparison_absent")
            | ("verification", "briefing_required_section_floor")
            | ("verification", "briefing_query_grounding_floor")
            | ("verification", "briefing_standard_identifier_floor")
            | (
                "verification",
                "briefing_authority_standard_identifier_floor"
            )
            | ("verification", "briefing_summary_inventory_floor")
            | ("verification", "briefing_narrative_aggregation_floor")
            | ("verification", "briefing_evidence_block_floor")
            | ("verification", "briefing_primary_authority_source_floor")
            | ("verification", "briefing_citation_read_backing_floor")
            | ("verification", "briefing_temporal_anchor_floor")
            | ("verification", "briefing_postamble_floor")
            | ("verification", "selected_source_url")
            | ("postcondition", "terminal_chat_reply_binding")
            | ("postcondition", "terminal_chat_reply_layout_profile")
            | ("postcondition", "terminal_chat_reply_story_headers_absent")
            | ("postcondition", "terminal_chat_reply_comparison_absent")
            | ("postcondition", "terminal_chat_reply_temporal_anchor_floor")
            | ("postcondition", "terminal_chat_reply_postamble_floor")
            | ("completion_gate", "contract_gate")
    )
}

fn top_news_receipt_allowed(stage: &str, key: &str) -> bool {
    matches!(
        (stage, key),
        ("provider_selection", "provider_selected")
            | ("verification", "source_floor")
            | ("verification", "selected_source_quality_floor")
            | ("verification", "story_slots_observed")
            | ("verification", "story_slot_floor")
            | ("verification", "story_citation_floor")
            | ("verification", "selected_source_url")
            | ("completion_gate", "contract_gate")
    )
}

fn receipt_identity(
    stage: &str,
    key: &str,
    provider_id: Option<&str>,
    observed_value: Option<&str>,
) -> String {
    let preserve_value = matches!(
        (stage, key),
        ("provider_selection", "provider_selected")
            | ("verification", "selected_source_url")
            | ("discovery", "provider_candidate")
    );
    format!(
        "{}::{}::{}::{}",
        stage,
        key,
        provider_id.unwrap_or_default(),
        if preserve_value {
            observed_value.unwrap_or_default()
        } else {
            ""
        }
    )
}

fn arbiter_cec_receipts_payload(case: &QueryCase, observation: &RunObservation) -> Vec<Value> {
    let max_receipts = match case.id {
        "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing" => 32,
        "find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus" => 28,
        "top_news_headlines" => 24,
        _ => 20,
    };
    let mut seen = BTreeSet::new();
    let mut kept = Vec::new();

    for receipt in observation.cec_receipts.iter().rev() {
        let stage = receipt.stage.as_str();
        let key = receipt.key.as_str();
        let allowed = match case.id {
            "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing" => {
                nist_receipt_allowed(stage, key)
            }
            "top_news_headlines" => top_news_receipt_allowed(stage, key),
            _ => true,
        };
        if !allowed {
            continue;
        }

        let identity = receipt_identity(
            stage,
            key,
            receipt.provider_id.as_deref(),
            receipt.observed_value.as_deref(),
        );
        if !seen.insert(identity) {
            continue;
        }

        kept.push(json!({
            "stage": stage,
            "key": key,
            "satisfied": receipt.satisfied,
            "timestamp_ms": receipt.timestamp_ms,
            "probe_source": receipt.probe_source,
            "observed_value": receipt
                .observed_value
                .as_deref()
                .map(|value| truncate_chars(value, 240)),
            "provider_id": receipt.provider_id,
        }));
        if kept.len() >= max_receipts {
            break;
        }
    }

    kept.reverse();
    kept
}

fn build_arbiter_payload(
    case: &QueryCase,
    observation: &RunObservation,
    local: &LocalJudgeResult,
    contract_failure_marker: bool,
) -> Value {
    json!({
        "case_id": case.id,
        "query": case.query,
        "success_definition": case.success_definition,
        "run_timestamp_ms": observation.run_timestamp_ms,
        "run_timestamp_iso_utc": observation.run_timestamp_iso_utc,
        "completion": {
            "completed": observation.completed,
            "failed": observation.failed,
            "final_status": observation.final_status,
            "final_artifact_char_count": observation.final_reply.chars().count(),
            "elapsed_ms": observation.elapsed_ms,
            "chat_reply_count": observation.chat_reply_count,
        },
        "signals": {
            "action_tools": observation.action_tools,
            "routing_tools": observation.routing_tools,
            "workload_tools": observation.workload_tools,
            "cec_receipts": arbiter_cec_receipts_payload(case, observation),
            "web_observation": web_observation_payload(observation),
            "screenshot_observation": observation.screenshot,
            "approval_required_events": observation.approval_required_events,
            "contract_failure_marker": contract_failure_marker,
            "kernel_event_count": observation.kernel_event_count,
            "command_history_count": observation.command_history_evidence.len(),
            "action_evidence": typed_action_evidence(observation),
        },
        "local_judge": {
            "pass": local.pass,
            "score": local.score,
            "checks": local_check_payload(local),
            "failures": local.failures,
        },
        "screenshot_signals": if case.id == "take_a_screenshot_of_my_desktop" {
            screenshot_signals_payload(observation, contract_failure_marker)
        } else {
            Value::Null
        },
    })
}

pub async fn run_arbiter(
    runtime: Arc<dyn InferenceRuntime>,
    case: &QueryCase,
    observation: &RunObservation,
    local: &LocalJudgeResult,
) -> Result<ArbiterVerdict> {
    let contract_failure_marker = has_typed_contract_failure_evidence(observation);
    let payload = build_arbiter_payload(case, observation, local, contract_failure_marker);

    let prompt = format!(
        "You are a non-deterministic arbiter for live desktop capability tests.\n\
Return JSON only with exact schema:\n\
{{\"pass\":bool,\"confidence\":\"high|medium|low\",\"score\":number,\"rationale\":string,\"failures\":[string]}}\n\
Rules:\n\
1) Judge whether the query objective was successfully completed in this run.\n\
2) `completion.completed=false` MUST be pass=false.\n\
3) Treat local_judge checks as strong runtime evidence, and override only with clear contrary typed runtime evidence.\n\
4) `score` must be in [0,1].\n\
5) If pass=true then failures must be [].\n\
6) For `case_id=top_news_headlines`, if `local_judge.failures` is non-empty then pass MUST be false.\n\
7) For `case_id=take_a_screenshot_of_my_desktop`, approval-gate evidence is mandatory before capture success: `screenshot_signals.approval_transition_seen=true`, `screenshot_signals.capture_runtime_evidence=true`, `screenshot_signals.capture_route_seen=true`, and `screenshot_signals.no_gui_snapshot_fallback=true`.\n\
8) For `case_id=take_a_screenshot_of_my_desktop`, if `local_judge.failures` is non-empty then pass MUST be false.\n\
9) For `case_id=take_a_screenshot_of_my_desktop`, if `local_judge.pass=true` and `screenshot_signals.contract_failure_marker=false`, pass MUST be true.\n\
10) For `case_id=research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing`, if `local_judge.failures` is non-empty then pass MUST be false.\n\
11) For `case_id=research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing`, if `local_judge.pass=true`, `local_judge.failures=[]`, `completion.completed=true`, `completion.failed=false`, and `signals.contract_failure_marker=false`, pass MUST be true unless you can cite explicit contrary typed runtime evidence from `signals.cec_receipts`.\n\
12) For `case_id=research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing`, rely on typed verification receipts for document layout, section floors, query grounding, authority coverage, temporal anchoring, and postamble readiness. Do not infer verdict from freeform prose.\n\
13) For `case_id=find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus`, if `local_judge.failures` is non-empty then pass MUST be false.\n\
14) For `case_id=find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus`, if `local_judge.pass=true`, `local_judge.failures=[]`, `completion.completed=true`, `completion.failed=false`, and `signals.contract_failure_marker=false`, pass MUST be true unless you can cite explicit contrary typed runtime evidence from `signals.cec_receipts`.\n\
15) For `case_id=find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus`, rely on typed verification receipts for runtime locality, local-business entity anchoring, menu-surface selected sources, citation backing, and comparison readiness. Do not infer verdict from freeform prose.\n\
16) For non-strict cases (all except `top_news_headlines`, `research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing`, and `find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus`), if `local_judge.pass=true`, `local_judge.failures=[]`, `completion.completed=true`, `completion.failed=false`, and `signals.contract_failure_marker=false`, pass SHOULD be true unless there is explicit contrary runtime evidence.\n\
17) Treat the payload as typed runtime evidence. Do not infer pass/fail from freeform chat/debug excerpts.\n\
Payload:\n{}",
        serde_json::to_string(&payload)?
    );

    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.4,
        json_mode: true,
        max_tokens: 500,
        stop_sequences: vec![],
        required_finality_tier: FinalityTier::BaseFinal,
        sealed_finality_proof: None,
        canonical_collapse_object: None,
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
                last_err = Some(err.to_string());
                if attempt < 4 {
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
    });
    let raw = match raw {
        Ok(bytes) => bytes,
        Err(err) => {
            return Ok(fallback_arbiter_verdict(
                case,
                observation,
                local,
                contract_failure_marker,
                &err.to_string(),
            ))
        }
    };
    let text = match String::from_utf8(raw) {
        Ok(text) => text,
        Err(_) => {
            return Ok(fallback_arbiter_verdict(
                case,
                observation,
                local,
                contract_failure_marker,
                "arbiter response was not UTF-8",
            ))
        }
    };
    let mut verdict = match parse_arbiter_verdict(&text) {
        Ok(verdict) => verdict,
        Err(error) => fallback_arbiter_verdict(
            case,
            observation,
            local,
            contract_failure_marker,
            &format!("{} raw={}", error, truncate_chars(&text, 220)),
        ),
    };

    if case.id == "top_news_headlines" {
        let web = observation.web.as_ref();
        let story_floor_receipt_met = web
            .map(|web| {
                web.story_slot_floor_met.unwrap_or(false)
                    && web.story_citation_floor_met.unwrap_or(false)
                    && web.story_slots_observed.unwrap_or(0) >= 3
            })
            .unwrap_or(false);
        let source_floor_receipt_met = web
            .map(|web| {
                let min_sources = web.min_sources.unwrap_or(0);
                web.source_floor_met.unwrap_or(false)
                    && min_sources >= 3
                    && web.sources_success.unwrap_or(0) >= min_sources
                    && web.selected_source_quality_floor_met.unwrap_or(false)
            })
            .unwrap_or(false);
        let top_news_gate_failed = !story_floor_receipt_met || !source_floor_receipt_met;
        let local_failed = !local.pass || !local.failures.is_empty();
        if local_failed || top_news_gate_failed || contract_failure_marker {
            verdict.pass = false;
            let mut failures = Vec::new();
            failures.extend(local.failures.iter().cloned());
            if !story_floor_receipt_met {
                failures.push("web_headline_story_floor_met=false".to_string());
            }
            if !source_floor_receipt_met {
                failures.push("web_source_floor_met=false".to_string());
            }
            if contract_failure_marker {
                failures.push("contract_failure_marker=true".to_string());
            }
            failures.sort();
            failures.dedup();
            verdict.failures = failures;
            if verdict.score > 0.49 {
                verdict.score = 0.49;
            }
            if verdict.confidence == "high" {
                verdict.confidence = "medium".to_string();
            }
            verdict.rationale = "Top-news receipt gates were not satisfied.".to_string();
        } else {
            verdict.pass = true;
            verdict.failures.clear();
            if verdict.score < 0.8 {
                verdict.score = 0.8;
            }
            if verdict.confidence == "low" {
                verdict.confidence = "medium".to_string();
            }
            verdict.rationale =
                "Top-news local verification and receipt gates were satisfied.".to_string();
        }
    }

    if case.id == "take_a_screenshot_of_my_desktop" {
        let screenshot = observation.screenshot.as_ref();
        let capture_route_seen = screenshot
            .map(|screenshot| screenshot.capture_route_seen)
            .unwrap_or_else(|| observation_has_tool_name(observation, "screen"));
        let capture_route_terminalized = screenshot
            .map(|screenshot| screenshot.capture_route_terminalized)
            .unwrap_or(false);
        let approval_gate_seen = screenshot
            .map(|screenshot| screenshot.approval_gate_seen)
            .unwrap_or_else(|| {
                observation.approval_required_events > 0
                    || has_policy_decision(observation, "require_approval")
            });
        let approval_transition_seen = screenshot
            .map(|screenshot| screenshot.approval_transition_seen)
            .unwrap_or_else(|| {
                let policy_decision_allow = has_policy_decision(observation, "approved")
                    || has_policy_decision(observation, "allowed");
                approval_gate_seen && policy_decision_allow
            });
        let incident_resolved = screenshot
            .map(|screenshot| screenshot.incident_resolved)
            .unwrap_or(false);
        let capture_runtime_evidence = screenshot
            .map(|screenshot| screenshot.capture_action_count > 0)
            .unwrap_or(false)
            || (capture_route_terminalized
                && capture_route_seen
                && approval_transition_seen
                && incident_resolved);
        let no_gui_snapshot_fallback = screenshot
            .map(|screenshot| screenshot.no_gui_snapshot_fallback)
            .unwrap_or(false);
        if local.pass
            && local.failures.is_empty()
            && approval_transition_seen
            && capture_runtime_evidence
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
            verdict.rationale =
                "Screenshot local verification satisfied execution and contract requirements."
                    .to_string();
        }
    }

    if case.id
        == "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing"
    {
        if !local.pass || !local.failures.is_empty() || contract_failure_marker {
            verdict.pass = false;
            let mut failures = local.failures.clone();
            if contract_failure_marker {
                failures.push("contract_failure_marker=true".to_string());
            }
            failures.sort();
            failures.dedup();
            verdict.failures = failures;
            if verdict.score > 0.49 {
                verdict.score = 0.49;
            }
            if verdict.confidence == "high" {
                verdict.confidence = "medium".to_string();
            }
            verdict.rationale =
                "NIST briefing local verification or contract gates were not satisfied."
                    .to_string();
        } else if observation.completed && !observation.failed {
            verdict.pass = true;
            verdict.failures.clear();
            if verdict.score < 0.8 {
                verdict.score = 0.8;
            }
            if verdict.confidence == "low" {
                verdict.confidence = "medium".to_string();
            }
            verdict.rationale = "NIST briefing local verification satisfied typed receipt gates; no contrary contract evidence was observed.".to_string();
        }
    }

    if case.id == "find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus"
    {
        if !local.pass || !local.failures.is_empty() || contract_failure_marker {
            verdict.pass = false;
            let mut failures = local.failures.clone();
            if contract_failure_marker {
                failures.push("contract_failure_marker=true".to_string());
            }
            failures.sort();
            failures.dedup();
            verdict.failures = failures;
            if verdict.score > 0.49 {
                verdict.score = 0.49;
            }
            if verdict.confidence == "high" {
                verdict.confidence = "medium".to_string();
            }
            verdict.rationale =
                "Restaurant menu-comparison local verification or contract gates were not satisfied."
                    .to_string();
        } else if observation.completed && !observation.failed {
            verdict.pass = true;
            verdict.failures.clear();
            if verdict.score < 0.8 {
                verdict.score = 0.8;
            }
            if verdict.confidence == "low" {
                verdict.confidence = "medium".to_string();
            }
            verdict.rationale = "Restaurant menu-comparison local verification satisfied typed receipt gates; no contrary contract evidence was observed.".to_string();
        }
    }

    if !is_strict_arbiter_case(case.id)
        && local.pass
        && local.failures.is_empty()
        && observation.completed
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
        verdict.rationale = "Local runtime verification satisfied completion criteria; no terminal contract failure markers observed."
            .to_string();
    }

    if !matches!(verdict.confidence.as_str(), "high" | "medium" | "low") {
        verdict.confidence = "medium".to_string();
    }
    if !verdict.score.is_finite() || !(0.0..=1.0).contains(&verdict.score) {
        verdict.score = local.score.clamp(0.0, 1.0);
    }
    if verdict.pass && !verdict.failures.is_empty() {
        verdict.failures.clear();
    }
    if !observation.completed && verdict.pass {
        verdict.pass = false;
        if verdict.failures.is_empty() {
            verdict
                .failures
                .push("completion.completed=false".to_string());
        }
        if verdict.score > 0.49 {
            verdict.score = 0.49;
        }
        if verdict.confidence == "high" {
            verdict.confidence = "medium".to_string();
        }
        verdict.rationale =
            "Completion gate not satisfied: completion.completed=false.".to_string();
    }

    Ok(verdict)
}

fn parse_arbiter_verdict(raw: &str) -> Result<ArbiterVerdict> {
    if let Ok(verdict) = serde_json::from_str::<ArbiterVerdict>(raw) {
        return Ok(verdict);
    }
    let json_text =
        extract_json_object(raw).ok_or_else(|| anyhow!("arbiter did not return JSON object"))?;

    serde_json::from_str(json_text)
        .map_err(|error| anyhow!("failed to parse arbiter verdict: {}", error))
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
    matches!(
        case_id,
        "top_news_headlines"
            | "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing"
            | "find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus"
    )
}

fn fallback_arbiter_verdict(
    case: &QueryCase,
    observation: &RunObservation,
    local: &LocalJudgeResult,
    contract_failure_marker: bool,
    reason: &str,
) -> ArbiterVerdict {
    if is_strict_arbiter_case(case.id) {
        return ArbiterVerdict {
            pass: false,
            confidence: "medium".to_string(),
            rationale: format!(
                "Arbiter inference unavailable for strict case; runtime artifact review is mandatory. {}",
                truncate_chars(reason, 220)
            ),
            score: 0.0,
            failures: vec!["arbiter_inference_unavailable".to_string()],
        };
    }
    let pass = local.pass
        && local.failures.is_empty()
        && observation.completed
        && !observation.failed
        && !contract_failure_marker;
    let failures = if pass {
        Vec::new()
    } else if !local.failures.is_empty() {
        local.failures.clone()
    } else if !observation.completed {
        vec!["completion.completed=false".to_string()]
    } else if observation.failed {
        vec!["completion.failed=true".to_string()]
    } else if contract_failure_marker {
        vec!["contract_failure_marker=true".to_string()]
    } else {
        vec!["arbiter_inference_unavailable".to_string()]
    };

    ArbiterVerdict {
        pass,
        confidence: "medium".to_string(),
        rationale: format!(
            "Arbiter inference unavailable; using typed local runtime evidence only. {}",
            truncate_chars(reason, 220)
        ),
        score: local.score,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities_suite::types::{
        CecReceiptEvidence, ExecutionProfile, LocalCheck, ScreenshotObservation,
    };
    use ioi_types::app::agentic::IntentScopeProfile;
    use std::path::Path;

    #[derive(Clone)]
    struct StaticInferenceRuntime {
        output: Vec<u8>,
    }

    #[async_trait]
    impl InferenceRuntime for StaticInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(self.output.clone())
        }

        async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn test_case(id: &'static str) -> QueryCase {
        QueryCase {
            id,
            query: "query",
            success_definition: "success",
            seeded_intent_id: "seed",
            intent_scope: IntentScopeProfile::WebResearch,
            seed_resolved_intent: true,
            expected_pass: true,
            execution_profile: ExecutionProfile::Hermetic,
            sla_seconds: 60,
            max_steps: 8,
            min_local_score: 1.0,
            allow_retry_blocked_completion_with_local_evidence: false,
            allow_timeout_completion_with_local_evidence: false,
            local_sniff: |_| LocalJudgeResult::from_checks(Vec::new()),
        }
    }

    fn test_observation() -> RunObservation {
        RunObservation {
            case_id: "case".to_string(),
            query: "query".to_string(),
            run_timestamp_ms: 1,
            run_timestamp_iso_utc: "2026-03-07T00:00:00Z".to_string(),
            elapsed_ms: 2,
            completed: true,
            failed: false,
            final_status: "Completed(None)".to_string(),
            terminal_pause_reason: None,
            terminal_failure_reason: None,
            final_reply: "reply".to_string(),
            chat_reply_count: 1,
            action_tools: vec!["chat__reply".to_string()],
            planned_tool_calls: Vec::new(),
            routing_tools: vec!["screen".to_string()],
            workload_tools: vec!["screen".to_string()],
            routing_policy_decisions: vec!["approved".to_string()],
            routing_failure_classes: Vec::new(),
            routing_stop_condition_hits: 0,
            verification_checks: Vec::new(),
            verification_facts: Vec::new(),
            approval_required_events: 1,
            parent_playbook_receipts: Vec::new(),
            route_decisions: Vec::new(),
            tool_normalizations: Vec::new(),
            tool_recoveries: Vec::new(),
            action_evidence: Vec::new(),
            action_error_classes: Vec::new(),
            command_history_evidence: Vec::new(),
            cec_receipts: vec![CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "completion_gate".to_string(),
                key: "contract_gate".to_string(),
                satisfied: true,
                timestamp_ms: 1,
                probe_source: None,
                observed_value: None,
                evidence_type: None,
                provider_id: None,
            }],
            intent_resolution_evidence: Vec::new(),
            environment_receipts: Vec::new(),
            web: None,
            screenshot: Some(ScreenshotObservation {
                capture_action_count: 1,
                capture_failure_count: 0,
                gui_snapshot_action_count: 0,
                gui_snapshot_routing_count: 0,
                capture_route_seen: true,
                capture_route_terminalized: true,
                incident_resolved: true,
                approval_gate_seen: true,
                approval_transition_seen: true,
                no_gui_snapshot_fallback: true,
            }),
            mail: None,
            google: None,
            event_excerpt: vec!["debug line".to_string()],
            kernel_event_count: 3,
            kernel_log_lines: vec!["kernel log line".to_string()],
        }
    }

    #[test]
    fn arbiter_payload_omits_debug_excerpts() {
        let case = test_case("generic_case");
        let observation = test_observation();
        let local = LocalJudgeResult::from_checks(vec![LocalCheck::new("typed", true, "detail")]);

        let payload = build_arbiter_payload(&case, &observation, &local, false);

        let payload_text = serde_json::to_string(&payload).expect("payload should serialize");
        assert!(!payload_text.contains("output_excerpt"));
        assert!(!payload_text.contains("event_excerpt"));
        assert!(!payload_text.contains("kernel_log_excerpt"));
        assert!(!payload_text.contains("command_history_evidence"));
        assert!(!payload_text.contains("final_artifact_excerpt"));
    }

    #[test]
    fn arbiter_payload_bounds_receipts_and_web_url_lists() {
        let case = test_case(
            "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing",
        );
        let mut observation = test_observation();
        observation.cec_receipts = (0..64)
            .map(|idx| CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: if idx % 2 == 0 {
                    "selected_source_url".to_string()
                } else {
                    format!("irrelevant_{idx}")
                },
                satisfied: true,
                timestamp_ms: idx as u64,
                probe_source: Some("probe".to_string()),
                observed_value: Some(format!("https://example.com/{idx}")),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            })
            .collect();
        observation.web = Some(crate::capabilities_suite::types::WebObservation {
            selected_source_urls: (0..20)
                .map(|idx| format!("https://sources.example/{idx}"))
                .collect(),
            semantic_subject_alignment_urls: (0..20)
                .map(|idx| format!("https://semantic.example/{idx}"))
                .collect(),
            ..Default::default()
        });
        let local = LocalJudgeResult::from_checks(vec![LocalCheck::new("typed", true, "detail")]);

        let payload = build_arbiter_payload(&case, &observation, &local, false);
        let cec_receipts = payload
            .get("signals")
            .and_then(Value::as_object)
            .and_then(|signals| signals.get("cec_receipts"))
            .and_then(Value::as_array)
            .expect("cec_receipts should be an array");
        let web_observation = payload
            .get("signals")
            .and_then(Value::as_object)
            .and_then(|signals| signals.get("web_observation"))
            .and_then(Value::as_object)
            .expect("web_observation should be an object");
        let selected_source_urls = web_observation
            .get("selected_source_urls")
            .and_then(Value::as_array)
            .expect("selected_source_urls should be an array");

        assert!(cec_receipts.len() <= 32);
        assert!(selected_source_urls.len() <= 8);
        assert!(cec_receipts.iter().all(|receipt| {
            receipt
                .get("key")
                .and_then(Value::as_str)
                .is_some_and(|key| {
                    key == "selected_source_url"
                        || key == "contract_gate"
                        || key == "source_floor"
                        || key == "selected_source_quality_floor"
                        || key == "selected_source_identifier_coverage_floor"
                        || key == "final_output_contract_ready"
                        || key.starts_with("briefing_")
                })
        }));
    }

    #[test]
    fn strict_case_fallback_does_not_auto_pass() {
        let case = test_case(
            "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing",
        );
        let observation = test_observation();
        let local = LocalJudgeResult::from_checks(vec![LocalCheck::new("typed", true, "detail")]);

        let verdict = fallback_arbiter_verdict(&case, &observation, &local, false, "offline");

        assert!(!verdict.pass);
        assert_eq!(verdict.failures, vec!["arbiter_inference_unavailable"]);
    }

    #[test]
    fn screenshot_payload_is_derived_from_typed_observation() {
        let case = test_case("take_a_screenshot_of_my_desktop");
        let observation = test_observation();
        let local = LocalJudgeResult::from_checks(vec![LocalCheck::new("typed", true, "detail")]);

        let payload = build_arbiter_payload(&case, &observation, &local, false);
        let screenshot = payload
            .get("screenshot_signals")
            .and_then(Value::as_object)
            .expect("screenshot_signals should be an object");

        assert_eq!(
            screenshot
                .get("approval_transition_seen")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            screenshot
                .get("capture_runtime_evidence")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            screenshot
                .get("no_gui_snapshot_fallback")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[tokio::test]
    async fn malformed_arbiter_json_falls_back_to_strict_research_local_evidence() {
        let case = test_case(
            "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing",
        );
        let observation = test_observation();
        let local = LocalJudgeResult::from_checks(vec![LocalCheck::new("typed", true, "detail")]);
        let runtime: Arc<dyn InferenceRuntime> = Arc::new(StaticInferenceRuntime {
            output: br#"{
  "pass": true,
  "confidence": "high",
  "score": 0.92,
  "rationale": "looks good",
  "failures": ["truncated"
"#
            .to_vec(),
        });

        let verdict = run_arbiter(runtime, &case, &observation, &local)
            .await
            .expect("malformed arbiter output should not abort strict research case");

        assert!(verdict.pass);
        assert!(verdict.failures.is_empty());
        assert_eq!(verdict.confidence, "medium");
        assert!(verdict.rationale.contains("typed receipt gates"));
    }
}
