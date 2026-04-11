pub(crate) mod harness;
mod judge;
#[path = "../live_inference_support.rs"]
mod live_inference_support;
pub(crate) mod queries;
pub(crate) mod types;

use anyhow::{anyhow, Result};
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use serde_json::json;
use std::sync::Arc;

use self::live_inference_support::{configured_model_candidates, select_http_inference_model};
use self::types::{is_retry_blocked_terminal, is_timeout_terminal, CaseOutcome, ExecutionProfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelLogDumpMode {
    Never,
    FailureOnly,
    Always,
}

fn kernel_log_dump_mode() -> KernelLogDumpMode {
    match std::env::var("CAPABILITIES_DUMP_KERNEL_LOGS")
        .unwrap_or_else(|_| "failure".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "never" | "0" | "false" => KernelLogDumpMode::Never,
        "always" | "all" | "1" | "true" => KernelLogDumpMode::Always,
        _ => KernelLogDumpMode::FailureOnly,
    }
}

fn should_emit_kernel_log_dump(
    mode: KernelLogDumpMode,
    observed_pass: bool,
    local_pass: bool,
    arbiter_pass: bool,
    completed: bool,
    failed: bool,
) -> bool {
    match mode {
        KernelLogDumpMode::Never => false,
        KernelLogDumpMode::Always => true,
        KernelLogDumpMode::FailureOnly => {
            !observed_pass || !local_pass || !arbiter_pass || !completed || failed
        }
    }
}

fn configured_execution_profile() -> Result<Option<ExecutionProfile>> {
    let raw = std::env::var("CAPABILITIES_PROFILE")
        .unwrap_or_else(|_| "all".to_string())
        .trim()
        .to_ascii_lowercase();
    match raw.as_str() {
        "all" | "*" => Ok(None),
        "hermetic" => Ok(Some(ExecutionProfile::Hermetic)),
        "policy_gate" | "policy-gate" | "policy" => Ok(Some(ExecutionProfile::PolicyGate)),
        "privileged" => Ok(Some(ExecutionProfile::Privileged)),
        other => Err(anyhow!(
            "invalid CAPABILITIES_PROFILE='{}'; expected hermetic|policy_gate|privileged|all",
            other
        )),
    }
}

fn is_human_intervention_blocker(observation: &types::RunObservation) -> bool {
    types::verification_bool(observation, "awaiting_sudo_password").unwrap_or(false)
        || observation.verification_facts.iter().any(|fact| {
            fact.key
                .eq_ignore_ascii_case("human_intervention_pause_reason")
        })
        || observation
            .terminal_pause_reason
            .as_ref()
            .map(|reason| reason.to_ascii_lowercase().contains("sudo password"))
            .unwrap_or(false)
}

pub async fn run_capabilities_suite() -> Result<()> {
    ioi_cli::testing::build_test_artifacts();
    harness::load_env_from_workspace_dotenv_if_present();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY is required for capabilities suite"))?;
    let api_url = std::env::var("OPENAI_API_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());
    let agent_model_candidates =
        configured_model_candidates("CAPABILITIES_E2E_AGENT_MODELS", "OPENAI_MODEL");
    let agent_model = select_http_inference_model(
        &api_url,
        &openai_api_key,
        &agent_model_candidates,
        "CAPABILITIES_INFERENCE_MODEL_SELECTED_AGENT",
    )
    .await?;
    let arbiter_model_candidates = configured_model_candidates(
        "CAPABILITIES_E2E_ARBITER_MODELS",
        "CAPABILITIES_E2E_ARBITER_MODEL",
    );
    let arbiter_model = if arbiter_model_candidates.is_empty() && !agent_model.trim().is_empty() {
        agent_model.clone()
    } else {
        select_http_inference_model(
            &api_url,
            &openai_api_key,
            if arbiter_model_candidates.is_empty() {
                std::slice::from_ref(&agent_model)
            } else {
                &arbiter_model_candidates
            },
            "CAPABILITIES_INFERENCE_MODEL_SELECTED_ARBITER",
        )
        .await?
    };

    let agent_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url.clone(),
        openai_api_key.clone(),
        agent_model,
    ));
    let arbiter_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        arbiter_model,
    ));

    let max_attempts = std::env::var("CAPABILITIES_MAX_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);

    let selected_profile = configured_execution_profile()?;
    let mut cases = queries::all_cases();
    if let Some(profile) = selected_profile {
        cases.retain(|case| case.execution_profile == profile);
    }
    let mut skipped_due_to_runtime_prereqs = Vec::new();
    cases.retain(|case| {
        let missing = harness::case_missing_runtime_prerequisites(case);
        if missing.is_empty() {
            return true;
        }
        skipped_due_to_runtime_prereqs.push((case.id.to_string(), missing));
        false
    });
    for (case_id, missing) in &skipped_due_to_runtime_prereqs {
        println!(
            "CAPABILITIES_CASE_SKIPPED_{}={}",
            case_id,
            missing.join(",")
        );
    }
    if cases.is_empty() {
        return Err(anyhow!(
            "no capabilities cases selected for CAPABILITIES_PROFILE={}",
            std::env::var("CAPABILITIES_PROFILE").unwrap_or_else(|_| "all".to_string())
        ));
    }

    let mut outcomes = Vec::new();
    let mut run_index = 0usize;
    let kernel_log_mode = kernel_log_dump_mode();
    for case in cases.into_iter() {
        let attempts_allowed = if case.expected_pass { max_attempts } else { 1 };
        let debug_observation = std::env::var("CAPABILITIES_DEBUG_OBSERVATION")
            .map(|value| value.eq_ignore_ascii_case("1") || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut selected_outcome: Option<CaseOutcome> = None;
        let mut last_outcome: Option<CaseOutcome> = None;

        for attempt in 1..=attempts_allowed {
            run_index = run_index.saturating_add(1);
            let observation = match harness::run_case(&case, run_index, agent_runtime.clone()).await
            {
                Ok(observation) => observation,
                Err(err) => {
                    println!(
                        "CAPABILITIES_CASE_ATTEMPT_ERROR_{}_{}={}",
                        case.id, attempt, err
                    );
                    if attempt == attempts_allowed {
                        return Err(err);
                    }
                    continue;
                }
            };

            if debug_observation {
                println!(
                    "CAPABILITIES_CASE_OBSERVATION_{}_ATTEMPT_{}={}",
                    case.id,
                    attempt,
                    serde_json::to_string_pretty(&observation)?
                );
            }

            let local = (case.local_sniff)(&observation);
            let arbiter =
                judge::run_arbiter(arbiter_runtime.clone(), &case, &observation, &local).await?;
            let strict_arbiter_required = matches!(
                case.id,
                "top_news_headlines"
                    | "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing"
            );
            let strict_local_required = matches!(
                case.id,
                "top_news_headlines" | "take_a_screenshot_of_my_desktop"
            );
            let timeout_terminal = is_timeout_terminal(&observation);
            let timeout_completion_override = case.allow_timeout_completion_with_local_evidence
                && timeout_terminal
                && local.pass
                && local.score >= case.min_local_score;
            let arbiter_effective_pass = if strict_arbiter_required {
                arbiter.pass
            } else {
                arbiter.pass || (local.pass && (!observation.failed || timeout_completion_override))
            };
            let retry_blocked_terminal = is_retry_blocked_terminal(&observation);
            let completion_effective_pass = observation.completed
                || (case.allow_retry_blocked_completion_with_local_evidence
                    && retry_blocked_terminal
                    && local.pass
                    && !observation.failed
                    && local.score >= case.min_local_score)
                || timeout_completion_override
                || (arbiter.pass && local.score >= case.min_local_score);
            let unresolved_approval_gate = types::has_unresolved_approval_gate(&observation);
            let approval_effective_pass = if case.id == "take_a_screenshot_of_my_desktop" {
                observation.approval_required_events > 0 && !unresolved_approval_gate
            } else {
                !unresolved_approval_gate
            };
            let hermetic_intervention_blocked = case.execution_profile
                == ExecutionProfile::Hermetic
                && is_human_intervention_blocker(&observation);

            let observed_pass = completion_effective_pass
                && approval_effective_pass
                && !hermetic_intervention_blocked
                && observation.elapsed_ms <= (case.sla_seconds as u128 * 1_000)
                && local.score >= case.min_local_score
                && (!strict_local_required || local.pass)
                && arbiter_effective_pass;

            let outcome = CaseOutcome {
                case_id: case.id.to_string(),
                query: observation.query.clone(),
                expected_pass: case.expected_pass,
                observed_pass,
                completed: observation.completed,
                final_status: observation.final_status.clone(),
                local,
                arbiter,
            };

            println!(
                "CAPABILITIES_CASE_RESULT_{}_ATTEMPT_{}={}",
                case.id,
                attempt,
                serde_json::to_string_pretty(&outcome)?
            );
            if should_emit_kernel_log_dump(
                kernel_log_mode,
                outcome.observed_pass,
                outcome.local.pass,
                outcome.arbiter.pass,
                observation.completed,
                observation.failed,
            ) {
                println!(
                    "CAPABILITIES_KERNEL_LOG_DUMP_{}_ATTEMPT_{}={}",
                    case.id,
                    attempt,
                    serde_json::to_string_pretty(&json!({
                        "case_id": case.id,
                        "attempt": attempt,
                        "query": observation.query,
                        "observed_pass": outcome.observed_pass,
                        "expected_pass": outcome.expected_pass,
                        "completed": observation.completed,
                        "failed": observation.failed,
                        "final_status": observation.final_status,
                        "local_pass": outcome.local.pass,
                        "local_failures": outcome.local.failures.clone(),
                        "arbiter_pass": outcome.arbiter.pass,
                        "arbiter_failures": outcome.arbiter.failures.clone(),
                        "run_timestamp_ms": observation.run_timestamp_ms,
                        "run_timestamp_iso_utc": observation.run_timestamp_iso_utc,
                        "kernel_event_count": observation.kernel_event_count,
                        "kernel_log_lines": observation.kernel_log_lines,
                    }))?
                );
            }

            if outcome.observed_pass == outcome.expected_pass {
                selected_outcome = Some(outcome);
                break;
            }
            last_outcome = Some(outcome);
        }

        let outcome = selected_outcome
            .or(last_outcome)
            .ok_or_else(|| anyhow!("no outcome produced for case '{}'", case.id))?;

        println!(
            "CAPABILITIES_CASE_RESULT_{}={}",
            case.id,
            serde_json::to_string_pretty(&outcome)?
        );

        if outcome.observed_pass != outcome.expected_pass {
            return Err(anyhow!(
                "capabilities outcome mismatch for '{}' after {} attempt(s): expected_pass={} observed_pass={} final_status={} local_score={} arbiter_confidence={} arbiter_rationale={}",
                case.id,
                attempts_allowed,
                outcome.expected_pass,
                outcome.observed_pass,
                outcome.final_status,
                outcome.local.score,
                outcome.arbiter.confidence,
                outcome.arbiter.rationale,
            ));
        }

        outcomes.push(outcome);
    }

    println!(
        "CAPABILITIES_SUITE_SUMMARY={}",
        serde_json::to_string_pretty(&json!({
            "total_cases": outcomes.len(),
            "matched_expectations": outcomes.iter().filter(|o| o.expected_pass == o.observed_pass).count(),
            "expected_fail_cases": outcomes.iter().filter(|o| !o.expected_pass).map(|o| o.case_id.clone()).collect::<Vec<_>>(),
            "observed_fail_cases": outcomes.iter().filter(|o| !o.observed_pass).map(|o| o.case_id.clone()).collect::<Vec<_>>(),
        }))?
    );

    Ok(())
}
