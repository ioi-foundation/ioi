pub(crate) mod harness;
pub(crate) mod judge;
#[path = "../live_inference_support.rs"]
pub(crate) mod live_inference_support;
pub(crate) mod tasks;
pub(crate) mod types;
pub(crate) mod workflow_backend;

use anyhow::{anyhow, Result};
use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use judge::judge_case;
use tasks::{cases_for_task_set, validate_case_catalog};
use types::{
    AgentBackend, ComputerUseCaseResult, ComputerUseMode, SuiteConfig, SuiteSummary, TaskSet,
};

const REWARD_FLOOR_EPSILON: f32 = 1e-4;

pub(crate) fn reward_meets_floor(observed_reward: f32, expected_reward_floor: f32) -> bool {
    observed_reward + REWARD_FLOOR_EPSILON >= expected_reward_floor
}

fn parse_modes(raw: &str) -> Result<Vec<ComputerUseMode>> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(vec![ComputerUseMode::Agent]);
    }
    if normalized == "all" {
        return Ok(vec![
            ComputerUseMode::Oracle,
            ComputerUseMode::Runtime,
            ComputerUseMode::Agent,
        ]);
    }

    let mut modes = Vec::new();
    for part in normalized
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let mode = match part {
            "oracle" => ComputerUseMode::Oracle,
            "runtime" => ComputerUseMode::Runtime,
            "agent" => ComputerUseMode::Agent,
            other => {
                return Err(anyhow!(
                    "invalid COMPUTER_USE_SUITE_MODE value '{}'; expected oracle|runtime|agent|all",
                    other
                ))
            }
        };
        if !modes.contains(&mode) {
            modes.push(mode);
        }
    }
    Ok(modes)
}

fn parse_task_set(raw: &str) -> Result<TaskSet> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "smoke" => Ok(TaskSet::Smoke),
        "core" => Ok(TaskSet::Core),
        "stress" => Ok(TaskSet::Stress),
        "catalog" => Ok(TaskSet::Catalog),
        "workflow" => Ok(TaskSet::Workflow),
        "workflow_rich" => Ok(TaskSet::WorkflowRich),
        "workflow_audit" => Ok(TaskSet::WorkflowAudit),
        "workflow_mutation" => Ok(TaskSet::WorkflowMutation),
        "workflow_reorder" => Ok(TaskSet::WorkflowReorder),
        other => Err(anyhow!(
            "invalid COMPUTER_USE_SUITE_TASK_SET value '{}'; expected smoke|core|stress|catalog|workflow|workflow_rich|workflow_audit|workflow_mutation|workflow_reorder",
            other
        )),
    }
}

fn parse_agent_backend(raw: &str) -> Result<AgentBackend> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "live_http" | "http" | "live" => Ok(AgentBackend::LiveHttp),
        "deterministic_miniwob" | "deterministic" => {
            Ok(AgentBackend::DeterministicMiniwob)
        }
        other => Err(anyhow!(
            "invalid COMPUTER_USE_SUITE_AGENT_BACKEND value '{}'; expected deterministic_miniwob|live_http",
            other
        )),
    }
}

fn default_artifact_root() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    PathBuf::from("target")
        .join("computer_use_suite")
        .join(format!("run-{}", ts))
}

fn configured_case_filter() -> Option<Vec<String>> {
    env::var("COMPUTER_USE_SUITE_CASES")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|entries| !entries.is_empty())
}

pub fn config_from_env() -> Result<SuiteConfig> {
    live_inference_support::load_env_from_workspace_dotenv_if_present();

    let modes =
        parse_modes(&env::var("COMPUTER_USE_SUITE_MODE").unwrap_or_else(|_| "agent".to_string()))?;
    let agent_backend = parse_agent_backend(
        &env::var("COMPUTER_USE_SUITE_AGENT_BACKEND").unwrap_or_else(|_| "live_http".to_string()),
    )?;
    let task_set = parse_task_set(
        &env::var("COMPUTER_USE_SUITE_TASK_SET").unwrap_or_else(|_| "smoke".to_string()),
    )?;
    let artifact_root = env::var("COMPUTER_USE_SUITE_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_artifact_root());
    let max_cases = env::var("COMPUTER_USE_SUITE_MAX_CASES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let retain_artifacts_for_all_runs = env::var("COMPUTER_USE_SUITE_VERBOSE_ARTIFACTS")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let require_browser_display = env::var("COMPUTER_USE_SUITE_REQUIRE_DISPLAY")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let bridge_source_dir = env::var("COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR")
        .ok()
        .map(PathBuf::from);
    let python_bin =
        env::var("COMPUTER_USE_SUITE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let fail_on_case_failure = env::var("COMPUTER_USE_SUITE_FAIL_ON_FAILURE")
        .map(|value| !(value == "0" || value.eq_ignore_ascii_case("false")))
        .unwrap_or(true);

    Ok(SuiteConfig {
        modes,
        agent_backend,
        task_set,
        case_filter: configured_case_filter(),
        max_cases,
        artifact_root,
        retain_artifacts_for_all_runs,
        require_browser_display,
        bridge_source_dir,
        python_bin,
        fail_on_case_failure,
    })
}

fn print_summary(summary: &SuiteSummary) {
    println!(
        "computer_use_suite mode={} task_set={} pass={}/{} task_successes={} kernel_successes={} artifacts={}",
        summary.mode.as_str(),
        summary.task_set.as_str(),
        summary.passing_cases,
        summary.total_cases,
        summary.task_successes,
        summary.kernel_successes,
        summary.artifact_root
    );
}

pub async fn run_computer_use_suite(config: SuiteConfig) -> Result<Vec<SuiteSummary>> {
    let mut cases = cases_for_task_set(config.task_set, config.bridge_source_dir.as_deref())?;
    validate_case_catalog(&cases)?;
    if let Some(filter) = &config.case_filter {
        cases.retain(|case| filter.iter().any(|entry| entry == &case.id));
    }
    if let Some(max_cases) = config.max_cases {
        cases.truncate(max_cases);
    }
    if cases.is_empty() {
        return Err(anyhow!(
            "no computer_use_suite cases selected for task_set={}",
            config.task_set.as_str()
        ));
    }

    let mut suite_summaries = Vec::new();
    let mut failure_messages = Vec::new();
    for mode in &config.modes {
        harness::publish_live_run_started(&config, *mode, config.task_set, &cases)?;
        let mut judged_results = Vec::new();
        let total_cases = cases.len();
        let report = harness::run_mode_with_case_sink(
            &config,
            *mode,
            &cases,
            |case, completed_cases| {
                harness::publish_live_case_started(
                    &config,
                    *mode,
                    config.task_set,
                    case,
                    completed_cases,
                    total_cases,
                )
            },
            |case, result: &ComputerUseCaseResult, completed_cases| {
                let judged = judge_case(case, result.clone());
                judged_results.push(judged.clone());
                harness::publish_live_case_progress(
                    &config,
                    *mode,
                    config.task_set,
                    &judged,
                    completed_cases,
                    total_cases,
                )
            },
        )
        .await?;
        if judged_results.len() != report.results.len() {
            judged_results = report
                .results
                .into_iter()
                .zip(cases.iter())
                .map(|(result, case)| judge_case(case, result))
                .collect::<Vec<_>>();
        }
        harness::persist_mode_report(&config, *mode, config.task_set, &judged_results).await?;

        let summary = SuiteSummary {
            mode: *mode,
            task_set: config.task_set,
            total_cases: judged_results.len(),
            passing_cases: judged_results
                .iter()
                .filter(|result| result.overall_pass)
                .count(),
            failing_cases: judged_results
                .iter()
                .filter(|result| !result.overall_pass)
                .count(),
            task_successes: judged_results
                .iter()
                .filter(|result| result.validation.task_success)
                .count(),
            kernel_successes: judged_results
                .iter()
                .filter(|result| result.validation.kernel_success)
                .count(),
            artifact_root: config.artifact_root.to_string_lossy().to_string(),
        };
        print_summary(&summary);
        if summary.failing_cases > 0 && config.fail_on_case_failure {
            failure_messages.push(format!(
                "computer_use_suite mode={} had {} failing case(s); see {}",
                mode.as_str(),
                summary.failing_cases,
                config.artifact_root.display()
            ));
        }
        suite_summaries.push(summary);
    }

    if let Some(message) = failure_messages.into_iter().next() {
        return Err(anyhow!(message));
    }

    Ok(suite_summaries)
}

#[cfg(test)]
mod tests {
    use super::{parse_agent_backend, parse_modes, AgentBackend, ComputerUseMode};

    #[test]
    fn parse_agent_backend_accepts_live_http_aliases() {
        assert_eq!(
            parse_agent_backend("live_http").unwrap(),
            AgentBackend::LiveHttp
        );
        assert_eq!(parse_agent_backend("HTTP").unwrap(), AgentBackend::LiveHttp);
        assert_eq!(parse_agent_backend("live").unwrap(), AgentBackend::LiveHttp);
    }

    #[test]
    fn parse_agent_backend_defaults_to_live_http() {
        assert_eq!(parse_agent_backend("").unwrap(), AgentBackend::LiveHttp);
        assert_eq!(
            parse_agent_backend("deterministic_miniwob").unwrap(),
            AgentBackend::DeterministicMiniwob
        );
    }

    #[test]
    fn parse_modes_defaults_to_agent() {
        assert_eq!(parse_modes("").unwrap(), vec![ComputerUseMode::Agent]);
        assert_eq!(
            parse_modes("all").unwrap(),
            vec![
                ComputerUseMode::Oracle,
                ComputerUseMode::Runtime,
                ComputerUseMode::Agent
            ]
        );
    }
}
