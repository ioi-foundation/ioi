use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::time::Instant;

use super::agent::runner::{run_agent_case, AgentExecutionContext};
use super::bridge::BridgeProcess;
use super::results::error_case_result;
use super::support::{extract_error_class, write_json_file, write_text_file};
use crate::computer_use_suite::types::{
    AgentBackend, ComputerUseCase, ComputerUseCaseResult, ComputerUseMode, SuiteConfig, TaskSet,
};

pub struct ModeRunReport {
    pub results: Vec<ComputerUseCaseResult>,
}

fn record_case_result<F>(
    case: &ComputerUseCase,
    result: ComputerUseCaseResult,
    results: &mut Vec<ComputerUseCaseResult>,
    on_case_result: &mut F,
) -> Result<()>
where
    F: FnMut(&ComputerUseCase, &ComputerUseCaseResult, usize) -> Result<()>,
{
    results.push(result);
    let latest = results
        .last()
        .expect("results should contain the newly recorded case result");
    on_case_result(case, latest, results.len())
}

fn configured_agent_backend(config: &SuiteConfig, mode: ComputerUseMode) -> Option<AgentBackend> {
    matches!(mode, ComputerUseMode::Agent).then_some(config.agent_backend)
}

fn unsupported_mode_report(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    cases: &[ComputerUseCase],
    message: &str,
) -> Result<ModeRunReport> {
    let mut results = Vec::new();
    for case in cases {
        let case_artifact_root = config
            .artifact_root
            .join(mode.as_str())
            .join(case.id.clone());
        let error_path = case_artifact_root.join("error.txt");
        write_text_file(&error_path, message)?;
        results.push(error_case_result(
            case,
            mode,
            configured_agent_backend(config, mode),
            case_artifact_root,
            0,
            message.to_string(),
        ));
    }
    Ok(ModeRunReport { results })
}

fn startup_failure_report(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    cases: &[ComputerUseCase],
    err: &anyhow::Error,
) -> Result<ModeRunReport> {
    unsupported_mode_report(
        config,
        mode,
        cases,
        &format!(
            "ERROR_CLASS={} {}",
            extract_error_class(&err.to_string())
                .unwrap_or_else(|| "harness_startup_failure".to_string()),
            err
        ),
    )
}

pub async fn run_mode_with_case_sink<F, G>(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    cases: &[ComputerUseCase],
    mut on_case_started: F,
    mut on_case_result: G,
) -> Result<ModeRunReport>
where
    F: FnMut(&ComputerUseCase, usize) -> Result<()>,
    G: FnMut(&ComputerUseCase, &ComputerUseCaseResult, usize) -> Result<()>,
{
    if !matches!(mode, ComputerUseMode::Agent) {
        let report = unsupported_mode_report(
            config,
            mode,
            cases,
            "ERROR_CLASS=mode_not_supported The modular MiniWoB harness currently supports agent mode only. Set COMPUTER_USE_SUITE_MODE=agent.",
        )?;
        let mut results = Vec::new();
        for (index, case) in cases.iter().enumerate() {
            on_case_started(case, index)?;
            record_case_result(
                case,
                report.results[index].clone(),
                &mut results,
                &mut on_case_result,
            )?;
        }
        return Ok(ModeRunReport { results });
    }

    let context = match AgentExecutionContext::start(config).await {
        Ok(context) => context,
        Err(err) => return startup_failure_report(config, mode, cases, &err),
    };
    let mut bridge = match BridgeProcess::start(config).await {
        Ok(bridge) => bridge,
        Err(err) => {
            context.stop().await;
            return startup_failure_report(config, mode, cases, &err);
        }
    };
    let mut results = Vec::new();
    for case in cases {
        if let Err(err) = on_case_started(case, results.len()) {
            context.stop().await;
            bridge.stop().await;
            return Err(err);
        }
        let case_root = config
            .artifact_root
            .join(mode.as_str())
            .join(case.id.to_string());
        fs::create_dir_all(&case_root)?;
        let started = Instant::now();
        let result =
            run_agent_case(config, &context, bridge.client(), case, case_root.clone()).await;
        let case_result = match result {
            Ok(result) => result,
            Err(err) => {
                let error_path = case_root.join("error.txt");
                let _ = write_text_file(&error_path, &format!("{:#}", err));
                error_case_result(
                    case,
                    mode,
                    configured_agent_backend(config, mode),
                    case_root,
                    started.elapsed().as_millis(),
                    extract_error_class(&err.to_string())
                        .unwrap_or_else(|| "harness_error".to_string()),
                )
            }
        };
        if let Err(err) = record_case_result(case, case_result, &mut results, &mut on_case_result) {
            context.stop().await;
            bridge.stop().await;
            return Err(err);
        }
    }
    context.stop().await;
    bridge.stop().await;
    Ok(ModeRunReport { results })
}

pub async fn persist_mode_report(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    results: &[ComputerUseCaseResult],
) -> Result<()> {
    let mode_root = config.artifact_root.join(mode.as_str());
    fs::create_dir_all(&mode_root)?;
    let stem = format!("{}_{}", mode.as_str(), task_set.as_str());
    let jsonl_path = mode_root.join(format!("{}.jsonl", stem));
    let markdown_path = mode_root.join(format!("{}.md", stem));
    let csv_path = mode_root.join(format!("{}.csv", stem));
    let gap_matrix_path = mode_root.join(format!("{}_gap_matrix.json", stem));

    let mut jsonl = String::new();
    let mut csv = String::from(
        "case_id,env_id,mode,agent_backend,task_set,pass,support_state,primary_gap_class,secondary_gap_tags,reward,terminated,elapsed_ms,failure_class\n",
    );
    let mut support_counts = BTreeMap::<String, usize>::new();
    let mut gap_counts = BTreeMap::<String, usize>::new();
    for result in results {
        jsonl.push_str(&serde_json::to_string(result)?);
        jsonl.push('\n');
        *support_counts
            .entry(result.support_state.as_str().to_string())
            .or_default() += 1;
        if let Some(gap_class) = result.primary_gap_class {
            *gap_counts
                .entry(gap_class.as_str().to_string())
                .or_default() += 1;
        }
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{:.3},{},{},{}\n",
            result.case_id,
            result.env_id,
            result.mode.as_str(),
            result
                .agent_backend
                .map(|backend| backend.as_str().to_string())
                .unwrap_or_default(),
            result.task_set.as_str(),
            result.overall_pass,
            result.support_state.as_str(),
            result
                .primary_gap_class
                .map(|gap_class| gap_class.as_str().to_string())
                .unwrap_or_default(),
            result.secondary_gap_tags.join("|"),
            result.final_reward,
            result.terminated,
            result.elapsed_ms,
            result.failure_class.clone().unwrap_or_default()
        ));
    }

    let passing = results.iter().filter(|result| result.overall_pass).count();
    let markdown = format!(
        "# Computer Use Suite\n\n- mode: `{}`\n- task_set: `{}`\n- passing: `{}` / `{}`\n- artifact_root: `{}`\n- support_counts: `{}`\n- gap_counts: `{}`\n\n| case | env | backend | pass | support | gap | tags | reward | terminated | failure |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n{}",
        mode.as_str(),
        task_set.as_str(),
        passing,
        results.len(),
        config.artifact_root.display(),
        serde_json::to_string(&support_counts)?,
        serde_json::to_string(&gap_counts)?,
        results
            .iter()
            .map(|result| {
                format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {:.3} | {} | {} |",
                    result.case_id,
                    result.env_id,
                    result
                        .agent_backend
                        .map(|backend| backend.as_str().to_string())
                        .unwrap_or_default(),
                    if result.overall_pass { "yes" } else { "no" },
                    result.support_state.as_str(),
                    result
                        .primary_gap_class
                        .map(|gap_class| gap_class.as_str().to_string())
                        .unwrap_or_default(),
                    result.secondary_gap_tags.join(", "),
                    result.final_reward,
                    result.terminated,
                    result.failure_class.clone().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    );

    let gap_matrix = json!({
        "mode": mode.as_str(),
        "task_set": task_set.as_str(),
        "artifact_root": config.artifact_root.to_string_lossy(),
        "totals": {
            "cases": results.len(),
            "passing": passing,
            "failing": results.len().saturating_sub(passing),
        },
        "by_support_state": support_counts,
        "by_gap_class": gap_counts,
        "results": results.iter().map(|result| {
            json!({
                "case_id": &result.case_id,
                "env_id": &result.env_id,
                "overall_pass": result.overall_pass,
                "agent_backend": result.agent_backend.map(|backend| backend.as_str()),
                "support_state": result.support_state.as_str(),
                "primary_gap_class": result.primary_gap_class.map(|gap_class| gap_class.as_str()),
                "secondary_gap_tags": &result.secondary_gap_tags,
                "failure_class": result.failure_class.as_deref(),
                "artifact_root": &result.artifacts.artifact_root,
            })
        }).collect::<Vec<_>>(),
    });

    write_text_file(&jsonl_path, &jsonl)?;
    write_text_file(&markdown_path, &markdown)?;
    write_text_file(&csv_path, &csv)?;
    write_json_file(&gap_matrix_path, &gap_matrix)?;
    Ok(())
}
