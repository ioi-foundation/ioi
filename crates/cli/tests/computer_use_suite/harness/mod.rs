use anyhow::Result;

use super::types::{ComputerUseCase, ComputerUseCaseResult, ComputerUseMode, SuiteConfig, TaskSet};

pub(super) use super::reward_meets_floor;
pub(super) use super::workflow_backend;

mod agent;
mod benchmark_refresh;
mod benchmark_store;
mod benchmark_summary;
mod benchmark_trace;
mod bridge;
mod case_harness;
mod context;
mod mode_runner;
mod results;
mod support;

pub use mode_runner::run_mode_with_case_sink;

pub fn publish_live_run_started(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    cases: &[ComputerUseCase],
) -> Result<()> {
    benchmark_store::publish_live_run_started(config, mode, task_set, cases)
}

pub fn publish_live_case_started(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    case: &ComputerUseCase,
    completed_cases: usize,
    total_cases: usize,
) -> Result<()> {
    benchmark_store::publish_live_case_started(
        config,
        mode,
        task_set,
        case,
        completed_cases,
        total_cases,
    )
}

pub fn publish_live_case_progress(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    result: &ComputerUseCaseResult,
    completed_cases: usize,
    total_cases: usize,
) -> Result<()> {
    benchmark_store::publish_live_case(config, mode, task_set, result, completed_cases, total_cases)
}

pub async fn persist_mode_report(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    results: &[ComputerUseCaseResult],
) -> Result<()> {
    mode_runner::persist_mode_report(config, mode, task_set, results).await?;
    benchmark_store::publish_live_run(config, mode, task_set, results)?;
    Ok(())
}
