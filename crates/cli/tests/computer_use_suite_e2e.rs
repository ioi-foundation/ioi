#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Context;
use std::future::Future;
use std::thread;
use tokio::runtime::Builder;

#[path = "computer_use_suite/mod.rs"]
mod computer_use_suite;

const COMPUTER_USE_SUITE_TEST_STACK_BYTES: usize = 64 * 1024 * 1024;

#[test]
fn computer_use_suite_manifest_is_unique() -> anyhow::Result<()> {
    let cases = computer_use_suite::tasks::cases_for_task_set(
        computer_use_suite::types::TaskSet::Stress,
        None,
    )?;
    computer_use_suite::tasks::validate_case_catalog(&cases)?;
    Ok(())
}

fn run_computer_use_suite_test<F, Fut>(test_fn: F) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let handle = thread::Builder::new()
        .name("computer-use-suite-runtime".to_string())
        .stack_size(COMPUTER_USE_SUITE_TEST_STACK_BYTES)
        .spawn(move || {
            Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("build computer use suite Tokio runtime")?
                .block_on(test_fn())
        })
        .context("spawn computer use suite runtime thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[test]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
fn computer_use_suite_oracle_smoke() -> anyhow::Result<()> {
    run_computer_use_suite_test(|| async {
        let mut config = computer_use_suite::config_from_env()?;
        config.modes = vec![computer_use_suite::types::ComputerUseMode::Oracle];
        config.task_set = computer_use_suite::types::TaskSet::Smoke;
        computer_use_suite::run_computer_use_suite(config).await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
fn computer_use_suite_runtime_smoke() -> anyhow::Result<()> {
    run_computer_use_suite_test(|| async {
        let mut config = computer_use_suite::config_from_env()?;
        config.modes = vec![computer_use_suite::types::ComputerUseMode::Runtime];
        config.task_set = computer_use_suite::types::TaskSet::Smoke;
        computer_use_suite::run_computer_use_suite(config).await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
fn computer_use_suite_agent_smoke() -> anyhow::Result<()> {
    run_computer_use_suite_test(|| async {
        let mut config = computer_use_suite::config_from_env()?;
        config.modes = vec![computer_use_suite::types::ComputerUseMode::Agent];
        config.task_set = computer_use_suite::types::TaskSet::Smoke;
        computer_use_suite::run_computer_use_suite(config).await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
fn computer_use_suite_from_env() -> anyhow::Result<()> {
    run_computer_use_suite_test(|| async {
        let config = computer_use_suite::config_from_env()?;
        computer_use_suite::run_computer_use_suite(config).await?;
        Ok(())
    })
}
