#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

#[path = "computer_use_suite/mod.rs"]
mod computer_use_suite;

#[test]
fn computer_use_suite_manifest_is_unique() -> anyhow::Result<()> {
    let cases = computer_use_suite::tasks::cases_for_task_set(computer_use_suite::types::TaskSet::Stress);
    computer_use_suite::tasks::validate_case_catalog(&cases)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
async fn computer_use_suite_oracle_smoke() -> anyhow::Result<()> {
    let mut config = computer_use_suite::config_from_env()?;
    config.modes = vec![computer_use_suite::types::ComputerUseMode::Oracle];
    config.task_set = computer_use_suite::types::TaskSet::Smoke;
    computer_use_suite::run_computer_use_suite(config).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
async fn computer_use_suite_runtime_smoke() -> anyhow::Result<()> {
    let mut config = computer_use_suite::config_from_env()?;
    config.modes = vec![computer_use_suite::types::ComputerUseMode::Runtime];
    config.task_set = computer_use_suite::types::TaskSet::Smoke;
    computer_use_suite::run_computer_use_suite(config).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
async fn computer_use_suite_agent_smoke() -> anyhow::Result<()> {
    let mut config = computer_use_suite::config_from_env()?;
    config.modes = vec![computer_use_suite::types::ComputerUseMode::Agent];
    config.task_set = computer_use_suite::types::TaskSet::Smoke;
    computer_use_suite::run_computer_use_suite(config).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Chromium runtime, MiniWoB bridge helper, and local task assets"]
async fn computer_use_suite_from_env() -> anyhow::Result<()> {
    let config = computer_use_suite::config_from_env()?;
    computer_use_suite::run_computer_use_suite(config).await?;
    Ok(())
}
