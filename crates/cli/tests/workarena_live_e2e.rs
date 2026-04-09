#[allow(dead_code)]
#[path = "live_inference_support.rs"]
mod live_inference_support;

use anyhow::{anyhow, Context, Result};
use ioi_drivers::browser::BrowserDriver;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn bridge_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/browsergym/workarena_cdp_bridge.py")
}

fn run_bridge_json(args: &[&str]) -> Result<(Value, i32, String)> {
    let script = bridge_script_path();
    let output = Command::new("python3")
        .arg(&script)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute bridge script {}", script.display()))?;

    let stdout = String::from_utf8(output.stdout).context("bridge stdout was not utf8")?;
    let status = output.status.code().unwrap_or(-1);
    let payload: Value = serde_json::from_str(stdout.trim()).with_context(|| {
        format!(
            "bridge stdout was not valid json (status={}): {}",
            status, stdout
        )
    })?;
    Ok((payload, status, stdout))
}

#[test]
fn workarena_bridge_preflight_reports_repo_external_blockers_or_ready_state() -> Result<()> {
    live_inference_support::load_env_from_workspace_dotenv_if_present();
    let (payload, status, _) = run_bridge_json(&["preflight"])?;

    assert_eq!(payload["benchmark"].as_str(), Some("workarena"));
    assert_eq!(payload["bridge"].as_str(), Some("cdp"));
    assert!(payload.get("requirements").is_some());
    assert!(payload.get("env").is_some());

    let ok = payload["ok"]
        .as_bool()
        .ok_or_else(|| anyhow!("bridge preflight missing ok flag: {}", payload))?;
    if ok {
        assert_eq!(status, 0, "ready preflight should exit cleanly");
    } else {
        let blockers = payload["blockers"]
            .as_array()
            .ok_or_else(|| anyhow!("bridge preflight missing blockers array: {}", payload))?;
        assert!(
            !blockers.is_empty(),
            "non-ready preflight must explain blockers: {}",
            payload
        );
        assert!(
            status == 1 || status == 2,
            "blocked preflight should use a non-zero exit status"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "WorkArena dependencies, credentials, and a reachable benchmark instance are required"]
async fn workarena_bridge_prepare_validation_uses_browser_driver_session() -> Result<()> {
    live_inference_support::load_env_from_workspace_dotenv_if_present();

    let (preflight, _, _) = run_bridge_json(&["preflight"])?;
    anyhow::ensure!(
        preflight["ok"].as_bool().unwrap_or(false),
        "workarena preflight not ready: {}",
        serde_json::to_string_pretty(&preflight)?
    );

    let browser = BrowserDriver::new();
    browser.set_lease(true);
    browser.navigate("about:blank").await?;
    let cdp_url = browser.debugger_websocket_url().await?;

    let temp_dir = tempdir()?;
    let state_path = temp_dir.path().join("task_state.json");
    let state_path_string = state_path.display().to_string();

    let (payload, status, _) = run_bridge_json(&[
        "prepare",
        "--cdp-url",
        cdp_url.as_str(),
        "--task-id",
        "workarena.servicenow.all-menu",
        "--seed",
        "0",
        "--state-path",
        state_path_string.as_str(),
    ])?;

    anyhow::ensure!(
        status == 0,
        "workarena prepare failed: {}",
        serde_json::to_string_pretty(&payload)?
    );
    anyhow::ensure!(
        payload["ok"].as_bool().unwrap_or(false),
        "workarena prepare did not report ok: {}",
        serde_json::to_string_pretty(&payload)?
    );
    anyhow::ensure!(
        payload["goal"]
            .as_str()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false),
        "workarena prepare did not emit a goal: {}",
        serde_json::to_string_pretty(&payload)?
    );
    anyhow::ensure!(
        state_path.exists(),
        "workarena bridge did not write state file"
    );

    Ok(())
}
