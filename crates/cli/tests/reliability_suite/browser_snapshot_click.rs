use super::harness::{
    build_executor_with_events, describe_result, extract_node_id_by_name,
    spawn_browser_fixture_server,
};
use anyhow::{anyhow, Result};
use ioi_services::agentic::runtime::execution::ToolExecutor;
use ioi_services::agentic::runtime::types::ExecutionTier;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{KernelEvent, WorkloadActivityKind};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};

fn artifact_dir() -> Option<PathBuf> {
    std::env::var("IOI_RELIABILITY_ARTIFACT_DIR")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn write_artifact(name: &str, content: &str) {
    let Some(dir) = artifact_dir() else {
        return;
    };
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("reliability artifact mkdir failed for {:?}: {}", dir, e);
        return;
    }
    let path = dir.join(name);
    if let Err(e) = fs::write(&path, content.as_bytes()) {
        eprintln!("reliability artifact write failed for {:?}: {}", path, e);
    }
}

fn append_artifact_line(name: &str, line: &str) {
    let Some(dir) = artifact_dir() else {
        return;
    };
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("reliability artifact mkdir failed for {:?}: {}", dir, e);
        return;
    }
    let path = dir.join(name);
    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("reliability artifact open failed for {:?}: {}", path, e);
            return;
        }
    };
    let _ = writeln!(file, "{}", line);
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, all_events: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        all_events.push(event);
    }
}

fn receipt_count_for_step(events: &[KernelEvent], step_index: u32) -> usize {
    events
        .iter()
        .filter(|event| {
            matches!(
                event,
                KernelEvent::WorkloadReceipt(receipt_event)
                    if receipt_event.step_index == step_index
            )
        })
        .count()
}

fn count_lifecycle_phase(events: &[KernelEvent], step_index: u32, phase: &str) -> usize {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::WorkloadActivity(activity) if activity.step_index == step_index => {
                Some(&activity.kind)
            }
            _ => None,
        })
        .filter(|kind| {
            matches!(
                kind,
                WorkloadActivityKind::Lifecycle {
                    phase: event_phase,
                    ..
                } if event_phase == phase
            )
        })
        .count()
}

fn assert_step_has_no_duplicate_events(events: &[KernelEvent], step_index: u32, tool: &str) {
    assert!(
        receipt_count_for_step(events, step_index) <= 1,
        "anti-loop guard: {} step {} emitted duplicate receipts",
        tool,
        step_index
    );
    assert!(
        count_lifecycle_phase(events, step_index, "started") <= 1,
        "anti-loop guard: {} step {} emitted duplicate started lifecycle events",
        tool,
        step_index
    );
    assert!(
        count_lifecycle_phase(events, step_index, "completed") <= 1,
        "anti-loop guard: {} step {} emitted duplicate completed lifecycle events",
        tool,
        step_index
    );
}

async fn snapshot_with_retry(
    exec: &ToolExecutor,
    session_id: [u8; 32],
    visual_phash: [u8; 32],
    step_start: u32,
    rx: &mut broadcast::Receiver<KernelEvent>,
    all_events: &mut Vec<KernelEvent>,
) -> Result<String> {
    let mut last_failure = String::new();

    for attempt in 0..5u32 {
        let step = step_start + attempt;
        let snapshot = exec
            .execute(
                AgentTool::BrowserSnapshot {},
                session_id,
                step,
                visual_phash,
                None,
                None,
                None,
            )
            .await;
        sleep(Duration::from_millis(40)).await;
        drain_events(rx, all_events);

        if snapshot.success {
            if let Some(xml) = snapshot.history_entry {
                if !xml.trim().is_empty() {
                    return Ok(xml);
                }
            }
            append_artifact_line(
                "snapshot_attempts.log",
                &format!(
                    "step={} attempt={} error=browser snapshot returned empty XML payload",
                    step_start,
                    attempt + 1
                ),
            );
            last_failure = "browser snapshot returned empty XML payload".to_string();
            if attempt < 4 {
                sleep(Duration::from_millis(180)).await;
                continue;
            }
            break;
        }

        let err = snapshot
            .error
            .unwrap_or_else(|| "unknown browser snapshot failure".to_string());
        append_artifact_line(
            "snapshot_attempts.log",
            &format!("step={} attempt={} error={}", step_start, attempt + 1, err),
        );
        last_failure = err.clone();
        let transient_ax = err.contains("CDP GetAxTree failed: uninteresting")
            || err.contains("Empty accessibility tree returned")
            || err.contains("empty XML payload");
        if !transient_ax || attempt == 4 {
            break;
        }
        sleep(Duration::from_millis(180)).await;
    }

    Err(anyhow!(
        "browser snapshot failed after retries: {}",
        last_failure
    ))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Chromium runtime and local browser fixture server"]
async fn browser_snapshot_then_click_element_updates_fixture() -> Result<()> {
    let mut fixture = spawn_browser_fixture_server().await?;
    let (tx, mut rx) = broadcast::channel(256);
    let (exec, _gui, browser) =
        build_executor_with_events(ExecutionTier::DomHeadless, None, Some(tx));
    let mut all_events: Vec<KernelEvent> = Vec::new();

    // Prefer non-headless under Xvfb CI for more stable AX trees.
    let headless = std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err();
    let require_display = std::env::var("IOI_RELIABILITY_REQUIRE_DISPLAY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if require_display && headless {
        return Err(anyhow!(
            "display session required for browser reliability run (set by IOI_RELIABILITY_REQUIRE_DISPLAY)"
        ));
    }
    browser
        .launch(headless)
        .await
        .map_err(|e| anyhow!("failed to launch Chromium for reliability test: {}", e))?;

    let session_id = [0xA4; 32];
    let visual_phash = [0u8; 32];

    let navigate = exec
        .execute(
            AgentTool::BrowserNavigate { url: fixture.url() },
            session_id,
            1,
            visual_phash,
            None,
            None,
            None,
        )
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(&mut rx, &mut all_events);
    if !navigate.success {
        write_artifact("navigate_result.txt", &describe_result(&navigate));
        browser.stop().await;
        fixture.stop().await;
        return Err(anyhow!("navigate failed: {}", describe_result(&navigate)));
    }
    if let Some(history) = navigate.history_entry.as_ref() {
        write_artifact("navigate_result.txt", history);
    }

    let first_xml =
        match snapshot_with_retry(&exec, session_id, visual_phash, 2, &mut rx, &mut all_events)
            .await
        {
            Ok(xml) => {
                write_artifact("first_snapshot.xml", &xml);
                xml
            }
            Err(e) => {
                write_artifact("first_snapshot_error.txt", &e.to_string());
                if !require_display
                    && e.to_string()
                        .contains("CDP GetAxTree failed: uninteresting")
                {
                    // Some local/dev Chromium runtime configurations can report an uninteresting AX tree.
                    // CI enables IOI_RELIABILITY_REQUIRE_DISPLAY=1 to make this a hard failure.
                    browser.stop().await;
                    fixture.stop().await;
                    eprintln!(
                        "Skipping browser reliability assertion due local AX-tree limitation: {}",
                        e
                    );
                    return Ok(());
                }
                browser.stop().await;
                fixture.stop().await;
                return Err(e);
            }
        };
    let target_id = extract_node_id_by_name(&first_xml, "Increment Count")
        .ok_or_else(|| anyhow!("could not find Increment Count button in browser snapshot XML"))?;

    let click = exec
        .execute(
            AgentTool::BrowserClickElement {
                id: Some(target_id.clone()),
                ids: Vec::new(),
                delay_ms_between_ids: None,
                continue_with: None,
            },
            session_id,
            7,
            visual_phash,
            None,
            None,
            None,
        )
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(&mut rx, &mut all_events);
    if !click.success {
        write_artifact("click_result.txt", &describe_result(&click));
        browser.stop().await;
        fixture.stop().await;
        return Err(anyhow!(
            "browser__click_element failed for id '{}': {}",
            target_id,
            describe_result(&click)
        ));
    }
    if let Some(history) = click.history_entry.as_ref() {
        write_artifact("click_result.txt", history);
    }

    let second_xml =
        match snapshot_with_retry(&exec, session_id, visual_phash, 8, &mut rx, &mut all_events)
            .await
        {
            Ok(xml) => {
                write_artifact("second_snapshot.xml", &xml);
                xml
            }
            Err(e) => {
                write_artifact("second_snapshot_error.txt", &e.to_string());
                browser.stop().await;
                fixture.stop().await;
                return Err(e);
            }
        };

    assert!(
        second_xml.contains("Increment Count (clicked 1)") || second_xml.contains("Count is now 1"),
        "post-click browser snapshot did not reflect the expected click side effect"
    );
    for step in 2..=6 {
        assert_step_has_no_duplicate_events(&all_events, step, "browser snapshot");
    }
    for step in 8..=12 {
        assert_step_has_no_duplicate_events(&all_events, step, "post-click browser snapshot");
    }
    assert_step_has_no_duplicate_events(&all_events, 1, "browser navigate");
    assert_step_has_no_duplicate_events(&all_events, 7, "browser click");

    browser.stop().await;
    fixture.stop().await;
    Ok(())
}
