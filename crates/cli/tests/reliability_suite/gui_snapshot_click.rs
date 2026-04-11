use super::harness::{
    build_executor_with_events, describe_result, extract_node_id_by_name, GuiFixtureApp,
};
use anyhow::{anyhow, Result};
use ioi_api::vm::drivers::gui::InputEvent;
use ioi_api::vm::drivers::os::WindowInfo;
use ioi_services::agentic::runtime::execution::ToolExecutor;
use ioi_services::agentic::runtime::types::ExecutionTier;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{KernelEvent, WorkloadActivityKind};
use std::fs;
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
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("reliability artifact open failed for {:?}: {}", path, e);
            return;
        }
    };
    let _ = std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes());
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(default)
}

fn fallback_root_target_id(snapshot_xml: &str) -> Option<String> {
    let lines: Vec<&str> = snapshot_xml
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("<!--"))
        .collect();
    if lines.len() != 1 {
        return None;
    }
    let line = lines[0];
    if !(line.starts_with("<desktop_frame") || line.starts_with("<root")) {
        return None;
    }
    let id_start = line.find(" id=\"")? + 5;
    let id_rest = &line[id_start..];
    let id_end = id_rest.find('"')?;
    let id = id_rest[..id_end].trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
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

async fn snapshot_with_target_retry(
    exec: &ToolExecutor,
    session_id: [u8; 32],
    visual_phash: [u8; 32],
    step_start: u32,
    rx: &mut broadcast::Receiver<KernelEvent>,
    all_events: &mut Vec<KernelEvent>,
) -> Result<(String, String, u32)> {
    const MAX_ATTEMPTS: u32 = 10;
    const RETRY_DELAY_MS: u64 = 500;
    let allow_root_fallback = parse_bool_env("IOI_RELIABILITY_GUI_ALLOW_ROOT_FALLBACK", true);
    let mut last_failure =
        "screen__inspect did not return a targetable accessibility node".to_string();

    for attempt in 0..MAX_ATTEMPTS {
        let step = step_start + attempt;
        let snapshot = exec
            .execute(
                AgentTool::GuiSnapshot {},
                session_id,
                step,
                visual_phash,
                None,
                None,
                None,
            )
            .await;
        sleep(Duration::from_millis(60)).await;
        drain_events(rx, all_events);

        if !snapshot.success {
            let err = describe_result(&snapshot);
            append_artifact_line(
                "gui_snapshot_attempts.log",
                &format!(
                    "step={} attempt={} failure={}",
                    step_start,
                    attempt + 1,
                    err
                ),
            );
            last_failure = format!("screen__inspect failed: {}", err);

            let transient = err.contains("Failed to fetch UI tree")
                || err.contains("Accessibility")
                || err.contains("atspi")
                || err.contains("AT-SPI");
            if transient && attempt + 1 < MAX_ATTEMPTS {
                sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            }
            break;
        }

        let snapshot_xml = snapshot.history_entry.unwrap_or_default();
        if snapshot_xml.trim().is_empty() {
            append_artifact_line(
                "gui_snapshot_attempts.log",
                &format!("step={} attempt={} empty_xml=true", step_start, attempt + 1),
            );
            last_failure = "screen__inspect returned an empty XML payload".to_string();
            if attempt + 1 < MAX_ATTEMPTS {
                sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            }
            break;
        }

        write_artifact(
            &format!("gui_snapshot_attempt_{}.xml", attempt + 1),
            &snapshot_xml,
        );

        if let Some(target_id) = extract_node_id_by_name(&snapshot_xml, "Confirm Reliability") {
            return Ok((snapshot_xml, target_id, step));
        }

        if allow_root_fallback {
            if let Some(fallback_id) = fallback_root_target_id(&snapshot_xml) {
                append_artifact_line(
                    "gui_snapshot_attempts.log",
                    &format!(
                        "step={} attempt={} fallback_target_id={} reason=root_only_tree",
                        step_start,
                        attempt + 1,
                        fallback_id
                    ),
                );
                return Ok((snapshot_xml, fallback_id, step));
            }
        }

        append_artifact_line(
            "gui_snapshot_attempts.log",
            &format!(
                "step={} attempt={} target_missing=true xml_len={}",
                step_start,
                attempt + 1,
                snapshot_xml.len()
            ),
        );
        last_failure = "could not find 'Confirm Reliability' in GUI snapshot XML".to_string();
        if attempt + 1 < MAX_ATTEMPTS {
            sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
            continue;
        }
    }

    Err(anyhow!(last_failure))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires live desktop accessibility session (DISPLAY/WAYLAND + AT-SPI/AX)"]
async fn gui_snapshot_then_click_element_emits_click_input() -> Result<()> {
    let require_gui = std::env::var("IOI_RELIABILITY_REQUIRE_GUI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut app = match GuiFixtureApp::spawn().await {
        Ok(app) => app,
        Err(e) => {
            write_artifact("gui_fixture_spawn_error.txt", &e.to_string());
            if !require_gui {
                eprintln!(
                    "Skipping GUI reliability assertion due local GUI fixture limitation: {}",
                    e
                );
                return Ok(());
            }
            return Err(e);
        }
    };
    let fixture_window = WindowInfo {
        title: "IOI GUI Click Fixture".to_string(),
        x: 120,
        y: 120,
        width: 420,
        height: 240,
        app_name: "python3".to_string(),
    };

    let (tx, mut rx) = broadcast::channel(256);
    let (exec, gui, browser) = build_executor_with_events(
        ExecutionTier::VisualForeground,
        Some(fixture_window),
        Some(tx),
    );
    let mut all_events: Vec<KernelEvent> = Vec::new();

    let session_id = [0xB6; 32];
    let visual_phash = [0u8; 32];

    let (snapshot_xml, target_id, snapshot_step) = match snapshot_with_target_retry(
        &exec,
        session_id,
        visual_phash,
        1,
        &mut rx,
        &mut all_events,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            write_artifact("gui_snapshot_error.txt", &e.to_string());
            if !require_gui {
                let err = e.to_string();
                let transient = err.contains("Failed to fetch UI tree")
                    || err.contains("Accessibility")
                    || err.contains("atspi")
                    || err.contains("AT-SPI");
                if transient {
                    app.stop().await;
                    browser.stop().await;
                    eprintln!(
                        "Skipping GUI reliability assertion due local accessibility limitation: {}",
                        err
                    );
                    return Ok(());
                }
            }
            app.stop().await;
            browser.stop().await;
            return Err(e);
        }
    };
    write_artifact("gui_snapshot.xml", &snapshot_xml);

    let click_step = snapshot_step + 1;
    let click = exec
        .execute(
            AgentTool::GuiClickElement {
                id: target_id.clone(),
            },
            session_id,
            click_step,
            visual_phash,
            None,
            None,
            None,
        )
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(&mut rx, &mut all_events);
    if !click.success {
        write_artifact("gui_click_error.txt", &describe_result(&click));
        app.stop().await;
        browser.stop().await;
        return Err(anyhow!(
            "screen__click failed for id '{}': {}",
            target_id,
            describe_result(&click)
        ));
    }

    let events = gui.take_events();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, InputEvent::Click { .. })),
        "expected screen__click to emit an injected click event, got: {:?}",
        events
    );
    for step in 1..=snapshot_step {
        assert_step_has_no_duplicate_events(&all_events, step, "gui snapshot");
    }
    assert_step_has_no_duplicate_events(&all_events, click_step, "gui click");
    write_artifact("gui_click_events.txt", &format!("{:?}", events));

    app.stop().await;
    browser.stop().await;
    Ok(())
}
