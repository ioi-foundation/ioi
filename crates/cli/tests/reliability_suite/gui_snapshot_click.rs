use super::harness::{
    build_executor_with_events, describe_result, extract_node_id_by_name, GuiFixtureApp,
};
use anyhow::{anyhow, Result};
use ioi_api::vm::drivers::gui::InputEvent;
use ioi_services::agentic::desktop::types::ExecutionTier;
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
    let (tx, mut rx) = broadcast::channel(256);
    let (exec, gui, browser) =
        build_executor_with_events(ExecutionTier::VisualForeground, None, Some(tx));
    let mut all_events: Vec<KernelEvent> = Vec::new();

    let session_id = [0xB6; 32];
    let visual_phash = [0u8; 32];

    let snapshot = exec
        .execute(
            AgentTool::GuiSnapshot {},
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
    if !snapshot.success {
        write_artifact("gui_snapshot_error.txt", &describe_result(&snapshot));
        if !require_gui {
            let err = describe_result(&snapshot);
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
        return Err(anyhow!(
            "gui__snapshot failed: {}",
            describe_result(&snapshot)
        ));
    }
    let snapshot_xml = snapshot
        .history_entry
        .clone()
        .ok_or_else(|| anyhow!("gui__snapshot returned no XML payload"))?;
    write_artifact("gui_snapshot.xml", &snapshot_xml);

    let target_id = extract_node_id_by_name(&snapshot_xml, "Confirm Reliability")
        .ok_or_else(|| anyhow!("could not find 'Confirm Reliability' in GUI snapshot XML"))?;

    let click = exec
        .execute(
            AgentTool::GuiClickElement {
                id: target_id.clone(),
            },
            session_id,
            2,
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
            "gui__click_element failed for id '{}': {}",
            target_id,
            describe_result(&click)
        ));
    }

    let events = gui.take_events();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, InputEvent::Click { .. })),
        "expected gui__click_element to emit an injected click event, got: {:?}",
        events
    );
    assert_eq!(
        receipt_count_for_step(&all_events, 1),
        1,
        "anti-loop guard: gui snapshot should emit one receipt"
    );
    assert_eq!(
        count_lifecycle_phase(&all_events, 1, "started"),
        1,
        "anti-loop guard: gui snapshot should emit one started lifecycle event"
    );
    assert_eq!(
        count_lifecycle_phase(&all_events, 1, "completed"),
        1,
        "anti-loop guard: gui snapshot should emit one completed lifecycle event"
    );
    assert_eq!(
        receipt_count_for_step(&all_events, 2),
        1,
        "anti-loop guard: gui click should emit one receipt"
    );
    assert_eq!(
        count_lifecycle_phase(&all_events, 2, "started"),
        1,
        "anti-loop guard: gui click should emit one started lifecycle event"
    );
    assert_eq!(
        count_lifecycle_phase(&all_events, 2, "completed"),
        1,
        "anti-loop guard: gui click should emit one completed lifecycle event"
    );
    write_artifact("gui_click_events.txt", &format!("{:?}", events));

    app.stop().await;
    browser.stop().await;
    Ok(())
}
