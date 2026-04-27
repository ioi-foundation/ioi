use super::harness::build_executor_with_events;
use anyhow::{anyhow, Result};
use ioi_services::agentic::runtime::execution::ToolExecutionResult;
use ioi_services::agentic::runtime::types::{CommandExecution, ExecutionTier};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{KernelEvent, WorkloadActivityKind, WorkloadReceipt, WorkloadReceiptEvent};
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};

fn parse_command_history_metadata(result: &ToolExecutionResult) -> Option<CommandExecution> {
    let entry = result.history_entry.as_ref()?;
    entry
        .lines()
        .find_map(|line| line.strip_prefix("COMMAND_HISTORY:"))
        .and_then(|json| serde_json::from_str::<CommandExecution>(json).ok())
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

fn exec_receipts_for_step(events: &[KernelEvent], step_index: u32) -> Vec<WorkloadReceiptEvent> {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::WorkloadReceipt(receipt) if receipt.step_index == step_index => {
                Some(receipt.clone())
            }
            _ => None,
        })
        .collect()
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, all_events: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        all_events.push(event);
    }
}

async fn execute_with_event_drain(
    exec: &ioi_services::agentic::runtime::execution::ToolExecutor,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    visual_phash: [u8; 32],
    rx: &mut broadcast::Receiver<KernelEvent>,
    all_events: &mut Vec<KernelEvent>,
) -> ToolExecutionResult {
    let result = exec
        .execute(tool, session_id, step_index, visual_phash, None, None, None)
        .await;
    sleep(Duration::from_millis(40)).await;
    drain_events(rx, all_events);
    result
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local shell runtime for persistent session commands"]
async fn sys_exec_session_continuity_reset_failure_receipts_and_anti_loop() -> Result<()> {
    let (tx, mut rx) = broadcast::channel(256);
    let (exec, _gui, browser) =
        build_executor_with_events(ExecutionTier::DomHeadless, None, Some(tx));
    let session_id = [0xD4; 32];
    let visual_phash = [0u8; 32];
    let mut all_events: Vec<KernelEvent> = Vec::new();

    let reset_before = execute_with_event_drain(
        &exec,
        AgentTool::SysExecSessionReset {},
        session_id,
        1,
        visual_phash,
        &mut rx,
        &mut all_events,
    )
    .await;
    if !reset_before.success {
        browser.stop().await;
        return Err(anyhow!(
            "shell__reset (pre) failed: {:?}",
            reset_before.error
        ));
    }

    let export_result = execute_with_event_drain(
        &exec,
        AgentTool::SysExecSession {
            command: "export IOI_RELIABILITY_PHASE0_VAR=phase0_ready".to_string(),
            args: vec![],
            stdin: None,
            wait_ms_before_async: None,
        },
        session_id,
        2,
        visual_phash,
        &mut rx,
        &mut all_events,
    )
    .await;
    if !export_result.success {
        browser.stop().await;
        return Err(anyhow!("shell__start export failed: {:?}", export_result));
    }

    let read_var_before_reset = execute_with_event_drain(
        &exec,
        AgentTool::SysExecSession {
            command: "printf '%s' \"$IOI_RELIABILITY_PHASE0_VAR\"".to_string(),
            args: vec![],
            stdin: None,
            wait_ms_before_async: None,
        },
        session_id,
        3,
        visual_phash,
        &mut rx,
        &mut all_events,
    )
    .await;
    if !read_var_before_reset.success {
        browser.stop().await;
        return Err(anyhow!(
            "shell__start read before reset failed: {:?}",
            read_var_before_reset
        ));
    }
    let before_meta = parse_command_history_metadata(&read_var_before_reset)
        .ok_or_else(|| anyhow!("missing command history metadata before reset"))?;
    assert!(
        before_meta.stdout.contains("phase0_ready"),
        "expected exported value in stdout before reset, got: {:?}",
        before_meta.stdout
    );

    let reset_after = execute_with_event_drain(
        &exec,
        AgentTool::SysExecSessionReset {},
        session_id,
        4,
        visual_phash,
        &mut rx,
        &mut all_events,
    )
    .await;
    if !reset_after.success {
        browser.stop().await;
        return Err(anyhow!(
            "shell__reset (post) failed: {:?}",
            reset_after.error
        ));
    }

    let read_var_after_reset = execute_with_event_drain(
        &exec,
        AgentTool::SysExecSession {
            command: "printf '%s' \"$IOI_RELIABILITY_PHASE0_VAR\"".to_string(),
            args: vec![],
            stdin: None,
            wait_ms_before_async: None,
        },
        session_id,
        5,
        visual_phash,
        &mut rx,
        &mut all_events,
    )
    .await;
    if !read_var_after_reset.success {
        browser.stop().await;
        return Err(anyhow!(
            "shell__start read after reset failed: {:?}",
            read_var_after_reset
        ));
    }
    let after_meta = parse_command_history_metadata(&read_var_after_reset)
        .ok_or_else(|| anyhow!("missing command history metadata after reset"))?;
    assert!(
        !after_meta.stdout.contains("phase0_ready"),
        "expected reset session to clear exported variable marker, got stdout={:?}",
        after_meta.stdout
    );

    let missing_command = execute_with_event_drain(
        &exec,
        AgentTool::SysExecSession {
            command: "__ioi_missing_command_for_reliability__".to_string(),
            args: vec![],
            stdin: None,
            wait_ms_before_async: None,
        },
        session_id,
        6,
        visual_phash,
        &mut rx,
        &mut all_events,
    )
    .await;
    assert!(!missing_command.success);
    let failure = missing_command.error.unwrap_or_default();
    assert!(
        failure.contains("ERROR_CLASS=ToolUnavailable"),
        "expected ToolUnavailable classification, got: {}",
        failure
    );

    let timeout_class_failure = execute_with_event_drain(
        &exec,
        AgentTool::SysExecSession {
            command: "sh".to_string(),
            args: vec!["-lc".to_string(), "echo timed out >&2; exit 1".to_string()],
            stdin: None,
            wait_ms_before_async: None,
        },
        session_id,
        7,
        visual_phash,
        &mut rx,
        &mut all_events,
    )
    .await;
    assert!(!timeout_class_failure.success);
    let timeout_failure = timeout_class_failure.error.unwrap_or_default();
    assert!(
        timeout_failure.contains("ERROR_CLASS=TimeoutOrHang"),
        "expected TimeoutOrHang classification, got: {}",
        timeout_failure
    );

    for success_step in [1u32, 2, 3, 4, 5] {
        let evidence = exec_receipts_for_step(&all_events, success_step);
        assert_eq!(
            evidence.len(),
            1,
            "expected exactly one workload receipt for success step {}",
            success_step
        );
        match &evidence[0].receipt {
            WorkloadReceipt::Exec(exec_receipt) => {
                assert!(
                    exec_receipt.success,
                    "expected success receipt for step {}",
                    success_step
                );
            }
            other => {
                browser.stop().await;
                return Err(anyhow!(
                    "expected exec receipt for step {}, got {:?}",
                    success_step,
                    other
                ));
            }
        }
        assert_eq!(
            count_lifecycle_phase(&all_events, success_step, "started"),
            1,
            "expected exactly one started lifecycle event for step {}",
            success_step
        );
        assert_eq!(
            count_lifecycle_phase(&all_events, success_step, "completed"),
            1,
            "expected exactly one completed lifecycle event for step {}",
            success_step
        );
    }

    let failure_receipts = exec_receipts_for_step(&all_events, 6);
    assert_eq!(
        failure_receipts.len(),
        1,
        "anti-loop guard: expected a single receipt for failed command step"
    );
    match &failure_receipts[0].receipt {
        WorkloadReceipt::Exec(exec_receipt) => {
            assert!(!exec_receipt.success);
            assert_eq!(exec_receipt.error_class.as_deref(), Some("ToolUnavailable"));
        }
        other => {
            browser.stop().await;
            return Err(anyhow!(
                "expected exec receipt for failure step, got {:?}",
                other
            ));
        }
    }
    assert_eq!(
        count_lifecycle_phase(&all_events, 6, "started"),
        1,
        "anti-loop guard: failure step should have one started lifecycle"
    );
    assert_eq!(
        count_lifecycle_phase(&all_events, 6, "failed"),
        1,
        "anti-loop guard: failure step should have one failed lifecycle"
    );

    let timeout_receipts = exec_receipts_for_step(&all_events, 7);
    assert_eq!(
        timeout_receipts.len(),
        1,
        "anti-loop guard: expected a single receipt for timeout-classified failure step"
    );
    match &timeout_receipts[0].receipt {
        WorkloadReceipt::Exec(exec_receipt) => {
            assert!(!exec_receipt.success);
            assert_eq!(exec_receipt.error_class.as_deref(), Some("TimeoutOrHang"));
        }
        other => {
            browser.stop().await;
            return Err(anyhow!(
                "expected exec receipt for timeout failure step, got {:?}",
                other
            ));
        }
    }
    assert_eq!(
        count_lifecycle_phase(&all_events, 7, "started"),
        1,
        "anti-loop guard: timeout failure step should have one started lifecycle"
    );
    assert_eq!(
        count_lifecycle_phase(&all_events, 7, "failed"),
        1,
        "anti-loop guard: timeout failure step should have one failed lifecycle"
    );

    browser.stop().await;
    Ok(())
}
