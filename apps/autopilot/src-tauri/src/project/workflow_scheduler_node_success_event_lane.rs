// apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs

use super::workflow_node_metadata_lane::workflow_node_name;
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn workflow_scheduler_emit_node_success_events(
    events: &mut Vec<WorkflowStreamEvent>,
    run_id: &str,
    thread_id: &str,
    node_id: &str,
    node: &Value,
    action_kind: &ActionKind,
    output: &Value,
    update: WorkflowStateUpdate,
) {
    let node_name = workflow_node_name(node);
    workflow_push_event(
        events,
        run_id,
        thread_id,
        "node_succeeded",
        Some(node_id),
        Some("success"),
        Some(format!("{node_name} completed.")),
        Some(vec![update]),
    );
    if output.get("toolKind").and_then(Value::as_str) == Some("workflow_tool") {
        let child_run_id = output
            .get("childRunId")
            .and_then(Value::as_str)
            .unwrap_or("child run");
        let child_status = output
            .get("childRunStatus")
            .and_then(Value::as_str)
            .unwrap_or("completed");
        workflow_push_event(
            events,
            run_id,
            thread_id,
            "child_run_completed",
            Some(node_id),
            Some(child_status),
            Some(format!(
                "{node_name} completed child workflow run {child_run_id}."
            )),
            None,
        );
    }
    if *action_kind == ActionKind::Output {
        workflow_push_event(
            events,
            run_id,
            thread_id,
            "output_created",
            Some(node_id),
            Some("success"),
            Some(format!("{node_name} produced an output bundle.")),
            None,
        );
        if output
            .get("outputBundle")
            .and_then(|bundle| bundle.get("materializedAssets"))
            .and_then(Value::as_array)
            .map(|assets| !assets.is_empty())
            .unwrap_or(false)
        {
            workflow_push_event(
                events,
                run_id,
                thread_id,
                "asset_materialized",
                Some(node_id),
                Some("success"),
                Some(format!("{node_name} recorded a materialized asset.")),
                None,
            );
        }
    }
}
