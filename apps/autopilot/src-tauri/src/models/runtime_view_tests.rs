use super::*;
use std::collections::HashSet;

fn sample_task(phase: AgentPhase) -> AgentTask {
    AgentTask {
        id: "task-1".to_string(),
        intent: "Prepare release checklist".to_string(),
        agent: "Autopilot".to_string(),
        phase,
        progress: 0,
        total_steps: 3,
        current_step: "Inspecting retained output".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("task-1".to_string()),
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history: vec![ChatMessage {
            role: "agent".to_string(),
            text: "Drafted the first pass of the checklist.".to_string(),
            timestamp: 0,
        }],
        events: Vec::new(),
        artifacts: Vec::new(),
        chat_session: None,
        chat_outcome: None,
        renderer_session: None,
        build_session: None,
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        work_graph_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    }
}

#[test]
fn sync_runtime_views_marks_clarification_as_blocked() {
    let mut task = sample_task(AgentPhase::Complete);
    task.clarification_request = Some(ClarificationRequest {
        kind: "intent_resolution".to_string(),
        question: "Which release branch should I target?".to_string(),
        tool_name: "AskUserQuestion".to_string(),
        failure_class: None,
        evidence_snippet: None,
        context_hint: None,
        options: Vec::new(),
        allow_other: true,
    });

    task.sync_runtime_views();

    assert!(task
        .session_checklist
        .iter()
        .any(|item| item.item_id == "clarification" && item.status == "blocked"));
    assert_eq!(task.background_tasks[0].status, "blocked");
}

#[test]
fn sync_runtime_views_exposes_latest_output_for_completed_tasks() {
    let mut task = sample_task(AgentPhase::Complete);
    task.sync_runtime_views();

    assert!(task
        .session_checklist
        .iter()
        .any(|item| item.item_id == "review" && item.status == "completed"));
    assert_eq!(
        task.background_tasks[0].latest_output.as_deref(),
        Some("Drafted the first pass of the checklist.")
    );
}

#[test]
fn sync_runtime_views_hides_raw_install_receipt_in_latest_output() {
    let mut task = sample_task(AgentPhase::Failed);
    task.current_step = r#"Task failed: ERROR_CLASS=InstallerResolutionRequired {"summary":"No verified install candidate passed resolver policy for 'snorflepaint'.","install_event":{"stage":"unresolved"}}
install_resolution_stage=unresolved install_display_name=snorflepaint"#.to_string();
    task.history = vec![ChatMessage {
        role: "system".to_string(),
        text: r#"Task Failed: ERROR_CLASS=InstallerResolutionRequired {"summary":"No verified install candidate passed resolver policy for 'snorflepaint'.","install_event":{"stage":"unresolved"}}
install_resolution_stage=unresolved install_display_name=snorflepaint"#.to_string(),
        timestamp: 0,
    }];

    task.sync_runtime_views();

    let output = task.background_tasks[0]
        .latest_output
        .as_deref()
        .expect("latest output");
    assert!(output.starts_with("Install blocked: No verified install candidate"));
    assert!(!output.contains("ERROR_CLASS"));
}

#[test]
fn agent_task_accepts_legacy_swarm_tree_payloads() {
    let mut payload = serde_json::to_value(sample_task(AgentPhase::Running)).unwrap();
    let object = payload.as_object_mut().unwrap();
    object.remove("work_graph_tree");
    object.insert(
        "swarm_tree".to_string(),
        serde_json::json!([
            {
                "id": "worker-1",
                "parent_id": null,
                "name": "Investigator",
                "role": "Read relevant files",
                "status": "completed",
                "budget_used": 1.0,
                "budget_cap": 3.0,
                "current_thought": "Captured evidence",
                "artifacts_produced": 2,
                "estimated_cost": 0.12,
                "policy_hash": "policy:test"
            }
        ]),
    );

    let decoded: AgentTask = serde_json::from_value(payload).unwrap();

    assert_eq!(decoded.work_graph_tree.len(), 1);
    assert_eq!(decoded.work_graph_tree[0].id, "worker-1");
    assert_eq!(decoded.work_graph_tree[0].role, "Read relevant files");
}
