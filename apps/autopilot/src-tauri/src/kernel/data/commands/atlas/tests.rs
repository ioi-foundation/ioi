use super::*;
use chrono::TimeZone;
use serde_json::json;
use std::{fs, sync::Arc};
use uuid::Uuid;

fn parent_playbook_event(
    event_id: &str,
    timestamp_ms: u64,
    playbook: &crate::models::LocalEngineAgentPlaybookRecord,
    phase: &str,
    status: &str,
    success: bool,
    step: Option<&crate::models::LocalEngineAgentPlaybookStepRecord>,
    child_session_id: Option<&str>,
    summary: &str,
    artifact_ids: &[&str],
    error_class: Option<&str>,
) -> crate::models::AgentEvent {
    crate::models::AgentEvent {
        event_id: event_id.to_string(),
        timestamp: chrono::Utc
            .timestamp_millis_opt(timestamp_ms as i64)
            .single()
            .expect("timestamp should be valid")
            .to_rfc3339(),
        thread_id: "session-parent".to_string(),
        step_index: 1,
        event_type: crate::models::EventType::Receipt,
        title: format!("{} {}", phase, playbook.label.as_str()),
        digest: json!({
            "kind": "parent_playbook",
            "tool_name": if phase == "step_spawned" { "agent__delegate" } else { "agent__await" },
            "phase": phase,
            "playbook_id": playbook.playbook_id.clone(),
            "playbook_label": playbook.label.clone(),
            "status": status,
            "success": success,
            "error_class": error_class,
        }),
        details: json!({
            "timestamp_ms": timestamp_ms,
            "parent_session_id": "session-parent",
            "step_id": step.map(|entry| entry.step_id.clone()),
            "step_label": step.map(|entry| entry.label.clone()),
            "child_session_id": child_session_id,
            "template_id": step.map(|entry| entry.worker_template_id.clone()),
            "workflow_id": step.map(|entry| entry.worker_workflow_id.clone()),
            "summary": summary,
        }),
        artifact_refs: artifact_ids
            .iter()
            .map(|artifact_id| crate::models::ArtifactRef {
                artifact_id: (*artifact_id).to_string(),
                artifact_type: crate::models::ArtifactType::Report,
            })
            .collect(),
        receipt_ref: Some(format!("receipt::{}", event_id)),
        input_refs: Vec::new(),
        status: if success {
            crate::models::EventStatus::Success
        } else {
            crate::models::EventStatus::Failure
        },
        duration_ms: None,
    }
}

#[test]
fn default_worker_templates_expose_researcher_contract() {
    let templates = default_worker_templates();
    assert_eq!(templates.len(), 9);
    let researcher = templates
        .iter()
        .find(|template| template.template_id == "researcher")
        .expect("researcher template should exist");
    assert_eq!(researcher.template_id, "researcher");
    assert_eq!(researcher.role, "Research Worker");
    assert_eq!(
        researcher.completion_contract.merge_mode,
        "append_summary_to_parent"
    );
    assert!(templates
        .iter()
        .any(|template| template.template_id == "context_worker"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "perception_worker"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "verifier"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "coder"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "patch_synthesizer"));
    assert!(researcher
        .allowed_tools
        .iter()
        .any(|tool| tool == "web__search"));
    assert!(researcher
        .completion_contract
        .expected_output
        .contains("research brief"));
    assert!(researcher
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "live_research_brief"));
    let verifier = templates
        .iter()
        .find(|template| template.template_id == "verifier")
        .expect("verifier template should exist");
    let verifier_workflow = verifier
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "postcondition_audit")
        .expect("verifier workflow should exist");
    assert_eq!(verifier_workflow.default_budget, Some(48));
    assert_eq!(verifier_workflow.max_retries, Some(0));
    assert!(verifier_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "model__rerank"));
    assert!(verifier
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "browser_postcondition_audit"));
    assert!(verifier
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "citation_audit"));
    assert!(verifier
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "artifact_validation_audit"));
    assert!(verifier
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "targeted_test_audit"));
    let context_worker = templates
        .iter()
        .find(|template| template.template_id == "context_worker")
        .expect("context_worker template should exist");
    assert!(context_worker
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "artifact_context_brief"));
    let coder = templates
        .iter()
        .find(|template| template.template_id == "coder")
        .expect("coder template should exist");
    let coder_workflow = coder
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "patch_build_verify")
        .expect("coder workflow should exist");
    assert_eq!(coder_workflow.default_budget, Some(96));
    assert_eq!(coder_workflow.max_retries, Some(1));
    assert!(coder_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__edit"));
    assert!(coder_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "shell__start"));
    assert!(coder_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "agent__complete"));
}

#[test]
fn load_or_initialize_worker_templates_persists_defaults() {
    let data_dir = std::env::temp_dir().join(format!(
        "autopilot-worker-template-tests-{}",
        Uuid::new_v4()
    ));

    let result = (|| -> Result<(), String> {
        let runtime = Arc::new(crate::open_or_create_memory_runtime(&data_dir)?);
        let templates = load_or_initialize_worker_templates(&runtime);
        assert_eq!(templates.len(), 9);
        assert!(templates
            .iter()
            .any(|template| template.template_id == "researcher"));

        let persisted = orchestrator::load_worker_templates(&runtime);
        assert_eq!(persisted.len(), 9);
        assert!(persisted
            .iter()
            .any(|template| template.template_id == "researcher"));
        assert_eq!(
            persisted
                .iter()
                .find(|template| template.template_id == "researcher")
                .expect("persisted researcher template should exist")
                .completion_contract
                .merge_mode,
            "append_summary_to_parent"
        );
        Ok(())
    })();

    let _ = fs::remove_dir_all(&data_dir);
    result.unwrap();
}

#[test]
fn default_agent_playbooks_expose_evidence_audited_patch_contract() {
    let playbooks = default_agent_playbooks();
    assert_eq!(playbooks.len(), 5);
    let playbook = playbooks
        .iter()
        .find(|entry| entry.playbook_id == "evidence_audited_patch")
        .expect("evidence-audited patch playbook should exist");
    assert_eq!(playbook.default_budget, 196);
    assert_eq!(playbook.route_family, "coding");
    assert_eq!(playbook.topology, "planner_specialist_verifier");
    assert_eq!(
        playbook.completion_contract.merge_mode,
        "append_summary_to_parent"
    );
    assert!(playbook
        .trigger_intents
        .iter()
        .any(|intent| intent == "workspace.ops"));
    assert_eq!(playbook.steps.len(), 4);
    assert_eq!(playbook.steps[0].worker_template_id, "context_worker");
    assert_eq!(playbook.steps[1].worker_workflow_id, "patch_build_verify");
    assert_eq!(playbook.steps[2].worker_workflow_id, "targeted_test_audit");
    assert_eq!(
        playbook.steps[3].worker_workflow_id,
        "patch_synthesis_handoff"
    );
}

#[test]
fn default_agent_playbooks_expose_artifact_generation_gate_contract() {
    let playbook = default_agent_playbooks()
        .into_iter()
        .find(|entry| entry.playbook_id == "artifact_generation_gate")
        .expect("artifact_generation_gate playbook should exist");
    assert_eq!(playbook.default_budget, 196);
    assert_eq!(playbook.route_family, "artifacts");
    assert_eq!(playbook.topology, "planner_specialist_verifier");
    assert_eq!(playbook.steps.len(), 3);
    assert_eq!(playbook.steps[0].worker_template_id, "context_worker");
    assert_eq!(
        playbook.steps[0].worker_workflow_id,
        "artifact_context_brief"
    );
    assert_eq!(playbook.steps[1].worker_template_id, "artifact_builder");
    assert_eq!(
        playbook.steps[1].worker_workflow_id,
        "artifact_generate_repair"
    );
    assert_eq!(playbook.steps[2].worker_template_id, "verifier");
    assert_eq!(
        playbook.steps[2].worker_workflow_id,
        "artifact_validation_audit"
    );
}

#[test]
fn parent_playbook_projection_tracks_live_step_status_and_receipts() {
    let playbook = default_agent_playbooks()
        .into_iter()
        .find(|entry| entry.playbook_id == "evidence_audited_patch")
        .expect("expected evidence_audited_patch playbook");
    let playbook_specs = std::iter::once((playbook.playbook_id.clone(), playbook.clone()))
        .collect::<BTreeMap<_, _>>();
    let context_step = playbook
        .steps
        .first()
        .expect("context step should exist")
        .clone();
    let coder_step = playbook
        .steps
        .get(1)
        .expect("coder step should exist")
        .clone();

    let events = vec![
        parent_playbook_event(
            "receipt-1",
            1_000,
            &playbook,
            "started",
            "running",
            true,
            None,
            None,
            "Started evidence-audited patch run.",
            &[],
            None,
        ),
        parent_playbook_event(
            "receipt-2",
            1_100,
            &playbook,
            "step_spawned",
            "running",
            true,
            Some(&context_step),
            Some("child-context"),
            "Spawned context step.",
            &[],
            None,
        ),
        parent_playbook_event(
            "receipt-3",
            1_250,
            &playbook,
            "step_completed",
            "running",
            true,
            Some(&context_step),
            Some("child-context"),
            "Context brief merged into parent context.",
            &["artifact-context"],
            None,
        ),
        parent_playbook_event(
            "receipt-4",
            1_400,
            &playbook,
            "step_spawned",
            "running",
            true,
            Some(&coder_step),
            Some("child-coder"),
            "Spawned coder step.",
            &[],
            None,
        ),
    ];

    let mut runs = BTreeMap::new();
    ingest_parent_playbook_events("session-parent", &events, &playbook_specs, &mut runs);

    let projected = runs
        .remove("session-parent:evidence_audited_patch")
        .expect("projection should exist");
    assert_eq!(projected.status, "running");
    assert_eq!(projected.latest_phase, "step_spawned");
    assert_eq!(
        projected.current_step_id.as_deref(),
        Some(coder_step.step_id.as_str())
    );
    assert_eq!(
        projected.active_child_session_id.as_deref(),
        Some("child-coder")
    );
    assert_eq!(projected.steps.len(), 4);

    let projected_context = projected
        .steps
        .iter()
        .find(|step| step.step_id == context_step.step_id)
        .expect("projected context step should exist");
    assert_eq!(projected_context.status, "completed");
    assert_eq!(projected_context.receipts.len(), 2);
    assert_eq!(
        projected_context
            .receipts
            .last()
            .expect("latest context receipt should exist")
            .artifact_ids,
        vec!["artifact-context".to_string()]
    );

    let projected_coder = projected
        .steps
        .iter()
        .find(|step| step.step_id == coder_step.step_id)
        .expect("projected coder step should exist");
    assert_eq!(projected_coder.status, "running");
    assert_eq!(
        projected_coder.child_session_id.as_deref(),
        Some("child-coder")
    );
}

#[test]
fn visible_parent_playbook_runs_hide_and_restore_dismissed_runs() {
    let data_dir = std::env::temp_dir().join(format!(
        "autopilot-parent-playbook-dismissal-tests-{}",
        Uuid::new_v4()
    ));

    let result = (|| -> Result<(), String> {
        let runtime = Arc::new(crate::open_or_create_memory_runtime(&data_dir)?);
        let playbook = default_agent_playbooks()
            .into_iter()
            .find(|entry| entry.playbook_id == "evidence_audited_patch")
            .expect("expected evidence_audited_patch playbook");
        let sessions = vec![crate::models::SessionSummary {
            session_id: "session-parent".to_string(),
            title: "Parent playbook session".to_string(),
            timestamp: 1_000,
            phase: None,
            current_step: None,
            resume_hint: None,
            workspace_root: None,
        }];
        orchestrator::save_local_session_summary(&runtime, sessions[0].clone());
        orchestrator::append_event(
            &runtime,
            &parent_playbook_event(
                "receipt-started",
                1_000,
                &playbook,
                "started",
                "running",
                true,
                None,
                None,
                "Started evidence-audited patch run.",
                &[],
                None,
            ),
        );

        let playbooks = vec![playbook];
        let visible_before = visible_parent_playbook_runs(&runtime, &sessions, &playbooks);
        assert_eq!(visible_before.len(), 1);

        persist_parent_playbook_dismissal(
            &runtime,
            "session-parent:evidence_audited_patch",
            true,
        );
        let visible_after_dismiss =
            visible_parent_playbook_runs(&runtime, &sessions, &playbooks);
        assert!(visible_after_dismiss.is_empty());

        persist_parent_playbook_dismissal(
            &runtime,
            "session-parent:evidence_audited_patch",
            false,
        );
        let visible_after_restore =
            visible_parent_playbook_runs(&runtime, &sessions, &playbooks);
        assert_eq!(visible_after_restore.len(), 1);
        Ok(())
    })();

    let _ = fs::remove_dir_all(&data_dir);
    result.unwrap();
}

#[test]
fn parent_playbook_projection_reopens_step_on_operator_resume_request() {
    let playbook = default_agent_playbooks()
        .into_iter()
        .find(|entry| entry.playbook_id == "evidence_audited_patch")
        .expect("expected evidence_audited_patch playbook");
    let playbook_specs = std::iter::once((playbook.playbook_id.clone(), playbook.clone()))
        .collect::<BTreeMap<_, _>>();
    let coder_step = playbook
        .steps
        .get(1)
        .expect("coder step should exist")
        .clone();

    let events = vec![
        parent_playbook_event(
            "receipt-1",
            1_000,
            &playbook,
            "step_spawned",
            "running",
            true,
            Some(&coder_step),
            Some("child-coder"),
            "Spawned coder step.",
            &[],
            None,
        ),
        parent_playbook_event(
            "receipt-2",
            1_150,
            &playbook,
            "blocked",
            "blocked",
            false,
            Some(&coder_step),
            Some("child-coder"),
            "Coder step stalled on validation.",
            &[],
            Some("compile_error"),
        ),
        parent_playbook_event(
            "receipt-3",
            1_250,
            &playbook,
            "operator_resume_requested",
            "running",
            true,
            Some(&coder_step),
            Some("child-coder"),
            "Operator requested resume from the coder step.",
            &[],
            None,
        ),
    ];

    let mut runs = BTreeMap::new();
    ingest_parent_playbook_events("session-parent", &events, &playbook_specs, &mut runs);

    let projected = runs
        .remove("session-parent:evidence_audited_patch")
        .expect("projection should exist");
    let projected_coder = projected
        .steps
        .iter()
        .find(|step| step.step_id == coder_step.step_id)
        .expect("projected coder step should exist");

    assert_eq!(projected.status, "running");
    assert_eq!(projected.latest_phase, "operator_resume_requested");
    assert_eq!(
        projected.current_step_id.as_deref(),
        Some(coder_step.step_id.as_str())
    );
    assert_eq!(
        projected.active_child_session_id.as_deref(),
        Some("child-coder")
    );
    assert_eq!(projected_coder.status, "running");
    assert_eq!(projected_coder.error_class, None);
    assert_eq!(projected_coder.receipts.len(), 3);
}
