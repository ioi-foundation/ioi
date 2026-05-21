use super::*;
use crate::kernel::knowledge::{add_knowledge_text_entry, create_knowledge_collection};
use crate::models::{AgentPhase, AppState};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use std::collections::HashSet;
use std::sync::Mutex;
use tauri::{test::mock_app, Manager};
use uuid::Uuid;

fn temp_memory_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("runtime-parity-{}-{}", label, Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("temp memory dir should exist");
    dir
}

fn sample_task(session_id: &str, intent: &str) -> AgentTask {
    AgentTask {
        id: session_id.to_string(),
        intent: intent.to_string(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Running,
        progress: 1,
        total_steps: 4,
        current_step: "Wiring parity smoke coverage".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some(session_id.to_string()),
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history: vec![ChatMessage {
            role: "agent".to_string(),
            text: "1. Add browser coverage\n2. Add filesystem coverage\n3. Run focused validation"
                .to_string(),
            timestamp: 1,
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

#[tokio::test(flavor = "current_thread")]
async fn sync_planning_artifacts_materializes_expected_files_once() {
    let app = mock_app();
    let memory_dir = temp_memory_dir("planning");
    let memory_runtime =
        Arc::new(crate::open_or_create_memory_runtime(&memory_dir).expect("memory runtime"));
    let thread_id = format!("planning-{}", Uuid::new_v4());
    let mut task = sample_task(
        &thread_id,
        &format!(
            "{}\nExecute the parity smoke coverage plan end to end.",
            PLAN_MODE_DIRECTIVE
        ),
    );

    sync_planning_artifacts(&app.handle().clone(), &memory_runtime, &mut task)
        .expect("planning artifacts should sync");
    sync_planning_artifacts(&app.handle().clone(), &memory_runtime, &mut task)
        .expect("planning artifacts should stay idempotent");

    let planning_root =
        conversation_artifact_root(&app.handle().clone(), &thread_id).join("planning");
    let implementation_plan = planning_root.join("implementation_plan.md");
    let task_tracker = planning_root.join("task.md");
    let walkthrough = planning_root.join("walkthrough.md");

    let implementation_text =
        fs::read_to_string(&implementation_plan).expect("implementation plan should exist");
    let task_text = fs::read_to_string(&task_tracker).expect("task tracker should exist");
    let walkthrough_text = fs::read_to_string(&walkthrough).expect("walkthrough should exist");

    assert!(implementation_text.contains("# Implementation Plan"));
    assert!(task_text.contains("# Task Tracker"));
    assert!(walkthrough_text.contains("# Walkthrough"));
    assert_eq!(task.artifacts.len(), 3);
    assert_eq!(
        task.history
            .iter()
            .filter(|message| {
                message.role == "system" && message.text.contains("Planning artifacts ready")
            })
            .count(),
        1
    );

    let _ = fs::remove_dir_all(conversation_artifact_root(
        &app.handle().clone(),
        &thread_id,
    ));
    let _ = fs::remove_dir_all(memory_dir);
}

#[tokio::test(flavor = "current_thread")]
async fn inject_ambient_knowledge_materializes_summary_and_prompt_prefix() {
    let app = mock_app();
    let memory_dir = temp_memory_dir("knowledge");
    let memory_runtime =
        Arc::new(crate::open_or_create_memory_runtime(&memory_dir).expect("memory runtime"));
    let inference_runtime: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime::default());
    let mut app_state = AppState::default();
    app_state.memory_runtime = Some(memory_runtime.clone());
    app_state.inference_runtime = Some(inference_runtime.clone());
    app.manage(Mutex::new(app_state));

    let collection = create_knowledge_collection(
        app.state::<Mutex<AppState>>(),
        "IOI Runtime Notes".to_string(),
        Some("Parity hints for runtime smoke coverage".to_string()),
    )
    .await
    .expect("knowledge collection should be created");
    let entry = add_knowledge_text_entry(
        app.state::<Mutex<AppState>>(),
        collection.collection_id.clone(),
        "Browser subagent resume contract".to_string(),
        "The browser subagent accepts reused_subagent_id, returns one final report, and may pause when approval blockers stop completion.".to_string(),
    )
    .await
    .expect("knowledge entry should be added");

    let thread_id = format!("knowledge-{}", Uuid::new_v4());
    let injection = inject_ambient_knowledge(
        &app.handle().clone(),
        &memory_runtime,
        &inference_runtime,
        &thread_id,
        "browser subagent approval blocker final report resume contract",
    )
    .await
    .expect("knowledge injection should succeed")
    .expect("knowledge injection should return context");

    let knowledge_root =
        conversation_artifact_root(&app.handle().clone(), &thread_id).join("knowledge");
    let summary_path = knowledge_root.join(KI_SUMMARY_FILENAME);
    let entry_path = knowledge_root
        .join(&collection.collection_id)
        .join(format!("{}-text.md", entry.entry_id));
    let summary_text = fs::read_to_string(&summary_path).expect("summary file should exist");
    let entry_text = fs::read_to_string(&entry_path).expect("entry file should exist");

    assert!(summary_text.contains("# Active Knowledge Context"));
    assert!(summary_text.contains("Browser subagent resume contract"));
    assert!(entry_text.contains("reused_subagent_id"));
    assert!(injection
        .prompt_prefix
        .contains("ACTIVE KNOWLEDGE ITEM SUMMARIES"));
    assert!(injection
        .prompt_prefix
        .contains("Browser subagent resume contract"));
    assert!(injection
        .announcement
        .contains("Loaded 1 knowledge items into session context"));
    let expected_summary_path = slash_path(&summary_path);
    assert_eq!(
        injection.summary_artifact.metadata["path"].as_str(),
        Some(expected_summary_path.as_str())
    );

    let _ = fs::remove_dir_all(conversation_artifact_root(
        &app.handle().clone(),
        &thread_id,
    ));
    let _ = fs::remove_dir_all(memory_dir);
}
