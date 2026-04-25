use super::{
    get_local_sessions, get_local_sessions_with_live_tasks, load_global_checkpoint_blob,
    load_local_engine_control_plane_document, load_session_file_context,
    persisted_workspace_root_for_session, save_local_engine_control_plane,
    save_local_engine_control_plane_document, save_local_session_summary, save_local_task_state,
    save_session_file_context, session_summary_from_task,
    LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME, LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID,
    LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
};
use crate::kernel::file_context::{
    apply_exclude_file_context_path, apply_include_file_context_path,
};
use crate::models::{
    AgentPhase, AgentTask, BuildArtifactSession, ChatCodeWorkerLease,
    LocalEngineConfigMigrationRecord, LocalEngineControlPlaneDocument, SessionFileContext,
    SessionSummary,
};
use crate::open_or_create_memory_runtime;
use ioi_memory::MemoryRuntime;
use serde::Serialize;
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

fn build_session(workspace_root: &str) -> BuildArtifactSession {
    BuildArtifactSession {
        session_id: "build-session".to_string(),
        chat_session_id: "chat-session".to_string(),
        workspace_root: workspace_root.to_string(),
        entry_document: "src/App.tsx".to_string(),
        preview_url: Some("http://127.0.0.1:4173".to_string()),
        preview_process_id: Some(41),
        scaffold_recipe_id: "workspace_surface".to_string(),
        presentation_variant_id: None,
        package_manager: "npm".to_string(),
        build_status: "ready".to_string(),
        verification_status: "ready".to_string(),
        receipts: Vec::new(),
        current_worker_execution: ChatCodeWorkerLease {
            backend: "local".to_string(),
            planner_authority: "runtime".to_string(),
            allowed_mutation_scope: vec!["workspace".to_string()],
            allowed_command_classes: vec!["build".to_string()],
            execution_state: "complete".to_string(),
            retry_classification: None,
            last_summary: Some("Preview verified.".to_string()),
        },
        current_lens: "render".to_string(),
        available_lenses: vec!["render".to_string()],
        ready_lenses: vec!["render".to_string()],
        retry_count: 0,
        last_failure_summary: None,
    }
}

fn task_with_workspace_root(workspace_root: &str) -> AgentTask {
    let mut task = AgentTask {
        id: "task-id".to_string(),
        intent: "Create a workspace artifact for billing settings".to_string(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Complete,
        progress: 4,
        total_steps: 4,
        current_step: "Preview verified and ready".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("session-123".to_string()),
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history: Vec::new(),
        events: Vec::new(),
        artifacts: Vec::new(),
        chat_session: None,
        chat_outcome: None,
        renderer_session: None,
        build_session: Some(build_session(workspace_root)),
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };
    task.sync_runtime_views();
    task
}

fn task_without_workspace_root() -> AgentTask {
    let mut task = task_with_workspace_root("/tmp/unused");
    task.build_session = None;
    task.sync_runtime_views();
    task
}

fn temp_runtime_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("autopilot-store-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("temp runtime dir");
    dir
}

fn save_local_engine_control_plane_value<T: Serialize>(
    memory_runtime: &Arc<MemoryRuntime>,
    value: &T,
) {
    let key = super::global_checkpoint_key(LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME)
        .expect("local engine checkpoint key");
    let bytes = serde_json::to_vec(value).expect("serialize local engine checkpoint value");
    memory_runtime
        .upsert_checkpoint_blob(key, LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME, &bytes)
        .expect("persist local engine checkpoint value");
}

#[test]
fn session_summary_from_task_preserves_existing_title_and_timestamp() {
    let task = task_with_workspace_root("/tmp/workspace");
    let existing = SessionSummary {
        session_id: "session-123".to_string(),
        title: "Existing title".to_string(),
        timestamp: 42,
        phase: Some(AgentPhase::Running),
        current_step: Some("Initializing".to_string()),
        resume_hint: None,
        workspace_root: None,
    };

    let summary = session_summary_from_task(&task, Some(&existing));

    assert_eq!(summary.session_id, "session-123");
    assert_eq!(summary.title, "Existing title");
    assert_eq!(summary.timestamp, 42);
    assert_eq!(summary.phase, Some(AgentPhase::Complete));
    assert_eq!(
        summary.current_step.as_deref(),
        Some("Preview verified and ready")
    );
    assert_eq!(summary.resume_hint.as_deref(), Some("Open workspace"));
    assert_eq!(summary.workspace_root.as_deref(), Some("/tmp/workspace"));
}

#[test]
fn session_summary_from_task_derives_title_when_no_summary_exists() {
    let mut task = task_with_workspace_root("/tmp/workspace");
    task.intent = "Create a React app for a property management dashboard".to_string();

    let summary = session_summary_from_task(&task, None);

    assert_eq!(summary.session_id, "session-123");
    assert_eq!(summary.title, "Create a React app for a pr...");
    assert_eq!(summary.phase, Some(AgentPhase::Complete));
    assert_eq!(summary.resume_hint.as_deref(), Some("Open workspace"));
    assert_eq!(summary.workspace_root.as_deref(), Some("/tmp/workspace"));
}

#[test]
fn session_summary_from_task_preserves_existing_workspace_root() {
    let task = task_without_workspace_root();
    let existing = SessionSummary {
        session_id: "session-123".to_string(),
        title: "Existing title".to_string(),
        timestamp: 42,
        phase: Some(AgentPhase::Running),
        current_step: Some("Initializing".to_string()),
        resume_hint: None,
        workspace_root: Some("/tmp/preserved-root".to_string()),
    };

    let summary = session_summary_from_task(&task, Some(&existing));

    assert_eq!(
        summary.workspace_root.as_deref(),
        Some("/tmp/preserved-root")
    );
}

#[test]
fn live_task_summary_appears_even_when_not_retained_in_session_index() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let mut task = task_with_workspace_root("/tmp/live-workspace");
    task.session_id =
        Some("e65b8f5b1a0f4dc9aa424d9d50a792f5378cda656a5a421fb8d154a2060faa54".to_string());
    task.phase = AgentPhase::Gate;
    task.current_step = "Waiting for clarification.".to_string();

    save_local_task_state(&memory_runtime, &task);
    let summaries = get_local_sessions_with_live_tasks(&memory_runtime);

    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].session_id, task.session_id.clone().unwrap());
    assert_eq!(summaries[0].phase, Some(AgentPhase::Gate));
    assert_eq!(
        summaries[0].workspace_root.as_deref(),
        Some("/tmp/live-workspace")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn save_session_file_context_backfills_existing_session_summary_root() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    save_local_session_summary(
        &memory_runtime,
        SessionSummary {
            session_id: "session-123".to_string(),
            title: "Existing title".to_string(),
            timestamp: 42,
            phase: Some(AgentPhase::Running),
            current_step: Some("Initializing".to_string()),
            resume_hint: None,
            workspace_root: None,
        },
    );

    save_session_file_context(
        &memory_runtime,
        Some("session-123"),
        &SessionFileContext {
            session_id: Some("session-123".to_string()),
            workspace_root: "/tmp/from-file-context".to_string(),
            pinned_files: Vec::new(),
            recent_files: Vec::new(),
            explicit_includes: Vec::new(),
            explicit_excludes: Vec::new(),
            updated_at_ms: 1,
        },
    );

    let saved = get_local_sessions(&memory_runtime);
    assert_eq!(saved.len(), 1);
    assert_eq!(
        saved[0].workspace_root.as_deref(),
        Some("/tmp/from-file-context")
    );
    assert_eq!(
        persisted_workspace_root_for_session(&memory_runtime, Some("session-123")).as_deref(),
        Some("/tmp/from-file-context")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn sequential_session_file_context_saves_preserve_existing_scope_entries() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let workspace_root = "/tmp/workspace";

    save_local_session_summary(
        &memory_runtime,
        SessionSummary {
            session_id: "session-123".to_string(),
            title: "Existing title".to_string(),
            timestamp: 42,
            phase: Some(AgentPhase::Running),
            current_step: Some("Initializing".to_string()),
            resume_hint: None,
            workspace_root: Some(workspace_root.to_string()),
        },
    );

    let mut initial =
        load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
    apply_include_file_context_path(&mut initial, "docs").expect("include docs");
    initial.updated_at_ms = 1;
    save_session_file_context(&memory_runtime, Some("session-123"), &initial);

    let mut reloaded =
        load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
    assert_eq!(reloaded.explicit_includes, vec!["docs"]);
    assert!(reloaded.explicit_excludes.is_empty());

    apply_exclude_file_context_path(&mut reloaded, "target").expect("exclude target");
    reloaded.updated_at_ms = 2;
    save_session_file_context(&memory_runtime, Some("session-123"), &reloaded);

    let final_context =
        load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
    assert_eq!(final_context.explicit_includes, vec!["docs"]);
    assert_eq!(final_context.explicit_excludes, vec!["target"]);
    assert_eq!(final_context.recent_files, vec!["target", "docs"]);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_local_engine_control_plane_rejects_legacy_unversioned_payload() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let control_plane = crate::kernel::data::default_local_engine_control_plane();
    let legacy_value = json!({
        "runtime": control_plane.runtime.clone(),
        "storage": control_plane.storage.clone(),
        "watchdog": control_plane.watchdog.clone(),
        "memory": control_plane.memory.clone(),
        "backendPolicy": control_plane.backend_policy.clone(),
        "responses": control_plane.responses.clone(),
        "api": control_plane.api.clone(),
        "galleries": control_plane.galleries.clone(),
        "environment": control_plane.environment.clone()
    });
    save_local_engine_control_plane_value(&memory_runtime, &legacy_value);

    assert!(load_local_engine_control_plane_document(&memory_runtime).is_none());
    assert!(load_local_engine_control_plane(&memory_runtime).is_none());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn save_local_engine_control_plane_preserves_existing_profile_and_migrations() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let control_plane = crate::kernel::data::default_local_engine_control_plane();
    save_local_engine_control_plane_document(
        &memory_runtime,
        &LocalEngineControlPlaneDocument {
            schema_version: LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
            profile_id: "custom.profile".to_string(),
            migrations: vec![LocalEngineConfigMigrationRecord {
                migration_id: "legacy.seed".to_string(),
                from_version: 0,
                to_version: 1,
                applied_at_ms: 7,
                summary: "Imported legacy seed profile.".to_string(),
                details: vec!["Preserve this history across later saves.".to_string()],
            }],
            control_plane: control_plane.clone(),
        },
    );

    let mut updated = control_plane;
    updated.runtime.default_model = "gpt-4.1-mini".to_string();
    save_local_engine_control_plane(&memory_runtime, &updated);

    let saved = load_local_engine_control_plane_document(&memory_runtime)
        .expect("saved control plane document");
    assert_eq!(saved.profile_id, "custom.profile");
    assert_eq!(
        saved.schema_version,
        LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION
    );
    assert_eq!(saved.migrations.len(), 1);
    assert_eq!(saved.migrations[0].migration_id, "legacy.seed");
    assert_eq!(saved.control_plane.runtime.default_model, "gpt-4.1-mini");

    let _ = fs::remove_dir_all(dir);
}
