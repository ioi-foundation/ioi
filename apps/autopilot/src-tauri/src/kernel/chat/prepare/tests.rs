use super::places::places_request_for_tool_widget;
use crate::models::ChatOutcomeRequest;
use ioi_types::app::chat::{ChatNormalizedRequest, ChatOutcomeKind, ChatPlacesRequestFrame};
use ioi_types::app::ChatExecutionStrategy;
use std::fs;

fn places_outcome_request(frame: Option<ChatPlacesRequestFrame>) -> ChatOutcomeRequest {
    ChatOutcomeRequest {
        request_id: "places-request".to_string(),
        raw_prompt: "Find coffee shops open now.".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::ToolWidget,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec!["tool_widget:places".to_string()],
        lane_request: None,
        normalized_request: frame.map(ChatNormalizedRequest::Places),
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    }
}

#[test]
fn places_request_for_tool_widget_prefers_normalized_request_state() {
    let outcome_request = places_outcome_request(Some(ChatPlacesRequestFrame {
        search_anchor: None,
        category: Some("coffee shops".to_string()),
        location_scope: Some("Williamsburg, Brooklyn".to_string()),
        missing_slots: Vec::new(),
        clarification_required_slots: Vec::new(),
    }));

    let parsed = places_request_for_tool_widget("Near Williamsburg, Brooklyn.", &outcome_request)
        .expect("retained places request");

    assert_eq!(parsed.category.label, "coffee shops");
    assert_eq!(parsed.category.amenity, "cafe");
    assert_eq!(parsed.anchor_phrase, "Williamsburg, Brooklyn");
}

#[test]
fn workspace_grounding_sources_select_real_task_state_files() {
    let root =
        std::env::temp_dir().join(format!("autopilot-grounding-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("apps/autopilot/src-tauri/src/kernel/chat")).expect("chat dir");
    fs::create_dir_all(root.join("apps/autopilot/src-tauri/src/models")).expect("models dir");
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").expect("cargo");
    fs::write(root.join("package.json"), "{\"name\":\"test\"}\n").expect("package");
    fs::write(
        root.join("apps/autopilot/src-tauri/src/kernel/chat/task_state.rs"),
        "pub fn verified_reply_summary_for_task() {}\npub fn task_requires_chat_primary_execution() {}\n",
    )
    .expect("task state");
    fs::write(
        root.join("apps/autopilot/src-tauri/src/models/session.rs"),
        "pub struct AgentTask { pub chat_session: Option<ChatArtifactSession> }\n",
    )
    .expect("session");
    fs::write(
        root.join("apps/autopilot/src-tauri/src/models/chat.rs"),
        "pub struct ChatArtifactSession { pub verified_reply: ChatVerifiedReply }\n",
    )
    .expect("chat model");

    let sources = super::select_workspace_grounding_sources(
        &root,
        "Where is Autopilot chat task state defined? Cite the files you used.",
    );

    let paths = sources
        .iter()
        .map(|source| source.relative_path.as_str())
        .collect::<Vec<_>>();
    assert!(paths
        .iter()
        .any(|path| *path == "apps/autopilot/src-tauri/src/kernel/chat/task_state.rs"));
    assert!(paths
        .iter()
        .any(|path| *path == "apps/autopilot/src-tauri/src/models/session.rs"));
    assert!(paths
        .iter()
        .any(|path| *path == "apps/autopilot/src-tauri/src/models/chat.rs"));

    let rendered = super::render_workspace_grounded_reply(
        "Where is Autopilot chat task state defined? Cite the files you used.",
        &sources,
    );
    assert!(rendered.contains("task_state.rs"));
    assert!(rendered.contains("models/session.rs"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn workspace_grounding_prefers_explicit_file_reference() {
    let root = std::env::temp_dir().join(format!(
        "autopilot-explicit-file-grounding-test-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("nested")).expect("nested");
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").expect("cargo");
    fs::write(
        root.join("package.json"),
        "{\n  \"name\": \"ioi-network-monorepo\",\n  \"private\": true\n}\n",
    )
    .expect("package");
    fs::write(
        root.join("nested/package-lock.json"),
        "{\n  \"name\": \"wrong-package-lock\",\n  \"packages\": {}\n}\n",
    )
    .expect("package lock");

    let sources = super::select_workspace_grounding_sources(
        &root,
        "Read package.json and tell me the package name.",
    );

    assert_eq!(sources[0].relative_path, "package.json");
    assert!(sources[0].excerpt.contains("ioi-network-monorepo"));

    let rendered = super::render_workspace_grounded_reply(
        "Read package.json and tell me the package name.",
        &sources,
    );
    assert!(rendered.contains("`ioi-network-monorepo`"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn runtime_contract_grounding_ignores_example_noise_for_stopcondition_plan() {
    let root = std::env::temp_dir().join(format!(
        "autopilot-runtime-grounding-test-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("crates/types/src/app")).expect("types dir");
    fs::create_dir_all(root.join("crates/services/src/agentic/runtime")).expect("runtime dir");
    fs::create_dir_all(root.join("examples/noisy")).expect("examples dir");
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").expect("cargo");
    fs::write(root.join("package.json"), "{\"name\":\"test\"}\n").expect("package");
    fs::write(
        root.join("crates/types/src/app/runtime_contracts.rs"),
        "pub struct StopCondition; pub struct AgentRuntimeEvent; pub struct RuntimeExecutionEnvelope;\n",
    )
    .expect("contracts");
    fs::write(
        root.join("crates/services/src/agentic/runtime/substrate.rs"),
        "pub struct RuntimeSubstrateSnapshot; pub fn stop_condition_projection() {}\n",
    )
    .expect("substrate");
    fs::write(
        root.join("examples/noisy/add-button.test.ts"),
        "it('enables add button support', async () => {});\n",
    )
    .expect("noise");

    let sources = super::select_workspace_grounding_sources(
        &root,
        "Plan how to add StopCondition support, but do not edit files.",
    );

    assert!(!sources.is_empty());
    assert!(sources
        .iter()
        .all(|source| super::runtime_contract_grounding_source(&source.relative_path)));
    assert!(sources
        .iter()
        .all(|source| !source.relative_path.starts_with("examples/")));

    let rendered = super::render_workspace_grounded_reply(
        "Plan how to add StopCondition support, but do not edit files.",
        &sources,
    );
    assert!(sources
        .iter()
        .any(|source| source.relative_path.ends_with("runtime_contracts.rs")));
    assert!(!rendered.contains("Sources used:"));
    assert!(!rendered.contains("examples/noisy"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn runtime_lifecycle_grounded_reply_renders_mermaid_sequence_diagram() {
    let sources = vec![super::WorkspaceGroundingSource {
        relative_path: "crates/types/src/app/runtime_contracts.rs".to_string(),
        line: 1,
        excerpt: "pub struct AgentRuntimeEvent;".to_string(),
        score: 100,
    }];

    let rendered = super::render_workspace_grounded_reply(
        "Show the agent runtime event lifecycle as a Mermaid sequence diagram.",
        &sources,
    );

    assert!(rendered.starts_with("```mermaid\nsequenceDiagram"));
    assert!(rendered.contains("RuntimeExecutionEnvelope"));
    assert!(rendered.contains("TraceBundle"));
}

#[test]
fn harness_probe_grounded_reply_includes_uncertainty_and_probe() {
    let sources = vec![super::WorkspaceGroundingSource {
        relative_path: "scripts/run-autopilot-gui-harness-validation.mjs".to_string(),
        line: 1,
        excerpt: "AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop".to_string(),
        score: 100,
    }];

    let rendered = super::render_workspace_grounded_reply(
        "Find the cheapest way to verify whether desktop chat sources render.",
        &sources,
    );

    assert!(rendered.contains("UncertaintyAssessment"));
    assert!(rendered.contains("Probe"));
    assert!(!rendered.contains("Sources used:"));
    assert!(rendered.contains("run-autopilot-gui-harness-validation.mjs"));
}

#[test]
fn chat_ux_grounded_reply_cites_sources() {
    let sources = vec![super::WorkspaceGroundingSource {
        relative_path: "docs/specs/runtime/agent-runtime-parity-plus-master-guide.md".to_string(),
        line: 2448,
        excerpt:
            "| Chat UX | Final answer is primary; Markdown, Mermaid, collapsible work summaries, and source chips render cleanly without raw receipt dumps, facts dashboards, or default evidence drawers. |"
                .to_string(),
        score: 100,
    }];

    let rendered = super::render_workspace_grounded_reply(
        "Using repo docs, summarize the chat UX contract and cite sources.",
        &sources,
    );

    assert!(rendered.contains("answer-first"));
    assert!(rendered.contains("collapsed explored-files disclosure"));
    assert!(!rendered.contains("Sources used:"));
}

#[test]
fn harness_validation_grounded_reply_cites_harness_sources() {
    let sources = vec![super::WorkspaceGroundingSource {
        relative_path: "scripts/run-autopilot-gui-harness-validation.mjs".to_string(),
        line: 313,
        excerpt: "async function collectRuntimeArtifacts(outputRoot, logPath) {".to_string(),
        score: 100,
    }];

    let rendered = super::render_workspace_grounded_reply(
        "Validate this answer path through the harness and explain the result.",
        &sources,
    );

    assert!(rendered.contains("GUI harness"));
    assert!(rendered.contains("scorecard"));
    assert!(!rendered.contains("Sources used:"));
}

#[test]
fn workspace_grounding_skips_old_validation_evidence_bundles() {
    let root = std::env::temp_dir().join(format!(
        "autopilot-grounding-evidence-skip-test-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("docs/evidence/autopilot-gui-harness-validation"))
        .expect("evidence dir");
    fs::create_dir_all(root.join("scripts")).expect("scripts dir");
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").expect("cargo");
    fs::write(root.join("package.json"), "{\"name\":\"test\"}\n").expect("package");
    fs::write(
        root.join("docs/evidence/autopilot-gui-harness-validation/result.json"),
        "\"query\": \"Find the cheapest way to verify whether desktop chat sources render.\"",
    )
    .expect("old evidence");
    fs::write(
        root.join("scripts/run-autopilot-gui-harness-validation.mjs"),
        "AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop\nselected_sources scorecard stop_reason quality_ledger\n",
    )
    .expect("harness script");

    let sources = super::select_workspace_grounding_sources(
        &root,
        "Find the cheapest way to verify whether desktop chat sources render.",
    );

    assert!(sources
        .iter()
        .any(|source| source.relative_path == "scripts/run-autopilot-gui-harness-validation.mjs"));
    assert!(sources
        .iter()
        .all(|source| !source.relative_path.starts_with("docs/evidence/")));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn workspace_grounding_skips_generated_artifact_dirs_for_overview() {
    let root = std::env::temp_dir().join(format!(
        "autopilot-grounding-artifact-skip-test-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".artifacts/generated/doc/api")).expect("artifact dir");
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").expect("cargo");
    fs::write(root.join("package.json"), "{\"name\":\"test\"}\n").expect("package");
    fs::write(root.join("README.md"), "IOI workspace runtime overview\n").expect("readme");
    fs::write(
        root.join(".artifacts/generated/doc/api/workspace.html"),
        "workspace workspace workspace generated artifact should not be selected\n",
    )
    .expect("artifact file");

    let sources = super::select_workspace_grounding_sources(
        &root,
        "Explain what this workspace is for in two concise paragraphs.",
    );

    assert!(!sources.is_empty());
    assert!(sources
        .iter()
        .all(|source| !source.relative_path.starts_with(".artifacts/")));

    let _ = fs::remove_dir_all(&root);
}
