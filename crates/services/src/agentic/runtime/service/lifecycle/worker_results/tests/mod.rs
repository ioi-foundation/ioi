use super::await_loop::{
    await_child_burst_step_limit, awaited_worker_handoff_completion_allowed,
    child_allows_await_burst,
};
use super::merge::{materialize_worker_result, merged_worker_output};
use super::{
    await_child_worker_result as await_child_worker_result_impl, build_parent_playbook_run,
    execution_evidence_value, inject_parent_playbook_context, latest_failed_goal_command_step,
    load_child_state, load_parent_playbook_run, load_worker_session_result,
    patch_build_verify_post_edit_followup_due, persist_parent_playbook_run,
    persist_worker_assignment, persist_worker_session_result, resolve_worker_assignment,
    resolve_worker_goal, retry_blocked_pause_reason,
    synthesize_observed_patch_build_verify_completion, LIVE_RESEARCH_AWAIT_BURST_STEPS,
    MAX_AWAIT_CHILD_BURST_STEPS, PARENT_PLAYBOOK_CONTEXT_MARKER,
    PATCH_BUILD_VERIFY_POST_EDIT_BURST_GRACE_STEPS,
};
use crate::agentic::rules::{ActionRules, DefaultPolicy};
use crate::agentic::runtime::agent_playbooks::builtin_agent_playbook;
use crate::agentic::runtime::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::runtime::service::lifecycle::delegation::spawn_delegated_child_session;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, ParentPlaybookStatus,
    ParentPlaybookStepStatus, PendingSearchCompletion, PendingSearchReadSummary, WorkerAssignment,
    WorkerCompletionContract, WorkerMergeMode,
};
use crate::agentic::runtime::utils::persist_agent_state;
use crate::agentic::runtime::worker_templates::builtin_worker_workflow;
use crate::agentic::skill_registry::{
    build_skill_archival_metadata_json, canonical_skill_hash, skill_archival_content,
    upsert_skill_record, SKILL_ARCHIVAL_KIND, SKILL_ARCHIVAL_SCOPE,
};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::{MemoryRuntime, NewArchivalMemoryRecord};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{
    AgentMacro, LlmToolDefinition, SkillLifecycleState, SkillRecord, SkillSourceType,
};
use ioi_types::app::{
    AccountId, ActionContext, ActionRequest, ActionTarget, ChainId, CodingVerificationScorecard,
};
use ioi_types::app::{ContextSlice, KernelEvent, WorkloadReceipt};
use ioi_types::codec;
use ioi_types::error::VmError;
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::sync::Arc;
use tempfile::tempdir;

#[derive(Clone)]
struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = image::ImageBuffer::<image::Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .map_err(|error| VmError::HostError(format!("mock PNG encode failed: {}", error)))?;
        Ok(bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root/>".to_string())
    }

    async fn capture_context(
        &self,
        _intent: &ioi_types::app::ActionRequest,
    ) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![b"<root/>".to_vec()],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_parent_state_with_goal(goal: &str, budget: u64) -> AgentState {
    AgentState {
        session_id: [0x91; 32],
        goal: goal.to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: Vec::new(),
        budget,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: Vec::new(),
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

fn build_parent_state() -> AgentState {
    build_parent_state_with_goal("Parent orchestration goal", 8)
}

#[test]
fn worker_goal_resolution_keeps_parent_shaped_goal_when_context_is_present() {
    let workflow = builtin_worker_workflow(Some("coder"), Some("patch_build_verify"))
        .expect("patch_build_verify workflow should exist");
    let raw_goal = format!(
            "Implement the parity fix in \"/tmp/example\" as a narrow workspace patch informed by the repo context brief, run focused executor-side checks, and return touched files, command results, and residual risk.\n\n{}\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            PARENT_PLAYBOOK_CONTEXT_MARKER
        );

    let resolved = resolve_worker_goal(&raw_goal, Some(&workflow));

    assert_eq!(resolved, raw_goal);
    assert_eq!(resolved.matches("Implement the parity fix").count(), 1);
}

#[test]
fn worker_goal_resolution_still_templates_root_kickoff_without_parent_context() {
    let workflow = builtin_worker_workflow(Some("context_worker"), Some("repo_context_brief"))
        .expect("repo_context_brief workflow should exist");
    let raw_goal = "Port the path-normalization parity fix into the repo at \"/tmp/example\".";

    let resolved = resolve_worker_goal(raw_goal, Some(&workflow));

    assert!(resolved.starts_with("Inspect repo context for "));
    assert!(resolved.contains("/tmp/example"));
    assert!(!resolved.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
}

#[tokio::test(flavor = "current_thread")]
async fn delegated_child_inherits_parent_policy_rules() {
    let (tx, _rx) = tokio::sync::broadcast::channel(4);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state();
    let parent_key = get_state_key(&parent_state.session_id);
    state
        .insert(
            &parent_key,
            &codec::to_bytes_canonical(&parent_state).expect("parent state encode"),
        )
        .expect("parent state insert should succeed");
    let parent_rules = ActionRules {
        policy_id: "capabilities-suite".to_string(),
        defaults: DefaultPolicy::AllowAll,
        ..ActionRules::default()
    };
    let parent_policy_key = [AGENT_POLICY_PREFIX, parent_state.session_id.as_slice()].concat();
    state
        .insert(
            &parent_policy_key,
            &codec::to_bytes_canonical(&parent_rules).expect("parent policy encode"),
        )
        .expect("parent policy insert should succeed");

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x51; 32],
        "Inspect the repo and return a bounded context brief.",
        8,
        None,
        Some("context_worker"),
        Some("repo_context_brief"),
        None,
        None,
        None,
        None,
        1,
        0,
    )
    .await
    .expect("delegated child should spawn");

    let child_policy_key = [AGENT_POLICY_PREFIX, spawned.child_session_id.as_slice()].concat();
    let child_policy_bytes = state
        .get(&child_policy_key)
        .expect("child policy lookup should succeed")
        .expect("child policy should exist");
    let child_rules: ActionRules =
        codec::from_bytes_canonical(&child_policy_bytes).expect("child policy should decode");

    assert_eq!(child_rules.policy_id, "capabilities-suite");
    assert_eq!(child_rules.defaults, DefaultPolicy::AllowAll);
}

fn build_test_service(
    event_sender: tokio::sync::broadcast::Sender<KernelEvent>,
) -> (RuntimeAgentService, tempfile::TempDir) {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let runtime = Arc::new(MockInferenceRuntime);
    let temp_dir = tempdir().expect("tempdir should open");
    let memory_path = temp_dir.path().join("worker-results.sqlite");
    let memory_runtime =
        Arc::new(MemoryRuntime::open_sqlite(&memory_path).expect("sqlite memory should open"));
    let service = RuntimeAgentService::new(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime,
    )
    .with_memory_runtime(memory_runtime)
    .with_event_sender(event_sender);
    (service, temp_dir)
}

fn test_call_context<'a>(services: &'a ServiceDirectory) -> ServiceCallContext<'a> {
    ServiceCallContext {
        block_height: 1,
        block_timestamp: 1,
        chain_id: ChainId(1),
        signer_account_id: AccountId([7u8; 32]),
        services,
        simulation: false,
        is_internal: false,
    }
}

async fn await_child_worker_result(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    child_session_id_hex: &str,
) -> Result<String, String> {
    let services = ServiceDirectory::new(Vec::new());
    await_child_worker_result_impl(
        service,
        state,
        parent_state,
        parent_step_index,
        block_height,
        test_call_context(&services),
        child_session_id_hex,
    )
    .await
}

async fn seed_runtime_skill(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    query_anchor: &str,
) {
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .expect("memory runtime should be configured");
    let skill = AgentMacro {
        definition: LlmToolDefinition {
            name: "research__benchmark_scorecard".to_string(),
            description:
                "Assemble a source-grounded benchmark scorecard for the active research route."
                    .to_string(),
            parameters:
                r#"{"type":"object","properties":{"topic":{"type":"string"}},"required":["topic"]}"#
                    .to_string(),
        },
        steps: vec![ActionRequest {
            target: ActionTarget::BrowserInteract,
            params: br#"{"__ioi_tool_name":"web__search","query":"{{topic}} benchmark scorecard"}"#
                .to_vec(),
            context: ActionContext {
                agent_id: "macro".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 0,
        }],
        source_trace_hash: [0x33; 32],
        fitness: 1.0,
    };
    let skill_hash = canonical_skill_hash(&skill).expect("skill hash");
    let content = format!(
        "{} {}",
        skill_archival_content(&skill.definition),
        query_anchor
    );
    let archival_record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: SKILL_ARCHIVAL_SCOPE.to_string(),
            thread_id: None,
            kind: SKILL_ARCHIVAL_KIND.to_string(),
            content: content.clone(),
            metadata_json: build_skill_archival_metadata_json(skill_hash, &skill)
                .expect("skill metadata"),
        })
        .expect("insert skill archival record")
        .expect("archival store available");
    let embedding = service
        .reasoning_inference
        .embed_text(&content)
        .await
        .expect("embed skill");
    memory_runtime
        .upsert_archival_embedding(archival_record_id, &embedding)
        .expect("index skill embedding");

    upsert_skill_record(
        state,
        &SkillRecord {
            skill_hash,
            archival_record_id,
            macro_body: skill,
            lifecycle_state: SkillLifecycleState::Validated,
            source_type: SkillSourceType::Imported,
            source_session_id: None,
            source_evidence_hash: None,
            benchmark: None,
            publication: None,
            created_at: 1,
            updated_at: 1,
        },
    )
    .expect("persist skill record");
}

async fn seed_runtime_artifact_skill(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    query_anchor: &str,
) {
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .expect("memory runtime should be configured");
    let skill = AgentMacro {
            definition: LlmToolDefinition {
                name: "artifact__frontend_validation_spine".to_string(),
                description:
                    "Shape artifact generation toward bold frontend execution and presentation-first validation checks."
                        .to_string(),
                parameters: r#"{"type":"object","properties":{"topic":{"type":"string"}},"required":["topic"]}"#
                    .to_string(),
            },
            steps: vec![ActionRequest {
                target: ActionTarget::BrowserInteract,
                params: br#"{"__ioi_tool_name":"file__write","path":"artifact-preview.html"}"#
                    .to_vec(),
                context: ActionContext {
                    agent_id: "macro".to_string(),
                    session_id: None,
                    window_id: None,
                },
                nonce: 0,
            }],
            source_trace_hash: [0x34; 32],
            fitness: 1.0,
        };
    let skill_hash = canonical_skill_hash(&skill).expect("skill hash");
    let content = format!(
        "{} {}",
        skill_archival_content(&skill.definition),
        query_anchor
    );
    let archival_record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: SKILL_ARCHIVAL_SCOPE.to_string(),
            thread_id: None,
            kind: SKILL_ARCHIVAL_KIND.to_string(),
            content: content.clone(),
            metadata_json: build_skill_archival_metadata_json(skill_hash, &skill)
                .expect("skill metadata"),
        })
        .expect("insert skill archival record")
        .expect("archival store available");
    let embedding = service
        .reasoning_inference
        .embed_text(&content)
        .await
        .expect("embed skill");
    memory_runtime
        .upsert_archival_embedding(archival_record_id, &embedding)
        .expect("index skill embedding");

    upsert_skill_record(
        state,
        &SkillRecord {
            skill_hash,
            archival_record_id,
            macro_body: skill,
            lifecycle_state: SkillLifecycleState::Validated,
            source_type: SkillSourceType::Imported,
            source_session_id: None,
            source_evidence_hash: None,
            benchmark: None,
            publication: None,
            created_at: 1,
            updated_at: 1,
        },
    )
    .expect("persist skill record");
}

async fn seed_runtime_computer_use_skill(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    query_anchor: &str,
) {
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .expect("memory runtime should be configured");
    let skill = AgentMacro {
            definition: LlmToolDefinition {
                name: "computer_use__ui_state_spine".to_string(),
                description:
                    "Prime the computer-use perception lane to identify the live target state, approval risk, and next safe action."
                        .to_string(),
                parameters: r#"{"type":"object","properties":{"topic":{"type":"string"}},"required":["topic"]}"#
                    .to_string(),
            },
            steps: vec![ActionRequest {
                target: ActionTarget::BrowserInteract,
                params: br#"{"__ioi_tool_name":"browser__inspect"}"#.to_vec(),
                context: ActionContext {
                    agent_id: "macro".to_string(),
                    session_id: None,
                    window_id: None,
                },
                nonce: 0,
            }],
            source_trace_hash: [0x35; 32],
            fitness: 1.0,
        };
    let skill_hash = canonical_skill_hash(&skill).expect("skill hash");
    let content = format!(
        "{} {}",
        skill_archival_content(&skill.definition),
        query_anchor
    );
    let archival_record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: SKILL_ARCHIVAL_SCOPE.to_string(),
            thread_id: None,
            kind: SKILL_ARCHIVAL_KIND.to_string(),
            content: content.clone(),
            metadata_json: build_skill_archival_metadata_json(skill_hash, &skill)
                .expect("skill metadata"),
        })
        .expect("insert skill archival record")
        .expect("archival store available");
    let embedding = service
        .reasoning_inference
        .embed_text(&content)
        .await
        .expect("embed skill");
    memory_runtime
        .upsert_archival_embedding(archival_record_id, &embedding)
        .expect("index skill embedding");

    upsert_skill_record(
        state,
        &SkillRecord {
            skill_hash,
            archival_record_id,
            macro_body: skill,
            lifecycle_state: SkillLifecycleState::Validated,
            source_type: SkillSourceType::Imported,
            source_session_id: None,
            source_evidence_hash: None,
            benchmark: None,
            publication: None,
            created_at: 1,
            updated_at: 1,
        },
    )
    .expect("persist skill record");
}

async fn seed_runtime_fact(service: &RuntimeAgentService, content: &str) {
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .expect("memory runtime should be configured");
    let record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: "desktop.facts".to_string(),
            thread_id: None,
            kind: "fact".to_string(),
            content: content.to_string(),
            metadata_json:
                r#"{"role":"fact","trust_level":"standard","source":"worker_results_test"}"#
                    .to_string(),
        })
        .expect("insert fact archival record")
        .expect("archival store available");
    let embedding = service
        .reasoning_inference
        .embed_text(content)
        .await
        .expect("embed fact");
    memory_runtime
        .upsert_archival_embedding(record_id, &embedding)
        .expect("index fact embedding");
}

mod artifact_gate;
mod await_flow;
mod browser_gate;
mod citation_brief_flow;
mod delegation_receipts;
mod evidence_patch_flow;
mod parent_playbook;
mod patch_recovery;
mod playbook_merge;
