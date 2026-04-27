use super::{
    builtin_agent_playbooks, playbook_decision_record, recommended_agent_playbook,
    render_agent_playbook_catalog, AgentPlaybookDecisionRecord,
};
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, LlmToolDefinition, ResolvedIntentState,
};

fn workspace_ops_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("filesystem.patch")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[test]
fn builtin_agent_playbook_catalog_contains_evidence_audited_patch() {
    let playbooks = builtin_agent_playbooks();
    assert_eq!(playbooks.len(), 5);
    let playbook = playbooks
        .into_iter()
        .find(|entry| entry.playbook_id == "evidence_audited_patch")
        .expect("evidence-audited patch playbook should exist");
    assert_eq!(playbook.steps.len(), 4);
    assert_eq!(playbook.steps[0].worker_template_id, "context_worker");
    assert_eq!(playbook.steps[0].worker_workflow_id, "repo_context_brief");
    assert_eq!(playbook.steps[1].worker_template_id, "coder");
    assert_eq!(playbook.steps[1].worker_workflow_id, "patch_build_verify");
    assert_eq!(playbook.steps[2].worker_template_id, "verifier");
    assert_eq!(playbook.steps[2].worker_workflow_id, "targeted_test_audit");
    assert_eq!(playbook.steps[3].worker_template_id, "patch_synthesizer");
    assert_eq!(
        playbook.steps[3].worker_workflow_id,
        "patch_synthesis_handoff"
    );
}

#[test]
fn builtin_agent_playbook_catalog_contains_citation_grounded_brief() {
    let playbooks = builtin_agent_playbooks();
    let playbook = playbooks
        .into_iter()
        .find(|entry| entry.playbook_id == "citation_grounded_brief")
        .expect("citation-grounded brief playbook should exist");
    assert_eq!(playbook.steps.len(), 2);
    assert_eq!(playbook.steps[0].worker_template_id, "researcher");
    assert_eq!(playbook.steps[0].worker_workflow_id, "live_research_brief");
    assert_eq!(playbook.steps[1].worker_template_id, "verifier");
    assert_eq!(playbook.steps[1].worker_workflow_id, "citation_audit");
}

#[test]
fn builtin_agent_playbook_catalog_contains_browser_postcondition_gate() {
    let playbooks = builtin_agent_playbooks();
    let playbook = playbooks
        .into_iter()
        .find(|entry| entry.playbook_id == "browser_postcondition_gate")
        .expect("browser postcondition gate should exist");
    assert_eq!(playbook.steps.len(), 3);
    assert_eq!(playbook.steps[0].worker_template_id, "perception_worker");
    assert_eq!(playbook.steps[0].worker_workflow_id, "ui_state_brief");
    assert_eq!(playbook.steps[1].worker_template_id, "browser_operator");
    assert_eq!(
        playbook.steps[1].worker_workflow_id,
        "browser_postcondition_pass"
    );
    assert_eq!(playbook.steps[2].worker_template_id, "verifier");
    assert_eq!(
        playbook.steps[2].worker_workflow_id,
        "browser_postcondition_audit"
    );
}

#[test]
fn recommends_evidence_audited_patch_for_port_with_verification() {
    let recommendation = recommended_agent_playbook(
        "Port the LocalAI parity fix in the Rust crate, research the current behavior, patch the workspace, and verify the postcondition.",
        Some(&workspace_ops_intent()),
    )
    .expect("playbook should be recommended");
    assert_eq!(recommendation.playbook_id, "evidence_audited_patch");
}

#[test]
fn recommends_citation_grounded_brief_for_research_intent() {
    let recommendation = recommended_agent_playbook(
        "Research the latest kernel scheduling benchmarks and verify the source freshness.",
        Some(&ResolvedIntentState {
            intent_id: "web.research".to_string(),
            ..workspace_ops_intent()
        }),
    )
    .expect("research playbook should be recommended");
    assert_eq!(recommendation.playbook_id, "citation_grounded_brief");
}

#[test]
fn does_not_recommend_research_playbook_for_simple_currentness_lookup() {
    let recommendation = recommended_agent_playbook(
        "Who is the current Secretary-General of the UN?",
        Some(&ResolvedIntentState {
            intent_id: "web.research".to_string(),
            ..workspace_ops_intent()
        }),
    );
    assert!(
        recommendation.is_none(),
        "simple currentness lookups should stay on the direct research lane"
    );
}

#[test]
fn recommends_browser_postcondition_gate_for_browser_task() {
    let recommendation = recommended_agent_playbook(
        "Open the billing website, click the submit button, and verify the confirmation page appears.",
        Some(&ResolvedIntentState {
            intent_id: "delegation.task".to_string(),
            ..workspace_ops_intent()
        }),
    )
    .expect("browser playbook should be recommended");
    assert_eq!(recommendation.playbook_id, "browser_postcondition_gate");
}

#[test]
fn recommends_artifact_generation_gate_for_artifact_task() {
    let recommendation = recommended_agent_playbook(
        "Generate a launch landing page artifact and verify the retained HTML is ready for presentation.",
        Some(&ResolvedIntentState {
            intent_id: "delegation.task".to_string(),
            ..workspace_ops_intent()
        }),
    )
    .expect("artifact playbook should be recommended");
    assert_eq!(recommendation.playbook_id, "artifact_generation_gate");
}

#[test]
fn recommends_research_backed_artifact_gate_for_explainer_artifact_task() {
    let recommendation = recommended_agent_playbook(
        "Create an html file that explains quantum computers.",
        Some(&ResolvedIntentState {
            intent_id: "delegation.task".to_string(),
            ..workspace_ops_intent()
        }),
    )
    .expect("researched artifact playbook should be recommended");
    assert_eq!(recommendation.playbook_id, "research_backed_artifact_gate");
}

#[test]
fn builtin_agent_playbook_catalog_contains_artifact_generation_gate() {
    let playbook = builtin_agent_playbooks()
        .into_iter()
        .find(|entry| entry.playbook_id == "artifact_generation_gate")
        .expect("artifact_generation_gate playbook should exist");
    assert_eq!(playbook.default_budget, 196);
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
fn builtin_agent_playbook_catalog_contains_research_backed_artifact_gate() {
    let playbook = builtin_agent_playbooks()
        .into_iter()
        .find(|entry| entry.playbook_id == "research_backed_artifact_gate")
        .expect("research_backed_artifact_gate playbook should exist");
    assert_eq!(playbook.default_budget, 228);
    assert_eq!(playbook.steps.len(), 4);
    assert_eq!(
        playbook.steps[0].worker_workflow_id,
        "artifact_context_brief"
    );
    assert_eq!(playbook.steps[1].worker_workflow_id, "live_research_brief");
    assert_eq!(
        playbook.steps[2].worker_workflow_id,
        "artifact_generate_repair"
    );
    assert_eq!(
        playbook.steps[3].worker_workflow_id,
        "artifact_validation_audit"
    );
}

#[test]
fn playbook_decision_records_cover_primary_workload_families() {
    assert_eq!(
        playbook_decision_record("evidence_audited_patch"),
        AgentPlaybookDecisionRecord {
            route_family: "coding",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("test_verifier"),
            requires_verifier: true,
        }
    );
    assert_eq!(
        playbook_decision_record("citation_grounded_brief"),
        AgentPlaybookDecisionRecord {
            route_family: "research",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("citation_verifier"),
            requires_verifier: true,
        }
    );
    assert_eq!(
        playbook_decision_record("browser_postcondition_gate"),
        AgentPlaybookDecisionRecord {
            route_family: "computer_use",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("postcondition_verifier"),
            requires_verifier: true,
        }
    );
    assert_eq!(
        playbook_decision_record("artifact_generation_gate"),
        AgentPlaybookDecisionRecord {
            route_family: "artifacts",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("artifact_validation_verifier"),
            requires_verifier: true,
        }
    );
    assert_eq!(
        playbook_decision_record("research_backed_artifact_gate"),
        AgentPlaybookDecisionRecord {
            route_family: "artifacts",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("artifact_validation_verifier"),
            requires_verifier: true,
        }
    );
}

#[test]
fn render_agent_playbook_catalog_includes_recommendation_and_steps() {
    let rendered = render_agent_playbook_catalog(
        &[LlmToolDefinition {
            name: "agent__delegate".to_string(),
            description: "Spawn a bounded child worker.".to_string(),
            parameters: "{}".to_string(),
        }],
        "Port the LocalAI parity fix in the Rust crate, research the current behavior, patch the workspace, and verify the postcondition.",
        Some(&workspace_ops_intent()),
    )
    .expect("catalog should render");

    assert!(rendered.contains("[PARENT PLAYBOOKS]"));
    assert!(rendered.contains("Recommended now: `evidence_audited_patch`"));
    assert!(rendered.contains("citation_grounded_brief"));
    assert!(rendered.contains("browser_postcondition_gate"));
    assert!(rendered.contains("artifact_generation_gate"));
    assert!(rendered.contains("research_backed_artifact_gate"));
    assert!(rendered.contains("context_worker/repo_context_brief"));
    assert!(rendered.contains("coder/patch_build_verify"));
    assert!(rendered.contains("verifier/targeted_test_audit"));
    assert!(rendered.contains("patch_synthesizer/patch_synthesis_handoff"));
    assert!(rendered.contains("verifier/citation_audit"));
    assert!(rendered.contains("perception_worker/ui_state_brief"));
    assert!(rendered.contains("verifier/browser_postcondition_audit"));
    assert!(rendered.contains("context_worker/artifact_context_brief"));
    assert!(rendered.contains("artifact_builder/artifact_generate_repair"));
    assert!(rendered.contains("verifier/artifact_validation_audit"));
    assert!(rendered.contains("researcher/live_research_brief"));
}
