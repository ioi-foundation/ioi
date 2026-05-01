use super::*;
use ioi_types::app::agentic::InstructionSideEffectMode;

fn contract_with_success_criteria(criteria: &[&str]) -> InstructionContract {
    InstructionContract {
        operation: "click".to_string(),
        side_effect_mode: InstructionSideEffectMode::Update,
        slot_bindings: vec![],
        negative_constraints: vec![],
        success_criteria: criteria.iter().map(|value| value.to_string()).collect(),
    }
}

#[test]
fn enriches_generic_updated_success_criterion_from_query_end_state() {
    let mut contract = contract_with_success_criteria(&["status_text.updated"]);

    enrich_instruction_contract_from_query(
        "Click the button so the status text becomes done.",
        &mut contract,
    );

    assert_eq!(
        contract.success_criteria,
        vec!["status_text.updated_to_done"]
    );
}

#[test]
fn keeps_specific_success_criterion_unchanged() {
    let mut contract = contract_with_success_criteria(&["status_text.updated_to_done"]);

    enrich_instruction_contract_from_query(
        "Click the button so the status text becomes done.",
        &mut contract,
    );

    assert_eq!(
        contract.success_criteria,
        vec!["status_text.updated_to_done"]
    );
}

#[test]
fn does_not_enrich_unrelated_success_criterion() {
    let mut contract = contract_with_success_criteria(&["button_label.updated"]);

    enrich_instruction_contract_from_query(
        "Click the button so the status text becomes done.",
        &mut contract,
    );

    assert_eq!(contract.success_criteria, vec!["button_label.updated"]);
}

#[test]
fn extracts_quoted_terminal_values_from_query() {
    let mut contract = contract_with_success_criteria(&["toast.equals"]);

    enrich_instruction_contract_from_query(
        "Save the form so the toast equals 'Saved successfully'.",
        &mut contract,
    );

    assert_eq!(
        contract.success_criteria,
        vec!["toast.equals_saved_successfully"]
    );
}

#[test]
fn seeds_researcher_template_for_web_research_intent() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Research the latest kernel scheduling benchmarks.",
        "web.research",
        &mut contract,
    );

    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("template binding should be added");
    assert_eq!(
        template_binding.binding_kind,
        ioi_types::app::agentic::InstructionBindingKind::UserLiteral
    );
    assert_eq!(template_binding.value.as_deref(), Some("researcher"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("live_research_brief")
    );
}

#[test]
fn does_not_seed_research_template_or_playbook_for_simple_currentness_lookup() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Who is the current Secretary-General of the UN?",
        "web.research",
        &mut contract,
    );

    assert!(
        contract
            .slot_bindings
            .iter()
            .all(|binding| binding.slot != "playbook_id"),
        "simple currentness lookups should not force a research playbook"
    );
    assert!(
        contract
            .slot_bindings
            .iter()
            .all(|binding| binding.slot != "template_id"),
        "simple currentness lookups should not force a delegated researcher template"
    );
}

#[test]
fn preserves_existing_template_binding_when_present() {
    let mut contract = InstructionContract {
        operation: "delegate".to_string(),
        side_effect_mode: InstructionSideEffectMode::ReadOnly,
        slot_bindings: vec![ioi_types::app::agentic::InstructionSlotBinding {
            slot: "template_id".to_string(),
            binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
            value: Some("verifier".to_string()),
            origin: ioi_types::app::agentic::ArgumentOrigin::UserSpan,
            protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
        }],
        negative_constraints: vec![],
        success_criteria: vec![],
    };

    finalize_instruction_contract(
        "Research and verify the latest kernel scheduling benchmarks.",
        "web.research",
        &mut contract,
    );

    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("template binding should exist");
    assert_eq!(template_binding.value.as_deref(), Some("verifier"));
}

#[test]
fn seeds_coder_template_for_workspace_code_change_intent() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Implement a patch in the Rust workspace to fix the failing test.",
        "workspace.ops",
        &mut contract,
    );

    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("coder template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("coder"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("coder workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("patch_build_verify")
    );
}

#[test]
fn seeds_evidence_audited_parent_playbook_for_workspace_port_task() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Port LocalAI parity into the Rust workspace, research the current behavior first, and verify the final postcondition.",
        "workspace.ops",
        &mut contract,
    );

    let playbook_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "playbook_id")
        .expect("parent playbook binding should be added");
    assert_eq!(
        playbook_binding.value.as_deref(),
        Some("evidence_audited_patch")
    );
    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("context worker template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("context_worker"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("context worker workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("repo_context_brief")
    );
}

#[test]
fn seeds_research_playbook_for_web_research_intent() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Research the latest kernel scheduling benchmarks and verify the source freshness.",
        "web.research",
        &mut contract,
    );

    let playbook_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "playbook_id")
        .expect("research playbook binding should be added");
    assert_eq!(
        playbook_binding.value.as_deref(),
        Some("citation_grounded_brief")
    );
    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("researcher template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("researcher"));
}

#[test]
fn seeds_browser_playbook_for_browser_task() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Open the billing website, click the submit button, and verify the confirmation page appears.",
        "delegation.task",
        &mut contract,
    );

    let playbook_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "playbook_id")
        .expect("browser playbook binding should be added");
    assert_eq!(
        playbook_binding.value.as_deref(),
        Some("browser_postcondition_gate")
    );
    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("perception worker template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("perception_worker"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("browser workflow binding should be added");
    assert_eq!(workflow_binding.value.as_deref(), Some("ui_state_brief"));
}

#[test]
fn seeds_artifact_playbook_for_artifact_task() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Generate a launch landing page artifact and verify the retained HTML is ready for presentation.",
        "delegation.task",
        &mut contract,
    );

    let playbook_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "playbook_id")
        .expect("artifact playbook binding should be added");
    assert_eq!(
        playbook_binding.value.as_deref(),
        Some("artifact_generation_gate")
    );
    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("artifact context template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("context_worker"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("artifact workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("artifact_context_brief")
    );
}

#[test]
fn seeds_research_backed_artifact_playbook_for_explainer_artifact_task() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Create an html file that explains quantum computers.",
        "delegation.task",
        &mut contract,
    );

    let playbook_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "playbook_id")
        .expect("researched artifact playbook binding should be added");
    assert_eq!(
        playbook_binding.value.as_deref(),
        Some("research_backed_artifact_gate")
    );
    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("artifact context template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("context_worker"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("artifact workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("artifact_context_brief")
    );
}

#[test]
fn does_not_seed_coder_template_for_generic_workspace_file_task() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Rename every file in my Downloads folder to lowercase.",
        "workspace.ops",
        &mut contract,
    );

    assert!(
        contract
            .slot_bindings
            .iter()
            .all(|binding| binding.slot != "template_id"),
        "generic file-management tasks should not default to coder"
    );
}

#[test]
fn seeds_verifier_template_for_explicit_verification_delegation() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Delegate a worker to verify whether the evidence bundle supports the claim.",
        "delegation.task",
        &mut contract,
    );

    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("verifier template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("verifier"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("verifier workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("postcondition_audit")
    );
}

#[test]
fn seeds_targeted_test_verifier_for_code_verification_delegation() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Delegate a worker to verify the Rust patch by running the focused tests first and widening only if needed.",
        "delegation.task",
        &mut contract,
    );

    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("verifier template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("verifier"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("verifier workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("targeted_test_audit")
    );
}

#[test]
fn seeds_coder_workflow_for_explicit_code_change_delegation() {
    let mut contract = InstructionContract::default();

    finalize_instruction_contract(
        "Delegate a worker to patch the parser bug, run the focused tests, and report what changed.",
        "delegation.task",
        &mut contract,
    );

    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("coder template binding should be added");
    assert_eq!(template_binding.value.as_deref(), Some("coder"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("coder workflow binding should be added");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("patch_build_verify")
    );
}

#[test]
fn seeded_instruction_contract_helper_does_not_create_coding_parent_playbook_contract() {
    assert!(seeded_instruction_contract_for_intent(
        "Port the path-normalization parity fix into the repo, run the focused tests first, and report what changed.",
        "workspace.ops",
    )
    .is_none());
}

#[test]
fn seeded_instruction_contract_helper_does_not_create_research_parent_playbook_contract() {
    assert!(seeded_instruction_contract_for_intent(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        "web.research",
    )
    .is_none());
}

#[test]
fn skips_instruction_contract_inference_for_plain_conversation_reply() {
    assert!(!instruction_contract_inference_needed(
        "summarize what you can help me do in this repository in one short paragraph",
        "conversation.reply",
        &[capability("conversation.reply")],
        None,
    ));
}

#[test]
fn skips_instruction_contract_inference_for_explanatory_repo_summary_with_provider_selection() {
    assert!(!instruction_contract_inference_needed(
        "summarize what you can help me do in this repository in one short paragraph",
        "workspace.ops",
        &[capability("workspace.read")],
        Some(&ProviderSelectionState::default()),
    ));
}

#[test]
fn keeps_instruction_contract_inference_for_delegated_repo_work() {
    assert!(instruction_contract_inference_needed(
        "investigate this repository and fix the failing rust test",
        "delegation.task",
        &[capability("delegation.manage")],
        None,
    ));
}
