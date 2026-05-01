use super::*;
use crate::agentic::rules::{Rule, RuleConditions, Verdict};
use ioi_types::app::agentic::{IntentQueryBindingClass, ProviderSelectionMode, VerificationMode};

fn workspace_ops_entry() -> IntentCatalogEntry {
    IntentCatalogEntry {
        intent_id: "workspace.ops".to_string(),
        semantic_descriptor: "inspect and modify files in the local workspace".to_string(),
        query_binding: IntentQueryBindingClass::None,
        required_capabilities: vec![capability("filesystem.read")],
        risk_class: "low".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        preferred_tier: "tool_first".to_string(),
        applicability_class: ExecutionApplicabilityClass::TopologyDependent,
        requires_host_discovery: Some(false),
        provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
        required_evidence: vec![],
        success_conditions: vec![],
        verification_mode: Some(VerificationMode::DynamicSynthesis),
        aliases: vec![],
        exemplars: vec![],
    }
}

fn command_exec_entry() -> IntentCatalogEntry {
    IntentCatalogEntry {
        intent_id: "command.exec".to_string(),
        semantic_descriptor: "execute local shell or terminal commands".to_string(),
        query_binding: IntentQueryBindingClass::CommandDirected,
        required_capabilities: vec![capability("command.exec")],
        risk_class: "low".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        preferred_tier: "tool_first".to_string(),
        applicability_class: ExecutionApplicabilityClass::TopologyDependent,
        requires_host_discovery: Some(true),
        provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
        required_evidence: vec![],
        success_conditions: vec![],
        verification_mode: Some(VerificationMode::DynamicSynthesis),
        aliases: vec![],
        exemplars: vec![],
    }
}

fn automation_monitor_entry() -> IntentCatalogEntry {
    IntentCatalogEntry {
        intent_id: "automation.monitor".to_string(),
        semantic_descriptor:
            "install a durable local automation monitor that watches a source on a schedule"
                .to_string(),
        query_binding: IntentQueryBindingClass::DurableAutomation,
        required_capabilities: vec![capability("automation.monitor.install")],
        risk_class: "medium".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        preferred_tier: "tool_first".to_string(),
        applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
        requires_host_discovery: Some(false),
        provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
        required_evidence: vec![],
        success_conditions: vec![],
        verification_mode: Some(VerificationMode::DeterministicCheck),
        aliases: vec![],
        exemplars: vec![],
    }
}

fn model_registry_load_entry() -> IntentCatalogEntry {
    IntentCatalogEntry {
        intent_id: "model.registry.load".to_string(),
        semantic_descriptor: "load a local model into the kernel runtime".to_string(),
        query_binding: IntentQueryBindingClass::ModelRegistryControl,
        required_capabilities: vec![capability("model.registry.manage")],
        risk_class: "medium".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        preferred_tier: "tool_first".to_string(),
        applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
        requires_host_discovery: Some(false),
        provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
        required_evidence: vec![],
        success_conditions: vec![],
        verification_mode: Some(VerificationMode::DeterministicCheck),
        aliases: vec![],
        exemplars: vec![],
    }
}

fn temporal_files_profile() -> QueryBindingProfile {
    QueryBindingProfile {
        available: true,
        command_directed: true,
        temporal_filesystem_filter: true,
        ..Default::default()
    }
}

fn durable_remote_monitor_profile() -> QueryBindingProfile {
    QueryBindingProfile {
        available: true,
        remote_public_fact_required: true,
        command_directed: true,
        durable_automation_requested: true,
        ..Default::default()
    }
}

fn model_registry_control_profile() -> QueryBindingProfile {
    QueryBindingProfile {
        available: true,
        model_registry_control_requested: true,
        ..Default::default()
    }
}

#[test]
fn workspace_ops_temporal_file_queries_are_feasible_with_metadata_tooling() {
    let entry = workspace_ops_entry();
    let profile = temporal_files_profile();
    let bindings = tool_capability_bindings();
    let rules = ActionRules::default();

    assert!(intent_feasible_without_policy(&entry, &bindings, &profile));
    assert!(intent_feasible_for_execution(
        &entry, &bindings, &rules, &profile
    ));
}

#[test]
fn command_exec_remains_feasible_for_temporal_file_queries() {
    let entry = command_exec_entry();
    let profile = temporal_files_profile();
    let bindings = tool_capability_bindings();
    let rules = ActionRules::default();

    assert!(intent_feasible_without_policy(&entry, &bindings, &profile));
    assert!(intent_feasible_for_execution(
        &entry, &bindings, &rules, &profile
    ));
}

#[test]
fn filesystem_edit_line_inherits_filesystem_write_capability() {
    let resolved = ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![capability("filesystem.write")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [1u8; 32],
        evidence_requirements_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };

    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__write",
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__replace_line",
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&resolved),
        "file__edit",
    ));
}

#[test]
fn durable_automation_remains_feasible_when_monitoring_public_sources() {
    let entry = automation_monitor_entry();
    let profile = durable_remote_monitor_profile();
    let bindings = tool_capability_bindings();
    let rules = ActionRules::default();

    assert!(intent_feasible_without_policy(&entry, &bindings, &profile));
    assert!(intent_feasible_for_execution(
        &entry, &bindings, &rules, &profile
    ));
}

#[test]
fn model_control_family_block_makes_registry_intent_infeasible() {
    let entry = model_registry_load_entry();
    let profile = model_registry_control_profile();
    let bindings = tool_capability_bindings();
    let mut rules = ActionRules::default();
    rules.rules.push(Rule {
        rule_id: Some("block-model-control".to_string()),
        target: "model::control".to_string(),
        conditions: RuleConditions::default(),
        action: Verdict::Block,
    });

    assert!(intent_feasible_without_policy(&entry, &bindings, &profile));
    assert!(!intent_feasible_for_execution(
        &entry, &bindings, &rules, &profile
    ));
}

#[test]
fn parent_playbook_contract_adds_delegation_capability() {
    let contract = InstructionContract {
        slot_bindings: vec![ioi_types::app::agentic::InstructionSlotBinding {
            slot: "playbook_id".to_string(),
            binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
            value: Some("evidence_audited_patch".to_string()),
            origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
            protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
        }],
        ..InstructionContract::default()
    };

    let effective = required_capabilities_with_instruction_contract(
        &[
            capability("filesystem.read"),
            capability("filesystem.write"),
        ],
        Some(&contract),
    );

    assert!(effective.contains(&capability("filesystem.read")));
    assert!(effective.contains(&capability("filesystem.write")));
    assert!(effective.contains(&capability("delegation.manage")));
}
