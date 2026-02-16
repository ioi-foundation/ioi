use super::core::ApprovalDirective;
use super::flow::should_enter_incident_recovery;
use super::recovery::{effective_forbidden_tools, policy_max_transitions};
use crate::agentic::desktop::service::step::anti_loop::FailureClass;
use crate::agentic::desktop::service::step::ontology::IntentClass;
use crate::agentic::rules::{ActionRules, ApprovalMode, OntologyPolicy, ToolPreferences};

#[test]
fn incident_gate_blocks_non_recoverable_classes() {
    assert!(!should_enter_incident_recovery(
        Some(FailureClass::PermissionOrApprovalRequired),
        "allowed",
        false,
        None
    ));
    assert!(!should_enter_incident_recovery(
        Some(FailureClass::UserInterventionNeeded),
        "allowed",
        false,
        None
    ));
    assert!(should_enter_incident_recovery(
        Some(FailureClass::ToolUnavailable),
        "allowed",
        false,
        None
    ));
}

#[test]
fn policy_max_transitions_defaults_to_ontology_policy() {
    let rules = ActionRules {
        ontology_policy: OntologyPolicy {
            approval_mode: ApprovalMode::SinglePending,
            max_incident_transitions: 19,
            intent_failure_overrides: Vec::new(),
            tool_preferences: ToolPreferences::default(),
            intent_routing: Default::default(),
        },
        ..Default::default()
    };
    assert_eq!(
        policy_max_transitions(&rules, IntentClass::Unknown, FailureClass::UnexpectedState),
        19
    );
}

#[test]
fn forbidden_tools_include_policy_entries() {
    let rules = ActionRules {
        ontology_policy: OntologyPolicy {
            tool_preferences: ToolPreferences {
                forbidden_remediation_tools: vec!["sys__exec".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let set = effective_forbidden_tools(&rules);
    assert!(set.contains("agent__complete"));
    assert!(set.contains("sys__exec"));
}

#[test]
fn approval_directive_type_is_exhaustive() {
    let value = ApprovalDirective::PromptUser;
    assert!(matches!(
        value,
        ApprovalDirective::PromptUser
            | ApprovalDirective::SuppressDuplicatePrompt
            | ApprovalDirective::PauseLoop
    ));
}
