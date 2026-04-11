use super::core::ApprovalDirective;
use super::flow::{should_enter_incident_recovery, should_skip_incident_recovery_for_intent};
use super::recovery::{effective_forbidden_tools, policy_max_transitions};
use crate::agentic::rules::{ActionRules, ApprovalMode, OntologyPolicy, ToolPreferences};
use crate::agentic::runtime::service::step::anti_loop::FailureClass;
use crate::agentic::runtime::service::step::ontology::IntentClass;

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
            planning_enabled: true,
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
                forbidden_remediation_tools: vec!["shell__run".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let set = effective_forbidden_tools(&rules);
    assert!(set.contains("agent__complete"));
    assert!(set.contains("shell__run"));
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

#[test]
fn file_task_no_effect_failures_skip_incident_recovery() {
    assert!(should_skip_incident_recovery_for_intent(
        IntentClass::FileTask,
        "file__list",
        FailureClass::NoEffectAfterAction
    ));
    assert!(should_skip_incident_recovery_for_intent(
        IntentClass::FileTask,
        "file__search",
        FailureClass::UnexpectedState
    ));
    assert!(should_skip_incident_recovery_for_intent(
        IntentClass::FileTask,
        "file__create_dir",
        FailureClass::NoEffectAfterAction
    ));
    assert!(!should_skip_incident_recovery_for_intent(
        IntentClass::FileTask,
        "file__create_dir",
        FailureClass::TargetNotFound
    ));
    assert!(!should_skip_incident_recovery_for_intent(
        IntentClass::UIInteraction,
        "screen__click_at",
        FailureClass::NoEffectAfterAction
    ));
}

#[test]
fn conversation_mail_reply_no_effect_skips_incident_recovery() {
    assert!(should_skip_incident_recovery_for_intent(
        IntentClass::ConversationTask,
        "wallet_network__mail_reply",
        FailureClass::NoEffectAfterAction
    ));
    assert!(should_skip_incident_recovery_for_intent(
        IntentClass::ConversationTask,
        "mail__reply",
        FailureClass::UnexpectedState
    ));
    assert!(should_skip_incident_recovery_for_intent(
        IntentClass::ConversationTask,
        "connector__google__gmail_send_email",
        FailureClass::NoEffectAfterAction
    ));
    assert!(!should_skip_incident_recovery_for_intent(
        IntentClass::ConversationTask,
        "wallet_network__mail_list_recent",
        FailureClass::NoEffectAfterAction
    ));
}
