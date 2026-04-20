use super::{
    default_safe_policy, is_live_external_research_goal, is_mailbox_connector_goal,
    should_auto_complete_open_app_goal, LIVE_EXTERNAL_RESEARCH_SIGNAL_VERSION,
};

#[test]
fn auto_complete_open_app_goal_for_simple_launch() {
    assert!(should_auto_complete_open_app_goal(
        "Open calculator",
        "calculator",
        Some("calculator")
    ));
}

#[test]
fn does_not_auto_complete_when_follow_up_actions_exist() {
    assert!(!should_auto_complete_open_app_goal(
        "Open calculator and compute 2+2",
        "calculator",
        Some("calculator")
    ));
}

#[test]
fn requires_goal_to_mention_target_app() {
    assert!(!should_auto_complete_open_app_goal(
        "Open the app",
        "calculator",
        Some("calculator")
    ));
}

#[test]
fn browser_recovery_defaults_have_low_transition_caps() {
    let rules = default_safe_policy();
    let mut saw_unexpected = false;
    let mut saw_timeout = false;
    for ov in &rules.ontology_policy.intent_failure_overrides {
        if ov.intent_class == "BrowserTask" && ov.failure_class == "UnexpectedState" {
            saw_unexpected = ov.max_transitions == Some(2);
        }
        if ov.intent_class == "BrowserTask" && ov.failure_class == "TimeoutOrHang" {
            saw_timeout = ov.max_transitions == Some(2);
        }
    }
    assert!(saw_unexpected);
    assert!(saw_timeout);
}

#[test]
fn detects_live_external_research_goals() {
    assert_eq!(LIVE_EXTERNAL_RESEARCH_SIGNAL_VERSION, "ontology_signals_v3");
    assert!(is_live_external_research_goal(
        "As of now (UTC), top active cloud incidents with status page citations and user impact"
    ));
    assert!(is_live_external_research_goal(
        "Latest SaaS outage updates from major provider status pages with sources"
    ));
}

#[test]
fn does_not_misclassify_workspace_edit_requests_as_live_research() {
    assert!(!is_live_external_research_goal(
        "Search this repo for intent resolver logic and patch the rust file"
    ));
    assert!(!is_live_external_research_goal(
        "Update tests in the workspace and commit the diff"
    ));
    assert!(!is_live_external_research_goal(
        "As of now, search this repository for incident handler changes and cite the files"
    ));
}

#[test]
fn detects_mailbox_connector_goals() {
    assert!(is_mailbox_connector_goal(
        "Read me the latest email in my inbox"
    ));
    assert!(!is_mailbox_connector_goal(
        "Find the latest cloud outage updates with citations"
    ));
}

#[test]
fn default_safe_policy_uses_current_intent_matrix_version() {
    let upgraded = default_safe_policy();
    assert_eq!(
        upgraded.ontology_policy.intent_routing.matrix_version,
        "intent-matrix-v15"
    );
}
