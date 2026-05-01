use super::{classify_intent, default_strategy_for, IntentClass, StrategyNode};
use crate::agentic::runtime::service::recovery::anti_loop::FailureClass;

#[test]
fn classify_open_app_by_goal_and_hint() {
    assert_eq!(
        classify_intent("open calculator", "app__launch", Some("calculator")),
        IntentClass::OpenApp
    );
}

#[test]
fn classify_file_task() {
    assert_eq!(
        classify_intent("read file", "file__read", None),
        IntentClass::FileTask
    );
}

#[test]
fn open_app_unavailable_prefers_install_node() {
    let (_, node) = default_strategy_for(IntentClass::OpenApp, FailureClass::ToolUnavailable);
    assert_eq!(node, StrategyNode::InstallDependency);
}
