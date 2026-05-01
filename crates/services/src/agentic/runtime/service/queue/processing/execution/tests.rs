use super::{browser_queue_action_timeout, browser_queue_timeout_for_tool};
use ioi_types::app::agentic::AgentTool;
use std::time::Duration;

#[test]
fn browser_queue_timeout_defaults_for_non_wait_tools() {
    let tool = AgentTool::BrowserSnapshot {};
    assert_eq!(
        browser_queue_timeout_for_tool(&tool),
        browser_queue_action_timeout()
    );
}

#[test]
fn browser_wait_timeout_honors_requested_duration_plus_grace() {
    let tool = AgentTool::BrowserWait {
        ms: Some(15_000),
        condition: None,
        selector: None,
        query: None,
        scope: None,
        timeout_ms: None,
        continue_with: None,
    };

    assert_eq!(
        browser_queue_timeout_for_tool(&tool),
        Duration::from_millis(20_000)
    );
}
