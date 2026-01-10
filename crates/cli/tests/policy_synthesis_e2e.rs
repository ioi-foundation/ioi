// Path: crates/cli/tests/policy_synthesis_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use ioi_cli::testing::build_test_artifacts;
use ioi_types::app::agentic::StepTrace;
use ioi_validator::firewall::rules::DefaultPolicy;
use ioi_validator::firewall::synthesizer::PolicySynthesizer;

// We reuse the synthesis logic but feed it mock traces instead of running a full node
// to keep the test fast and focused on logic correctness.
#[test]
fn test_policy_synthesis_logic() {
    build_test_artifacts(); // Ensures types are built

    // 1. Create Mock Traces
    let trace1 = StepTrace {
        session_id: [1; 32],
        step_index: 0,
        visual_hash: [0; 32],
        full_prompt: "".into(),
        raw_output: r#"{"name": "browser__navigate", "arguments": {"url": "https://wikipedia.org/wiki/Rust"}}"#.into(),
        success: true,
        error: None,
        timestamp: 0,
    };

    let trace2 = StepTrace {
        session_id: [1; 32],
        step_index: 1,
        visual_hash: [0; 32],
        full_prompt: "".into(),
        raw_output: r#"{"name": "gui__click", "arguments": {"x": 500, "y": 500}}"#.into(),
        success: true,
        error: None,
        timestamp: 1,
    };

    let trace3_failed = StepTrace {
        session_id: [1; 32],
        step_index: 2,
        visual_hash: [0; 32],
        full_prompt: "".into(),
        raw_output: r#"{"name": "net__fetch", "arguments": {"url": "http://evil.com"}}"#.into(),
        success: false, // Failed action should NOT be whitelisted
        error: Some("Blocked".into()),
        timestamp: 2,
    };

    // 2. Synthesize Policy
    let traces = vec![trace1, trace2, trace3_failed];
    let policy = PolicySynthesizer::synthesize("test-session-policy", &traces);

    // 3. Verify
    assert_eq!(policy.policy_id, "test-session-policy");
    assert_eq!(policy.defaults, DefaultPolicy::DenyAll);
    assert_eq!(
        policy.rules.len(),
        2,
        "Only successful actions should produce rules"
    );

    let nav_rule = policy
        .rules
        .iter()
        .find(|r| r.target == "browser__navigate")
        .expect("Navigation rule missing");
    assert!(nav_rule
        .conditions
        .allow_domains
        .as_ref()
        .unwrap()
        .contains(&"wikipedia.org".to_string()));

    let click_rule = policy
        .rules
        .iter()
        .find(|r| r.target == "gui__click")
        .expect("Click rule missing");
    assert!(click_rule.conditions.allow_domains.is_none());

    // Ensure failed action was NOT whitelisted
    assert!(policy
        .rules
        .iter()
        .find(|r| r.target == "net__fetch")
        .is_none());

    println!("✅ Policy Synthesis Logic Test Passed");
}
