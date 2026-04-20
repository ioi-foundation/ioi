use super::*;

#[test]
fn test_synthesize_network_policy() {
    let trace1 = StepTrace {
        session_id: [0; 32],
        step_index: 0,
        visual_hash: [0; 32],
        full_prompt: "".into(),
        raw_output:
            r#"{"name": "browser__navigate", "arguments": {"url": "https://google.com/search"}}"#
                .into(),
        success: true,
        error: None,
        cost_incurred: 0,
        fitness_score: None,
        skill_hash: None,
        timestamp: 0,
    };
    let trace2 = StepTrace {
        session_id: [0; 32],
        step_index: 1,
        visual_hash: [0; 32],
        full_prompt: "".into(),
        raw_output: r#"{"name": "screen__click_at", "arguments": {"x": 100, "y": 100}}"#.into(),
        success: true,
        error: None,
        cost_incurred: 0,
        fitness_score: None,
        skill_hash: None,
        timestamp: 0,
    };

    let policy = PolicySynthesizer::synthesize("test-policy", &[trace1, trace2]);

    assert_eq!(policy.defaults, DefaultPolicy::DenyAll);
    assert_eq!(policy.rules.len(), 2);

    let nav_rule = policy
        .rules
        .iter()
        .find(|r| r.target == "browser__navigate")
        .unwrap();
    assert_eq!(
        nav_rule.conditions.allow_domains,
        Some(vec!["google.com".to_string()])
    );

    let click_rule = policy
        .rules
        .iter()
        .find(|r| r.target == "screen__click_at")
        .unwrap();
    assert!(click_rule.conditions.allow_domains.is_none());
}
