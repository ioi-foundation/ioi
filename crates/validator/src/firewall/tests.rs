#[test]
fn review_contract_helper_parity_between_firewall_and_ingestion() {
    let firewall_src = include_str!("mod.rs");
    let ingestion_src = ingestion_semantic_sources();

    for (firewall_needle, ingestion_needle) in [
        (
            "resolve_expected_request_hash(",
            "resolve_expected_request_hash(",
        ),
        (
            "validate_resume_review_contract_for_grant_local(",
            "validate_resume_review_contract_for_grant(",
        ),
        (
            "decode_exception_usage_state(",
            "decode_exception_usage_state(",
        ),
        (
            "check_exception_usage_increment_ok(",
            "check_exception_usage_increment_ok(",
        ),
    ] {
        assert!(
            firewall_src.contains(firewall_needle),
            "firewall source missing helper: {firewall_needle}"
        );
        assert!(
            ingestion_src.contains(ingestion_needle),
            "ingestion source missing helper: {ingestion_needle}"
        );
    }
}

#[test]
fn desktop_resume_binary_payload_bypass_is_kept_in_parity() {
    let firewall_src = include_str!("mod.rs");
    let ingestion_src = ingestion_semantic_sources();
    let needle = "Err(_) if service_id == \"desktop_agent\" => None";

    assert!(
        firewall_src.contains(needle),
        "firewall missing desktop binary payload bypass"
    );
    assert!(
        ingestion_src.contains(needle),
        "ingestion missing desktop binary payload bypass"
    );
    assert!(
        firewall_src.contains("allow_approval_bypass_for_message")
            && ingestion_src.contains("allow_approval_bypass_for_message"),
        "desktop_agent post_message approval bypass must remain explicit in both paths"
    );
}

#[test]
fn firewall_is_verify_only_for_scoped_exception_usage() {
    let firewall_src = include_str!("mod.rs");
    let firewall_src = firewall_src
        .split("\n#[cfg(test)]")
        .next()
        .unwrap_or(firewall_src);
    assert!(
        !firewall_src.contains("insert(&usage_key"),
        "firewall must not persist scoped exception usage counters"
    );
    assert!(
        !firewall_src.contains("insert(&usage_key_local"),
        "firewall must not persist scoped exception usage counters"
    );
}

#[test]
fn approval_policy_hash_fallback_uses_runtime_safe_policy_in_both_paths() {
    let firewall_src = include_str!("mod.rs");
    let ingestion_src = ingestion_semantic_sources();

    assert!(
        firewall_src.contains("default_safe_policy()"),
        "firewall approval verification must fallback to the same runtime safe policy as CEC"
    );
    assert!(
        ingestion_src.contains("unwrap_or_else(default_safe_policy)"),
        "ingestion approval verification must fallback to the same runtime safe policy as CEC"
    );
    assert!(
        !firewall_src.contains("ActionRules::default()"),
        "firewall must not bind approval grants to raw ActionRules::default()"
    );
    assert!(
        !ingestion_src.contains("ActionRules::default()"),
        "ingestion must not bind approval grants to raw ActionRules::default()"
    );
}

#[test]
fn approval_policy_hash_uses_effective_workspace_policy_in_both_paths() {
    let firewall_src = include_str!("mod.rs");
    let ingestion_src = ingestion_semantic_sources();

    assert!(
        firewall_src.contains(
            "effective_action_rules_for_session(&stored_rules, agent_state_opt.as_ref())"
        ),
        "firewall approval verification must hash the effective workspace policy"
    );
    assert!(
        ingestion_src.contains("augment_workspace_filesystem_policy("),
        "ingestion approval verification must hash the effective workspace policy"
    );
}

fn ingestion_semantic_sources() -> String {
    [
        include_str!("../standard/orchestration/ingestion/mod.rs"),
        include_str!("../standard/orchestration/ingestion/runner/semantic/system.rs"),
        include_str!("../standard/orchestration/ingestion/runner/semantic/policy/mod.rs"),
        include_str!("../standard/orchestration/ingestion/runner/semantic/policy/verdict.rs"),
        include_str!("../standard/orchestration/ingestion/runner/semantic/review/context.rs"),
        include_str!(
            "../standard/orchestration/ingestion/runner/semantic/review/scoped_exception.rs"
        ),
    ]
    .join("\n")
}
