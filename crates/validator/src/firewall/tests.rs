#[test]
fn review_contract_helper_parity_between_firewall_and_ingestion() {
    let firewall_src = include_str!("mod.rs");
    let ingestion_src = include_str!("../standard/orchestration/ingestion/mod.rs");

    for needle in [
        "resolve_expected_request_hash(",
        "validate_resume_review_contract(",
        "decode_exception_usage_state(",
        "check_exception_usage_increment_ok(",
    ] {
        assert!(
            firewall_src.contains(needle),
            "firewall source missing helper: {needle}"
        );
        assert!(
            ingestion_src.contains(needle),
            "ingestion source missing helper: {needle}"
        );
    }
}

#[test]
fn desktop_resume_binary_payload_bypass_is_kept_in_parity() {
    let firewall_src = include_str!("mod.rs");
    let ingestion_src = include_str!("../standard/orchestration/ingestion/mod.rs");
    let needle = "Err(_) if service_id == \"desktop_agent\" => None";

    assert!(
        firewall_src.contains(needle),
        "firewall missing desktop binary payload bypass"
    );
    assert!(
        ingestion_src.contains(needle),
        "ingestion missing desktop binary payload bypass"
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
