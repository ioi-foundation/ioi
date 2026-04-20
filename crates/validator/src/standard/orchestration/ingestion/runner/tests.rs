#[test]
fn ingestion_is_verify_only_for_scoped_exception_usage() {
    let sources = [
        ("runner.rs", include_str!("../runner.rs")),
        ("runner/collect.rs", include_str!("collect.rs")),
        ("runner/finalize.rs", include_str!("finalize.rs")),
        (
            "runner/semantic/system.rs",
            include_str!("semantic/system.rs"),
        ),
        (
            "runner/semantic/review/context.rs",
            include_str!("semantic/review/context.rs"),
        ),
        (
            "runner/semantic/review/scoped_exception.rs",
            include_str!("semantic/review/scoped_exception.rs"),
        ),
        (
            "runner/semantic/policy/mod.rs",
            include_str!("semantic/policy/mod.rs"),
        ),
        (
            "runner/semantic/policy/verdict.rs",
            include_str!("semantic/policy/verdict.rs"),
        ),
        (
            "runner/semantic/policy/egress.rs",
            include_str!("semantic/policy/egress.rs"),
        ),
    ];

    for (name, src) in sources {
        assert!(
            !src.contains("insert(&usage_key"),
            "{}: {}",
            name,
            "ingestion must not persist scoped exception usage counters"
        );
        assert!(
            !src.contains("insert(&usage_key_local"),
            "{}: {}",
            name,
            "ingestion must not persist scoped exception usage counters"
        );
    }
}
