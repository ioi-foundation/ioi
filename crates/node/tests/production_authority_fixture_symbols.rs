use std::fs;
use std::path::Path;

const SENTINEL: &[u8] = b"IOI_TEST_ONLY_AUTHORITY_MINTER_SENTINEL_v1";

#[test]
fn approval_grant_minters_are_test_scoped_and_absent_from_the_production_daemon() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let routes = manifest.join("src/bin/hypervisor_daemon_routes");
    let files = [
        "room_participation_routes.rs",
        "system_genesis_routes.rs",
        "system_activation_routes.rs",
    ];

    let mut literal_count = 0usize;
    for file in files {
        let source = fs::read_to_string(routes.join(file)).expect("route source is readable");
        for (offset, _) in source.match_indices("ApprovalGrant {") {
            literal_count += 1;
            let test_boundary = source[..offset].rfind("#[cfg(test)]").unwrap_or_else(|| {
                panic!("{file} contains a production-reachable ApprovalGrant minter")
            });
            let module_boundary = source[..offset]
                .rfind("mod ")
                .unwrap_or_else(|| panic!("{file} ApprovalGrant literal has no module boundary"));
            assert!(
                test_boundary < module_boundary,
                "{file} ApprovalGrant literal is not enclosed by a #[cfg(test)] module"
            );
        }
    }
    assert!(
        literal_count > 0,
        "fixture-minter source census unexpectedly empty"
    );

    let daemon = Path::new(env!("CARGO_BIN_EXE_hypervisor-daemon"));
    let binary = fs::read(daemon).expect("production hypervisor-daemon binary is readable");
    assert!(
        !binary
            .windows(SENTINEL.len())
            .any(|window| window == SENTINEL),
        "test-only authority minter sentinel was linked into the production daemon"
    );
}
