// Path: crates/forge/src/testing/build.rs

use std::path::Path;
use std::process::Command;
use std::sync::Once;

// --- One-Time Build ---
static BUILD: Once = Once::new();

/// Builds test artifacts that are NOT configuration-dependent (like contracts).
pub fn build_test_artifacts() {
    BUILD.call_once(|| {
        println!("--- Building Test Artifacts (one-time setup) ---");

        // Construct the path to the contract relative to the forge crate's manifest directory.
        // This is robust and works regardless of where `cargo test` is invoked from.
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let counter_manifest_path = manifest_dir.join("tests/contracts/counter/Cargo.toml");

        let status_contract = Command::new("cargo")
            .args([
                "build",
                "--manifest-path", // Use --manifest-path instead of -p
                counter_manifest_path
                    .to_str()
                    .expect("Path to counter contract manifest is not valid UTF-8"),
                "--release",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .status()
            .expect("Failed to execute cargo build for counter-contract");

        if !status_contract.success() {
            panic!("Counter contract build failed");
        }

        // The build for `test-service-v2` is removed. It was replaced by `fee-calculator-service`,
        // which is now built just-in-time within the `module_upgrade_e2e.rs` test,
        // making this build step obsolete.

        println!("--- Test Artifacts built successfully ---");
    });
}

/// Infer a correct feature string for `ioi-node` if the caller did not
/// supply one with an explicit `tree-*` feature.
#[allow(dead_code)] // This is a library function for test consumers
pub(crate) fn resolve_node_features(user_supplied: &str) -> String {
    fn has_tree_feature(s: &str) -> bool {
        s.split(',')
            .map(|f| f.trim())
            .any(|f| matches!(f, "state-iavl" | "state-sparse-merkle" | "state-verkle"))
    }

    if !user_supplied.trim().is_empty() && has_tree_feature(user_supplied) {
        return user_supplied.to_string();
    }

    let mut feats: Vec<&'static str> = Vec::new();

    // --- State tree (must be exactly one) ---
    let mut tree_count = 0usize;
    if cfg!(feature = "state-iavl") {
        feats.push("state-iavl");
        tree_count += 1;
    }
    if cfg!(feature = "state-sparse-merkle") {
        feats.push("state-sparse-merkle");
        tree_count += 1;
    }
    if cfg!(feature = "state-verkle") {
        feats.push("state-verkle");
        tree_count += 1;
    }
    if tree_count == 0 {
        panic!("No 'tree-*' feature was provided and none are enabled on ioi-forge. Enable exactly one of: state-iavl, state-sparse-merkle, state-verkle.");
    }
    if tree_count > 1 {
        panic!("Multiple 'tree-*' features are enabled on ioi-forge. Enable exactly one.");
    }

    // --- Commitment primitives ---
    if cfg!(feature = "commitment-hash") {
        feats.push("commitment-hash");
    }
    if cfg!(feature = "commitment-kzg") {
        feats.push("commitment-kzg");
    }

    // --- Consensus engines ---
    if cfg!(feature = "consensus-poa") {
        feats.push("consensus-poa");
    }
    if cfg!(feature = "consensus-pos") {
        feats.push("consensus-pos");
    }
    if cfg!(feature = "consensus-round-robin") {
        feats.push("consensus-round-robin");
    }

    // --- VMs / extras ---
    if cfg!(feature = "vm-wasm") {
        feats.push("vm-wasm");
    }
    if cfg!(feature = "malicious-bin") {
        feats.push("malicious-bin");
    }

    feats.join(",")
}