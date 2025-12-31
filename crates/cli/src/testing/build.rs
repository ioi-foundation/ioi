// Path: crates/cli/src/testing/build.rs

use std::path::Path;
use std::process::Command;
use std::sync::Once;

// --- One-Time Build ---
static BUILD: Once = Once::new();

/// Builds test artifacts that are NOT configuration-dependent (like contracts).
pub fn build_test_artifacts() {
    BUILD.call_once(|| {
        println!("--- Building Test Artifacts (one-time setup) ---");

        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        // Resolve workspace root relative to crates/cli
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("Failed to resolve workspace root");
        let target_dir = workspace_root.join("target");

        // [NEW] Mock Verifier for Dynamic IBC
        let mock_verifier_dir = manifest_dir.join("tests/contracts/mock-verifier");
        build_contract_component(&mock_verifier_dir, &target_dir, "mock-verifier");

        println!("--- Test Artifacts built successfully ---");
    });
}

/// Helper to build a contract using `cargo component`.
fn build_contract_component(contract_dir: &Path, target_dir: &Path, package_name: &str) {
    println!(
        "Building component for {} in {:?}",
        package_name, contract_dir
    );

    let status = Command::new("cargo")
        .env("CARGO_TARGET_DIR", target_dir)
        .args([
            "component",
            "build",
            "--release",
            "--target",
            "wasm32-wasip1", // [FIX] Reverted to wasm32-wasip1 for compatibility
        ])
        .current_dir(contract_dir)
        .status()
        .expect("Failed to execute `cargo component build`. Ensure cargo-component is installed.");

    if !status.success() {
        panic!("Failed to build component for {}", package_name);
    }
}

#[allow(dead_code)] // [FIX] Suppress unused warning
pub(crate) fn resolve_node_features(user_supplied: &str) -> String {
    fn has_tree_feature(s: &str) -> bool {
        s.split(',')
            .map(|f| f.trim())
            .any(|f| matches!(f, "state-iavl" | "state-verkle"))
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
        panic!("No 'tree-*' feature was provided and none are enabled on ioi-cli. Enable exactly one of: state-iavl, state-sparse-merkle, state-verkle.");
    }
    if tree_count > 1 {
        panic!("Multiple 'tree-*' features are enabled on ioi-cli. Enable exactly one.");
    }

    // --- Commitment primitives ---
    if cfg!(feature = "commitment-hash") {
        feats.push("commitment-hash");
    }
    if cfg!(feature = "commitment-kzg") {
        feats.push("commitment-kzg");
    }

    // --- Consensus engines ---
    if cfg!(feature = "consensus-admft") {
        feats.push("consensus-admft");
    }

    // --- VMs / extras ---
    if cfg!(feature = "vm-wasm") {
        feats.push("vm-wasm");
    }
    if cfg!(feature = "malicious-bin") {
        feats.push("malicious-bin");
    }
    // [FIX] Always include ethereum-zk if ibc-deps is enabled in this context,
    // though usually passed by test runner logic.
    // Ideally we pass what is active.

    feats.join(",")
}
