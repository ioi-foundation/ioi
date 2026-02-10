// Path: crates/cli/src/testing/build.rs

use std::env;
use std::path::{Path, PathBuf};
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
        // [FIX] Correct path is tests/fixtures/mock-verifier
        let mock_verifier_dir = manifest_dir.join("tests/fixtures/mock-verifier");
        build_contract_component(&mock_verifier_dir, &target_dir, "mock-verifier");

        println!("--- Test Artifacts built successfully ---");
    });
}

#[cfg(windows)]
fn exe_name(name: &str) -> String {
    format!("{name}.exe")
}

#[cfg(not(windows))]
fn exe_name(name: &str) -> String {
    name.to_string()
}

fn cargo_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Respect explicit CARGO_HOME when present.
    if let Some(ch) = env::var_os("CARGO_HOME") {
        dirs.push(PathBuf::from(ch).join("bin"));
    }

    // Default rustup install location.
    if let Some(home) = env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".cargo").join("bin"));
    }

    dirs
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let program = exe_name(program);

    // Search our known cargo bin dirs first, then inherited PATH.
    let mut search_dirs = cargo_bin_dirs();
    if let Some(path_os) = env::var_os("PATH") {
        search_dirs.extend(env::split_paths(&path_os));
    }

    for dir in search_dirs {
        let candidate = dir.join(&program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn augment_cmd_path(cmd: &mut Command) {
    // Prepend cargo bin dirs to PATH for the child process.
    let mut paths = cargo_bin_dirs();
    if let Some(path_os) = env::var_os("PATH") {
        paths.extend(env::split_paths(&path_os));
    }

    if let Ok(joined) = env::join_paths(paths) {
        cmd.env("PATH", joined);
    }
}

fn resolve_cargo() -> PathBuf {
    // Only trust CARGO if it points to an actual file.
    if let Ok(cargo_env) = env::var("CARGO") {
        let p = PathBuf::from(&cargo_env);
        if p.is_file() {
            return p;
        }
        // If it's not a real path, ignore it and fall back to PATH search.
    }

    find_on_path("cargo").unwrap_or_else(|| {
        let path = env::var("PATH").unwrap_or_default();
        let cargo_home = env::var("CARGO_HOME").unwrap_or_default();
        let home = env::var("HOME").unwrap_or_default();
        panic!(
            "Unable to locate `cargo` executable.\n\
             PATH={path}\nCARGO_HOME={cargo_home}\nHOME={home}\n\
             Looked in: $CARGO_HOME/bin and $HOME/.cargo/bin and PATH."
        );
    })
}

/// Helper to build a contract using `cargo component`.
fn build_contract_component(contract_dir: &Path, target_dir: &Path, package_name: &str) {
    println!(
        "Building component for {} in {:?}",
        package_name, contract_dir
    );

    // [FIX] Check for cargo-component availability before attempting build
    let cargo_component_path = find_on_path("cargo-component");

    // Check if the subcommand is available either as a binary or via cargo
    let has_component_support = if cargo_component_path.is_some() {
        true
    } else {
        let cargo = resolve_cargo();
        Command::new(cargo)
            .args(["component", "--version"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    if !has_component_support {
        println!("WARN: `cargo-component` not found. Skipping build of '{}'. Tests relying on this artifact may fail.", package_name);
        return;
    }

    let manifest_path = contract_dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        panic!("Contract manifest not found: {}", manifest_path.display());
    }

    let mut cmd = if let Some(cc) = cargo_component_path {
        println!("Using cargo-component at {}", cc.display());
        let mut c = Command::new(cc);
        c.args([
            "build",
            "--manifest-path",
            manifest_path.to_string_lossy().as_ref(),
            "--release",
            "--target",
            "wasm32-wasip1",
        ]);
        c
    } else {
        let cargo = resolve_cargo();
        println!("Using cargo at {}", cargo.display());
        let mut c = Command::new(cargo);
        c.args([
            "component",
            "build",
            "--manifest-path",
            manifest_path.to_string_lossy().as_ref(),
            "--release",
            "--target",
            "wasm32-wasip1",
        ]);
        c
    };

    cmd.env("CARGO_TARGET_DIR", target_dir);

    augment_cmd_path(&mut cmd);

    let status = cmd.status().unwrap_or_else(|e| {
        let path = env::var("PATH").unwrap_or_default();
        let cargo_home = env::var("CARGO_HOME").unwrap_or_default();
        let home = env::var("HOME").unwrap_or_default();
        panic!(
            "Failed to spawn component build command: {e:?}\n\
             PATH={path}\nCARGO_HOME={cargo_home}\nHOME={home}\n\
             Hint: ensure `cargo` and `cargo-component` are installed inside this environment."
        )
    });

    if !status.success() {
        panic!("Failed to build component for {}", package_name);
    }
}

#[allow(dead_code)] // [FIX] Suppress unused warning
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
