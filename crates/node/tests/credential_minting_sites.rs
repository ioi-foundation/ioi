//! BUILD-DELTA #36: THE CREDENTIAL-MINTING INVENTORY IS THE COMPILER'S.
//!
//! The syn walker that lived here re-implemented rustc's module, `#[path]`, `include!` and `cfg`
//! resolution in a test, and five review rounds each found another corner it got wrong. It is
//! RETIRED (the Hypervisor Director's ruling "Batch-3 Codex r5 = FAIL, 3 MAJOR + 1 MINOR" (3): no
//! second, weaker gate is kept beside the first). The inventory is crates/node/mint-gate:
//! - LAYER 1, in CI (`cargo run --locked -p ioi-node-mint-gate`): clippy's RESOLVED inventory of
//!   every randomness draw in the production code, for every pinned configuration, compared both
//!   ways with draw-sites.tsv, with the credential mints' regions pinned (mints.tsv) and the canary
//!   counted in every invocation;
//! - LAYER 2, required pre-merge (`crates/node/mint-gate/expanded-scan.sh`): the registered
//!   credential prefixes and the randomness primitives in the EXPANDED production source, compared
//!   both ways with expanded-sites.tsv. Its caller passes EXP_TOOLCHAIN (the pinned 1.93.1
//!   toolchain's directory) and CARGO_HOME, both resolved before HOME is replaced; there is no
//!   fallback to any host's path.
//!
//! This file pins only that the inventory cannot silently stop running: CI runs layer 1, the
//! workspace builds the gate and its canary, the gate's pinned inputs and registries exist, and
//! layer 2 takes its toolchain and cargo home from its caller alone.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo().join(relative))
        .unwrap_or_else(|error| panic!("{relative} does not read: {error}"))
}

/// CI runs layer 1 as its own step, beside the security regression tests.
#[test]
fn ci_runs_the_compiler_resolved_minting_inventory() {
    let ci = read(".github/workflows/ci.yml");
    let runs: Vec<&str> = ci
        .lines()
        .filter_map(|line| line.trim().strip_prefix("run: "))
        .filter(|command| command.contains("ioi-node-mint-gate"))
        .collect();
    assert_eq!(
        runs,
        ["cargo run --locked -p ioi-node-mint-gate"],
        "exactly one CI step runs the minting inventory, plainly"
    );
}

/// The workspace builds the gate and its canary, and the gate's pinned inputs and registries exist.
#[test]
fn the_minting_gate_and_its_registries_are_in_the_tree() {
    let workspace = read("Cargo.toml");
    for member in [
        "\"crates/node/mint-gate\"",
        "\"crates/node/mint-gate/canary\"",
    ] {
        assert!(workspace.contains(member), "the workspace lists {member}");
    }
    for file in [
        "clippy.toml",
        "deps.pin",
        "DEPENDENCY-REVIEW.md",
        "draw-sites.tsv",
        "hand-outs.tsv",
        "mints.tsv",
        "prefixes.tsv",
        "expanded-sites.tsv",
        "expanded-scan.sh",
        "expand-wrapper.sh",
        "src/main.rs",
        "canary/src/lib.rs",
        "canary/src/bin/mint-gate-canary.rs",
    ] {
        let path = repo().join("crates/node/mint-gate").join(file);
        assert!(path.is_file(), "{} exists", path.display());
    }
}

const SCAN: &str = "crates/node/mint-gate/expanded-scan.sh";

/// The pinned toolchain's directory, as the caller resolves it BEFORE it replaces HOME: from this
/// test's own environment, by the toolchain rustup selects for the repo (rust-toolchain.toml).
fn caller_toolchain() -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let out = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .current_dir(repo())
        .output()
        .unwrap_or_else(|error| panic!("{rustc} --print sysroot: {error}"));
    assert!(out.status.success(), "{rustc} --print sysroot failed");
    String::from_utf8(out.stdout)
        .expect("a UTF-8 sysroot")
        .trim()
        .to_string()
}

/// The cargo home, as the caller resolves it BEFORE it replaces HOME: this test's own CARGO_HOME
/// (rustup sets it for cargo and its children), else its own HOME's `.cargo`.
fn caller_cargo_home() -> String {
    std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").expect("the caller has a HOME");
        format!("{home}/.cargo")
    })
}

/// Runs layer 2's `--preflight` (every check before its first build; it builds nothing) under a
/// cleared environment: PATH, the given HOME and exactly `vars`.
fn preflight(home: &Path, vars: &[(&str, &str)]) -> (Option<i32>, String) {
    let Output { status, stdout, .. } = Command::new("bash")
        .arg(repo().join(SCAN))
        .arg("--preflight")
        .arg(repo())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .envs(vars.iter().copied())
        .output()
        .expect("bash runs the scan");
    (status.code(), String::from_utf8_lossy(&stdout).into_owned())
}

/// No host's path is a fallback (the Hypervisor Director's ruling "BATCH 3 SHIPS THIS HOST'S HOME
/// PATH"): the scan names no home directory and never consults rustup's home or a default for its
/// two inputs; each one unset is refused BY NAME, before anything else runs.
#[test]
fn layer_two_refuses_an_unset_toolchain_or_cargo_home_by_name() {
    let text = read(SCAN);
    for (index, line) in text.lines().enumerate() {
        let n = index + 1;
        for home_dir in ["/home/", "/Users/", "/root/"] {
            assert!(
                !line.contains(home_dir),
                "{SCAN}:{n} names a home directory: {line}"
            );
        }
        if line.trim_start().starts_with('#') {
            continue;
        }
        assert!(
            !line.contains("RUSTUP_HOME"),
            "{SCAN}:{n} consults rustup's home instead of EXP_TOOLCHAIN: {line}"
        );
        for input in ["EXP_TOOLCHAIN", "CARGO_HOME"] {
            let defaulted = line
                .match_indices(&format!("${{{input}:-"))
                .any(|(at, _)| !line[at..].starts_with(&format!("${{{input}:-}}")));
            assert!(!defaulted, "{SCAN}:{n} gives {input} a fallback: {line}");
        }
    }
    let home = tempfile::tempdir().expect("a fresh HOME");
    let toolchain = caller_toolchain();
    let cargo_home = caller_cargo_home();
    let cases: [(&str, Vec<(&str, &str)>); 3] = [
        ("EXP_TOOLCHAIN", vec![]),
        ("EXP_TOOLCHAIN", vec![("CARGO_HOME", cargo_home.as_str())]),
        ("CARGO_HOME", vec![("EXP_TOOLCHAIN", toolchain.as_str())]),
    ];
    for (unset, vars) in cases {
        let (code, stdout) = preflight(home.path(), &vars);
        assert_eq!(code, Some(3), "{unset} unset (set: {vars:?}): {stdout}");
        assert!(
            stdout.starts_with(&format!("EXPANDED-SCAN CANNOT RUN: {unset} is not set:")),
            "{unset} unset (set: {vars:?}) is refused by name first: {stdout}"
        );
    }
}

/// With both inputs passed, resolved from this test's own environment before HOME is replaced,
/// the scan's preflight runs under a FRESH, EMPTY HOME and leaves it empty: its toolchain is
/// EXP_TOOLCHAIN's and its registry CARGO_HOME's. Two controls are refused, so the pass is not
/// vacuous: an empty cargo home, and a directory that is no toolchain. The preflight requires the
/// isolated network the scan itself requires (CI runs this target under `unshare -rn`).
#[test]
fn layer_two_runs_with_the_callers_toolchain_and_cargo_home_under_a_fresh_home() {
    let home = tempfile::tempdir().expect("a fresh HOME");
    let empty = tempfile::tempdir().expect("an empty directory");
    let toolchain = caller_toolchain();
    let cargo_home = caller_cargo_home();
    let empty_dir = empty.path().to_str().expect("a UTF-8 temp path");

    let (code, stdout) = preflight(
        home.path(),
        &[
            ("EXP_TOOLCHAIN", toolchain.as_str()),
            ("CARGO_HOME", cargo_home.as_str()),
        ],
    );
    assert_eq!(code, Some(0), "both passed, fresh HOME: {stdout}");
    assert!(
        stdout.starts_with("EXPANDED-SCAN PREFLIGHT OK: rustc 1.93.1 ")
            && stdout.contains(&format!("HOME={}", home.path().display())),
        "the preflight passes under the fresh HOME with the pinned toolchain: {stdout}"
    );
    let left: Vec<_> = std::fs::read_dir(home.path())
        .expect("the fresh HOME reads")
        .collect();
    assert!(
        left.is_empty(),
        "the scan wrote nothing under HOME: {left:?}"
    );

    let (code, stdout) = preflight(
        home.path(),
        &[
            ("EXP_TOOLCHAIN", toolchain.as_str()),
            ("CARGO_HOME", empty_dir),
        ],
    );
    assert_eq!(code, Some(3), "an empty cargo home: {stdout}");
    assert!(
        stdout.contains("holds no offline registry"),
        "an empty cargo home is refused: {stdout}"
    );
    let (code, stdout) = preflight(
        home.path(),
        &[
            ("EXP_TOOLCHAIN", empty_dir),
            ("CARGO_HOME", cargo_home.as_str()),
        ],
    );
    assert_eq!(code, Some(3), "a directory that is no toolchain: {stdout}");
    assert!(
        stdout.contains("/bin/cargo (EXP_TOOLCHAIN must be the pinned 1.93.1"),
        "a directory that is no toolchain is refused: {stdout}"
    );
}
