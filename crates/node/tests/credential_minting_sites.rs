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
//!   both ways with expanded-sites.tsv.
//!
//! This file pins only that the inventory cannot silently stop running: the workspace builds the
//! gate and its canary, and the gate's pinned inputs and registries exist.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo().join(relative))
        .unwrap_or_else(|error| panic!("{relative} does not read: {error}"))
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
